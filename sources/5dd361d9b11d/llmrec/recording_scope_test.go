package llmrec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/norma/transcript"
	"github.com/sordado123/vulnetic/internal/runstate"
)

func TestTemporaryRecordingIsScopedAndExpires(t *testing.T) {
	dsn := os.Getenv("VULNETIC_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated VULNETIC_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	name := "recording-" + uuid.NewString()
	account, _, err := pg.CreateAccountWithAdmin(name, name+"@fixture.invalid", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		pg.Exec(`DELETE FROM users WHERE account_id=$1`, account.ID)
		pg.Exec(`DELETE FROM accounts WHERE id=$1`, account.ID)
	}()
	recorder := Wrap(completeProvider{}, pg, "model", "profile", "", "", func() bool { return false })
	contextFor := func(owner, conversation int64, session string) context.Context {
		state, err := runstate.New(runstate.Snapshot{ID: uuid.NewString(), ConversationID: conversation}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return transcript.WithSessionID(runstate.Bind(db.WithExecutionOwner(context.Background(), owner, 1), state), session)
	}
	write := func(raw string) {
		if err := pg.ForAccount(account.ID).SetSetting("llm_record_conversation", raw); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(map[string]any{"conversation_id": 7, "expires_at": time.Now().Add(time.Minute)})
	write(string(raw))
	if !recorder.recordingEnabled(contextFor(account.ID, 7, "conv-7")) {
		t.Fatal("authorized conversation not recorded")
	}
	for _, ctx := range []context.Context{context.Background(), contextFor(0, 7, "conv-7"), contextFor(account.ID, 8, "conv-8"), contextFor(account.ID, 7, "exp7-worker"), contextFor(account.ID+1, 7, "conv-7")} {
		if recorder.recordingEnabled(ctx) {
			t.Fatal("recording escaped its account/conversation scope")
		}
	}
	write(fmt.Sprintf(`{"conversation_id":7,"expires_at":%q}`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)))
	if recorder.recordingEnabled(contextFor(account.ID, 7, "conv-7")) {
		t.Fatal("expired scope renewed")
	}
	write("invalid")
	if recorder.recordingEnabled(contextFor(account.ID, 7, "conv-7")) {
		t.Fatal("invalid configuration enabled recording")
	}
}
