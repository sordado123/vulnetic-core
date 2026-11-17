package db

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/notify"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBetaVaultMigrationAndMaskedUpdates(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skip("PostgreSQL unavailable")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path += "_vault"
	d, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	name := fmt.Sprintf("vault-%d", time.Now().UnixNano())
	a, _, err := d.CreateAccountWithAdmin(name, name+"@example.test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	profileID, err := d.SaveProfile(&LLMProfile{AccountID: a.ID, Name: name, Format: "openai", Model: "test", APIKey: "clear-test-secret", BaseURL: "https://provider.example/v1"})
	if err != nil {
		t.Fatal(err)
	}
	mcpID, err := d.SaveMCP(&MCPServer{AccountID: a.ID, Name: name, Transport: "stdio", Command: "test-mcp", Args: json.RawMessage(`["--token","clear-test-secret"]`), Env: json.RawMessage(`{"TOKEN":"clear-test-secret"}`)})
	if err != nil {
		t.Fatal(err)
	}
	channelID, err := d.SaveNotificationChannel(context.Background(), &NotificationChannel{AccountID: a.ID, Name: name, Kind: notify.KindWebhook, Mode: NotifyModeRealtime, Config: json.RawMessage(`{"url":"https://hook.example","token":"clear-test-secret"}`)})
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("vault test", "proof", TaskCreateOptions{AccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := d.UpsertTaskCredential(task.ID, TaskCredentialInput{Domain: "example.test", Username: "test", Password: "clear-test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	d.ConfigureVault(key, true)
	if err := d.MigrateSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := d.MigrateSecrets(); err != nil {
		t.Fatalf("migration not idempotent: %v", err)
	}
	for _, query := range []struct {
		sql string
		id  int64
	}{
		{`SELECT api_key FROM llm_profiles WHERE id=$1`, profileID}, {`SELECT env::text FROM mcp_servers WHERE id=$1`, mcpID},
		{`SELECT config::text FROM notification_channels WHERE id=$1`, channelID}, {`SELECT password FROM task_credentials WHERE id=$1`, credential.ID},
	} {
		var stored string
		if err := d.QueryRow(query.sql, query.id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stored, "clear-test-secret") || !strings.Contains(stored, "vault:v1:") {
			t.Fatal("plaintext remained at rest")
		}
	}
	profile, err := d.ProfileByID(profileID)
	if err != nil || profile.APIKey != "clear-test-secret" {
		t.Fatalf("profile read: %v", err)
	}
	servers, err := d.ListMCPForAccount(a.ID)
	if err != nil || len(servers) != 1 || !strings.Contains(string(servers[0].Env), "clear-test-secret") {
		t.Fatalf("MCP read: %v", err)
	}
	if _, err := d.SaveMCP(servers[0].Masked()); err != nil {
		t.Fatalf("masked update: %v", err)
	}
	servers, err = d.ListMCPForAccount(a.ID)
	if err != nil || !strings.Contains(string(servers[0].Args), "clear-test-secret") {
		t.Fatalf("masked update lost secret: %v", err)
	}
	channel, err := d.NotificationChannelByID(context.Background(), channelID)
	if err != nil || !strings.Contains(string(channel.Config), "clear-test-secret") {
		t.Fatalf("channel read: %v", err)
	}
	credentials, err := d.TaskCredentials(task.ID)
	if err != nil || len(credentials) != 1 || credentials[0].Password != "clear-test-secret" {
		t.Fatalf("credential read: %v", err)
	}
	d.ConfigureVault([]byte("abcdef0123456789abcdef0123456789"), true)
	if _, err := d.ProfileByID(profileID); err == nil {
		t.Fatal("wrong master key accepted")
	}
	d.ConfigureVault(key, true)
	if _, err := d.ProfileByID(profileID); err != nil {
		t.Fatalf("key restoration failed: %v", err)
	}
}
