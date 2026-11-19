package platformpolicy

import (
	"encoding/json"
	"testing"
)

func TestCoordinationDoesNotGrantTargetAccess(t *testing.T) {
	if err := CheckTool("steer_work", json.RawMessage(`{"message":"Document the regex wss://[^ ]+ without connecting"}`)); err != nil {
		t.Fatal(err)
	}
	if err := CheckTool("remote_http_request", json.RawMessage(`{"url":"https://agent.vulnetic.site/","method":"GET"}`)); err == nil {
		t.Fatal("protected destination accepted")
	}
}
