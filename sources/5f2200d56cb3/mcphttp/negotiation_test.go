package mcphttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInitializeNegotiatesBeforeSendingVersionHeader(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q rpcRequest
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		if q.Method == "initialize" {
			attempts++
			if r.Header.Get("MCP-Protocol-Version") != "" {
				t.Error("version sent before negotiation")
			}
			if attempts == 1 {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32602,"message":"Unsupported protocol version"}}`, q.ID)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18"}}`, q.ID)
			return
		}
		if r.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
			t.Error("negotiated version missing")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c, err := New(t.Context(), "fixture", srv.URL, nil, false, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if attempts != 2 {
		t.Fatal("legacy fallback missing")
	}
}
