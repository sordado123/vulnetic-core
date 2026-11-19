// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSEFinalLineWithoutNewline(t *testing.T) {
	for _, input := range []string{"data: final", "event: message\ndata: final", "data: first\ndata: final"} {
		scan := newSSEScanner(strings.NewReader(input))
		_, data, err := scan.next()
		if err != nil || !strings.HasSuffix(data, "final") {
			t.Fatalf("%q: %q %v", input, data, err)
		}
		if _, _, err = scan.next(); err != io.EOF {
			t.Fatalf("missing EOF: %v", err)
		}
	}
}

func TestTerminalProviderFrameDoesNotWaitForSocketClose(t *testing.T) {
	for _, tc := range []struct {
		format Format
		body   string
	}{
		{FormatAnthropic, "data: {\"type\":\"message_stop\"}\n\n"},
		{FormatOpenAIResponses, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			p, err := NewProvider(Config{Format: tc.format, BaseURL: srv.URL, APIKey: "fixture", Model: "fixture", MaxRetries: -1})
			if err != nil {
				t.Fatal(err)
			}
			stopped := false
			for ev, err := range p.Stream(ctx, CompletionRequest{Messages: []Message{UserText("fixture")}}) {
				if err != nil {
					t.Fatal(err)
				}
				stopped = stopped || ev.Type == SEMessageStop
			}
			if !stopped || ctx.Err() != nil {
				t.Fatal("waited after the terminal frame")
			}
		})
	}
}

func TestTruncatedProviderStreamIsNotCompleted(t *testing.T) {
	for _, tc := range []struct {
		format Format
		body   string
	}{
		{FormatOpenAI, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"},
		{FormatAnthropic, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"},
		{FormatOpenAIResponses, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) }))
			defer srv.Close()
			p, err := NewProvider(Config{Format: tc.format, BaseURL: srv.URL, APIKey: "fixture", Model: "fixture", MaxRetries: -1})
			if err != nil {
				t.Fatal(err)
			}
			var got error
			for _, err := range p.Stream(context.Background(), CompletionRequest{Messages: []Message{UserText("fixture")}}) {
				if err != nil {
					got = err
				}
			}
			if !errors.Is(got, io.ErrUnexpectedEOF) {
				t.Fatalf("missing truncation error: %v", got)
			}
		})
	}
}
