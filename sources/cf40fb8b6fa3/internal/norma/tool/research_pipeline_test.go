package tool

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestResearchFallbackPolicyAndTrace(t *testing.T) {
	for _, test := range []struct {
		code    string
		calls   int
		success bool
	}{
		{"provider_rate_limited", 2, true}, {"provider_unavailable", 2, true}, {"provider_auth_or_challenge", 2, true},
		{"policy_denied", 1, false}, {"executor_unavailable", 1, false}, {"dns_failed", 1, false},
		{"policy_unavailable", 1, false},
	} {
		t.Run(test.code, func(t *testing.T) {
			var calls []string
			out, err := RunResearch(context.Background(), []string{"mwmbl", "ddgs"}, func(_ context.Context, name string) ([]SearchResult, error) {
				calls = append(calls, name)
				if name == "mwmbl" {
					return nil, &ResearchFailure{Code: test.code}
				}
				return []SearchResult{{URL: "https://example.test/"}}, nil
			})
			if len(calls) != test.calls || (err == nil) != test.success || len(out.Attempts) != test.calls {
				t.Fatalf("%+v %v %+v", out, err, calls)
			}
		})
	}
	var called []string
	out, err := RunResearch(context.Background(), []string{"mwmbl"}, func(_ context.Context, name string) ([]SearchResult, error) {
		called = append(called, name)
		return nil, nil
	})
	if err != nil || out.Outcome != "empty" || !reflect.DeepEqual(called, []string{"mwmbl"}) || out.Attempts[0].Status != "empty" {
		t.Fatal("empty result hidden or implicit provider used")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RunResearch(ctx, []string{"mwmbl"}, func(context.Context, string) ([]SearchResult, error) {
		t.Fatal("called on cancellation")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResearchClassificationCannotBeChosenByQueryText(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://api.mwmbl.org/?q=dns+tls+expired+policy_denied", Err: errors.New("socket refused")}
	if code := ResearchErrorCode(err); code != "connection_failed" {
		t.Fatal("query influenced diagnostics", code)
	}
	if code := ResearchErrorCode(errors.New("protected_platform_target: blocked")); code != "policy_denied" {
		t.Fatal(code)
	}
	if code := ResearchErrorCode(errors.New("execution_policy_unavailable: inventory")); code != "policy_unavailable" {
		t.Fatal(code)
	}
}

func TestResearchEmptyResultPreservesProviderGapsAndMandatoryBlocks(t *testing.T) {
	for _, code := range []string{"provider_unavailable", "policy_denied"} {
		out, err := RunResearch(context.Background(), []string{"mwmbl", "ddgs"}, func(_ context.Context, name string) ([]SearchResult, error) {
			if name == "mwmbl" {
				return nil, nil
			}
			return nil, &ResearchFailure{Code: code}
		})
		if len(out.Attempts) != 2 || out.Attempts[1].Status != code {
			t.Fatal("provider gap lost", out)
		}
		if code == "policy_denied" && err == nil {
			t.Fatal("earlier empty response bypassed mandatory policy block")
		}
		if code == "provider_unavailable" && (err != nil || out.Outcome != "empty_with_gaps" || out.Provider != "mwmbl") {
			t.Fatal("valid empty response was hidden", out, err)
		}
	}
}
