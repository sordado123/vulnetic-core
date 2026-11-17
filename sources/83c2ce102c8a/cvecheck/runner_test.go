package cvecheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCVEVerifierRequiresControlsAndRealMechanism(t *testing.T) {
	recipe, _ := Lookup("CVE-2021-28164")
	target := Target{URL: "http://fixture.invalid", CanaryID: strings.Repeat("a", 32), Token: "vulnetic-proof:" + strings.Repeat("b", 32), ControlPath: "/vulnetic-control/" + strings.Repeat("a", 32) + ".txt"}
	for _, mode := range []string{"vulnerable", "patched", "blanket_marker", "missing_canary", "waf", "redirect", "truncated", "network_error", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: fakeTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				code := 200
				body := "healthy fixture"
				h := make(http.Header)
				if mode == "network_error" {
					return nil, errors.New("fixture offline")
				}
				if mode == "blanket_marker" {
					body = target.Token
				} else if req.URL.Path == target.ControlPath {
					if mode == "missing_canary" {
						code = 404
					} else {
						body = target.Token
					}
				} else if strings.Contains(req.URL.RawPath, "%2e") && strings.Contains(req.URL.Path, "vulnetic-"+target.CanaryID) {
					if mode == "vulnerable" {
						body = target.Token
					} else if mode == "truncated" {
						body = strings.Repeat("x", BodyLimit+1) + target.Token
					} else if mode == "waf" {
						code = 403
					} else if mode == "redirect" {
						code = 302
						h.Set("Location", "https://vulnetic.site")
					} else {
						code = 404
					}
				} else if req.URL.Path != "/" {
					code = 404
				}
				return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			runner, e := NewRunner(client, func() error {
				if mode == "revoked" {
					return errors.New("revoked")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			runner.interval = 0
			got := runner.Run(t.Context(), recipe, target)
			if mode == "vulnerable" {
				if !got.DecisiveProof() {
					t.Fatalf("not reproduced: %+v", got)
				}
			} else if got.Outcome == "reproduced" || got.DecisiveProof() {
				t.Fatalf("false confirmation: %s %+v", mode, got)
			}
			if mode == "patched" && got.Outcome != "not_reproduced" {
				t.Fatal(got)
			}
			if calls > 6 {
				t.Fatal("request budget expanded")
			}
		})
	}
}
func TestCVEVerifierRejectsProtectedTargetAndChangedRecipe(t *testing.T) {
	calls := 0
	runner, _ := NewRunner(&http.Client{Transport: fakeTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not connect") })}, func() error { return nil })
	runner.interval = 0
	recipe, _ := Lookup("CVE-2025-30208")
	target := Target{URL: "https://vulnetic.site", CanaryID: strings.Repeat("a", 32), Token: "vulnetic-proof:" + strings.Repeat("b", 32), ControlPath: "/vulnetic-control/" + strings.Repeat("a", 32) + ".txt"}
	got := runner.Run(t.Context(), recipe, target)
	if got.Outcome != "blocked" || calls != 0 {
		t.Fatal(got, calls)
	}
	target.URL = "http://fixture.invalid"
	recipe.Probe = "/unreviewed"
	got = runner.Run(t.Context(), recipe, target)
	if got.Outcome != "blocked" || calls != 0 {
		t.Fatal(got, calls)
	}
	if _, e := NewRunner(&http.Client{}, func() error { return nil }); e == nil {
		t.Fatal("default transport allowed")
	}
}
func TestCVEVerifierCancellationAndCatalogue(t *testing.T) {
	if len(Catalogue()) != 10 {
		t.Fatal("expected ten reviewed recipes")
	}
	seen := map[string]bool{}
	for _, r := range Catalogue() {
		if seen[r.ID] || len(r.Digest()) != 64 || !r.LaboratoryOnly {
			t.Fatal(r)
		}
		seen[r.ID] = true
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	recipe, _ := Lookup("CVE-2021-28164")
	target := Target{URL: "http://fixture.invalid", CanaryID: strings.Repeat("a", 32), Token: "vulnetic-proof:" + strings.Repeat("b", 32), ControlPath: "/vulnetic-control/" + strings.Repeat("a", 32) + ".txt"}
	runner, _ := NewRunner(&http.Client{Transport: fakeTransport(func(*http.Request) (*http.Response, error) { t.Fatal("cancelled call executed"); return nil, nil })}, func() error { return nil })
	if got := runner.Run(ctx, recipe, target); got.Outcome != "inconclusive" {
		t.Fatal(got)
	}
}
