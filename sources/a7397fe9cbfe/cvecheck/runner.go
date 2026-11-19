package cvecheck

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"io"
	"net/http"
	"strings"
	"time"
)

const Version = "http-canary-v1"
const BodyLimit = 64 << 10
const RequestLimit = 20
const RunTimeout = 2 * time.Minute

type Observation struct {
	Role            string      `json:"role"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Status          int         `json:"status"`
	ResponseHeaders http.Header `json:"response_headers,omitempty"`
	Body            string      `json:"body"`
	Digest          string      `json:"sha256"`
	Truncated       bool        `json:"truncated"`
	StartedAt       time.Time   `json:"started_at"`
	FinishedAt      time.Time   `json:"finished_at"`
}
type Result struct {
	Version           string        `json:"version"`
	RecipeID          string        `json:"recipe_id"`
	RecipeDigest      string        `json:"recipe_digest"`
	Target            string        `json:"target"`
	Outcome           string        `json:"outcome"`
	Reason            string        `json:"reason"`
	Healthy           bool          `json:"healthy"`
	ControlValid      bool          `json:"control_valid"`
	BoundaryProtected bool          `json:"boundary_protected"`
	NegativeClean     bool          `json:"negative_clean"`
	Reproductions     int           `json:"reproductions"`
	Observations      []Observation `json:"observations"`
	StartedAt         time.Time     `json:"started_at"`
	FinishedAt        time.Time     `json:"finished_at"`
}

// No default HTTP transport exists here: the host must supply the selected VPS transport.
type Runner struct {
	client   http.Client
	lease    func() error
	interval time.Duration
}

func NewRunner(client *http.Client, lease func() error) (*Runner, error) {
	if client == nil || client.Transport == nil || lease == nil {
		return nil, fmt.Errorf("explicit transport and authorization check are required")
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copy.Timeout = 15 * time.Second
	return &Runner{client: copy, lease: lease, interval: 500 * time.Millisecond}, nil
}
func (r *Runner) Run(ctx context.Context, recipe Recipe, target Target) (out Result) {
	out = Result{Version: Version, RecipeID: recipe.ID, RecipeDigest: recipe.Digest(), Target: target.URL, Outcome: "inconclusive", StartedAt: time.Now().UTC()}
	defer func() { out.FinishedAt = time.Now().UTC() }()
	authoritative, e := Lookup(recipe.ID)
	if e != nil || authoritative.Digest() != recipe.Digest() {
		out.Outcome = "blocked"
		out.Reason = "unreviewed verifier"
		return
	}
	if e = target.Validate(); e != nil {
		out.Outcome = "blocked"
		out.Reason = e.Error()
		return
	}
	if e = platformpolicy.CheckHost(target.URL); e != nil {
		out.Outcome = "blocked"
		out.Reason = e.Error()
		return
	}
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	last := time.Time{}
	request := func(role, path string) (Observation, error) {
		if len(out.Observations) >= RequestLimit {
			return Observation{}, fmt.Errorf("request budget exceeded")
		}
		if e := ctx.Err(); e != nil {
			return Observation{}, e
		}
		if e := r.lease(); e != nil {
			return Observation{}, fmt.Errorf("executor authorization unavailable")
		}
		if wait := r.interval - time.Since(last); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Observation{}, ctx.Err()
			case <-timer.C:
			}
		}
		raw := strings.TrimRight(target.URL, "/") + path
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if e != nil {
			// This exact reviewed URI contains literal percent bytes; never normalize its path.
			req, e = http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(target.URL, "/"), nil)
			if e != nil {
				return Observation{}, fmt.Errorf("invalid verification origin")
			}
			req.URL.Opaque = path
			req.URL.Path = ""
		}
		if e = platformpolicy.CheckHost(req.URL.Hostname()); e != nil {
			return Observation{}, e
		}
		for k, v := range target.Headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "Vulnetic-Verification/1.0")
		req.Header.Set("Cache-Control", "no-cache")
		last = time.Now()
		obs := Observation{Role: role, Method: http.MethodGet, URL: raw, StartedAt: last.UTC()}
		response, e := r.client.Do(req)
		if e != nil {
			return obs, fmt.Errorf("request failed, cancelled or destination denied")
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, BodyLimit+1))
		if e != nil {
			return obs, fmt.Errorf("incomplete response")
		}
		obs.FinishedAt = time.Now().UTC()
		obs.Status = response.StatusCode
		obs.ResponseHeaders = response.Header.Clone()
		obs.Truncated = len(data) > BodyLimit
		obs.Body = string(data[:min(len(data), BodyLimit)])
		digest := sha256.Sum256(data)
		obs.Digest = hex.EncodeToString(digest[:])
		out.Observations = append(out.Observations, obs)
		if obs.Truncated {
			return obs, fmt.Errorf("response exceeds evidence limit")
		}
		if obs.Status >= 300 && obs.Status < 400 {
			return obs, fmt.Errorf("redirects require an independently authorized verifier")
		}
		// ConcatServlet reports a missing negative-control file as 500, including its exact name.
		missingConcat := role == "negative_control" && recipe.ID == "CVE-2021-28169" && obs.Status == 500 && strings.Contains(obs.Body, "java.io.FileNotFoundException") && strings.Contains(obs.Body, path[strings.LastIndex(path, "/")+1:])
		if obs.Status >= 500 && !missingConcat {
			return obs, fmt.Errorf("target returned an operational error")
		}
		return obs, nil
	}
	fail := func(e error) {
		out.Reason = e.Error()
		if ctx.Err() != nil {
			out.Reason = "verification interrupted or timed out"
		}
	}
	healthy, e := request("health", "/")
	if e != nil {
		fail(e)
		return
	}
	if healthy.Status != 200 || strings.Contains(healthy.Body, target.Token) {
		out.Reason = "normal response is unavailable or ambiguous"
		return
	}
	out.Healthy = true
	control, e := request("availability_control", target.ControlPath)
	if e != nil {
		fail(e)
		return
	}
	if control.Status != 200 || !strings.Contains(control.Body, target.Token) {
		out.Reason = "controlled canary availability is not established"
		return
	}
	out.ControlValid = true
	boundary, path := recipe.paths(target.CanaryID)
	protected, e := request("protected_boundary", boundary)
	if e != nil {
		fail(e)
		return
	}
	if strings.Contains(protected.Body, target.Token) {
		out.Outcome = "not_applicable"
		out.Reason = "canary is already reachable without the CVE mechanism"
		return
	}
	out.BoundaryProtected = true
	missing := strings.ReplaceAll(uuid.NewString(), "-", "")
	_, negative := recipe.paths(missing)
	neg, e := request("negative_control", negative)
	if e != nil {
		fail(e)
		return
	}
	if strings.Contains(neg.Body, target.Token) {
		out.Reason = "negative control reproduces the same response"
		return
	}
	out.NegativeClean = true
	matched := 0
	for i := 0; i < 2; i++ {
		obs, e := request(fmt.Sprintf("reproduction_%d", i+1), path)
		if e != nil {
			fail(e)
			return
		}
		if obs.Status == 401 || obs.Status == 403 || obs.Status == 429 {
			out.Reason = "authentication, filtering or rate limit prevents a decisive test"
			return
		}
		present := strings.Contains(obs.Body, target.Token)
		if recipe.Transform == "base64" {
			present = present || strings.Contains(obs.Body, base64.StdEncoding.EncodeToString([]byte(target.Token)))
		}
		if obs.Status == 200 && present {
			matched++
		}
	}
	out.Reproductions = matched
	switch matched {
	case 2:
		out.Outcome = "reproduced"
		out.Reason = "controlled file reached through the documented mechanism in two executions, with valid positive and negative controls"
	case 0:
		out.Outcome = "not_reproduced"
		out.Reason = "mechanism did not reproduce; this alone does not prove remediation"
	default:
		out.Reason = "inconsistent reproduction"
	}
	return
}
func (r Result) DecisiveProof() bool {
	return r.Version == Version && r.Outcome == "reproduced" && r.Healthy && r.ControlValid && r.BoundaryProtected && r.NegativeClean && r.Reproductions == 2 && len(r.Observations) == 6
}
