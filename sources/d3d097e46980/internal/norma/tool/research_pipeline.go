package tool

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ResearchFailure never includes response bodies, credentials or raw transport URLs.
type ResearchFailure struct {
	Code       string
	RetryAfter time.Duration
}

func (e *ResearchFailure) Error() string { return e.Code }

func ResearchHTTPError(status int, retryAfter string) error {
	code := "provider_response"
	switch {
	case status == 401 || status == 403:
		code = "provider_auth_or_challenge"
	case status == 202 || status == 429:
		code = "provider_rate_limited"
	case status >= 500:
		code = "provider_unavailable"
	}
	var delay time.Duration
	if n, err := strconv.Atoi(retryAfter); err == nil && n > 0 {
		delay = time.Duration(min(n, 60)) * time.Second
	} else if t, err := http.ParseTime(retryAfter); err == nil {
		delay = min(max(time.Until(t), 0), time.Minute)
	}
	return &ResearchFailure{Code: code, RetryAfter: delay}
}

func ResearchErrorCode(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var typed *ResearchFailure
	if errors.As(err, &typed) {
		return typed.Code
	}
	// Gateway errors already carry bounded diagnostic categories; do not expose their payload.
	classificationError := err
	var transport *url.Error
	if errors.As(err, &transport) {
		classificationError = transport.Err
	}
	message := strings.ToLower(classificationError.Error())
	for _, item := range []struct{ match, code string }{
		{"policy_denied", "policy_denied"}, {"operation_not_permitted", "policy_denied"},
		{"protected_platform_target", "policy_denied"}, {"gateway disconnected", "executor_unavailable"},
		{"revoked", "executor_unavailable"}, {"expired", "executor_unavailable"},
		{"execution_policy_unavailable", "policy_unavailable"},
		{"dns", "dns_failed"}, {"no such host", "dns_failed"}, {"tls", "tls_failed"}, {"certificate", "tls_failed"},
		{"invalid search", "invalid_response"}, {"exceeded size", "response_too_large"},
		{"challenge", "provider_auth_or_challenge"},
	} {
		if strings.Contains(message, item.match) {
			return item.code
		}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failed"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "timeout"
	}
	if errors.As(err, &transport) {
		return "connection_failed"
	}
	return "provider_failed"
}

type ResearchAttempt struct {
	Provider          string `json:"provider"`
	Status            string `json:"status"`
	DurationMS        int64  `json:"duration_ms"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}
type ResearchResponse struct {
	Outcome  string            `json:"outcome"`
	Provider string            `json:"provider,omitempty"`
	Results  []SearchResult    `json:"results"`
	Attempts []ResearchAttempt `json:"attempts"`
}

// RunResearch only uses the supplied, account-authorized order. No implicit paid fallback.
// A provider gets one request: bounded fallbacks cannot multiply adapter retries.
func RunResearch(ctx context.Context, providers []string, search func(context.Context, string) ([]SearchResult, error)) (ResearchResponse, error) {
	out := ResearchResponse{Results: []SearchResult{}, Outcome: "failed"}
	var lastErr error
	emptyProvider := ""
	for _, name := range providers {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		start := time.Now()
		results, err := search(ctx, name)
		code := ResearchErrorCode(err)
		if err == nil && len(results) == 0 {
			code = "empty"
			emptyProvider = name
		}
		attempt := ResearchAttempt{Provider: name, Status: code, DurationMS: time.Since(start).Milliseconds()}
		var failure *ResearchFailure
		if errors.As(err, &failure) {
			attempt.RetryAfterSeconds = int(failure.RetryAfter / time.Second)
		}
		out.Attempts = append(out.Attempts, attempt)
		lastErr = err
		if err == nil && len(results) > 0 {
			out.Provider = name
			out.Results = results
			out.Outcome = "results"
			return out, nil
		}
		switch code {
		case "policy_denied", "policy_unavailable", "executor_unavailable", "cancelled", "dns_failed", "tls_failed", "connection_failed":
			return out, &ResearchFailure{Code: code}
		}
	}
	if emptyProvider != "" {
		out.Provider = emptyProvider
		out.Outcome = "empty"
		for _, attempt := range out.Attempts {
			if attempt.Status != "empty" {
				out.Outcome = "empty_with_gaps"
			}
		}
		return out, nil
	}
	if lastErr != nil {
		return out, lastErr
	}
	if len(out.Attempts) > 0 {
		return out, &ResearchFailure{Code: out.Attempts[len(out.Attempts)-1].Status}
	}
	return out, &ResearchFailure{Code: "not_configured"}
}
