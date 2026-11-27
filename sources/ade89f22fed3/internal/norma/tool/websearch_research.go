package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type researchSearchProvider struct {
	backend string
	apiKey  string
	client  *http.Client
}

func (p *researchSearchProvider) Name() string { return p.backend }

func (p *researchSearchProvider) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	method, endpoint := http.MethodPost, ""
	var payload map[string]any
	switch p.backend {
	case "mwmbl":
		method, endpoint = http.MethodGet, "https://api.mwmbl.org/api/v2/search/?"+url.Values{"q": {query}}.Encode()
	case "exa":
		endpoint = "https://api.exa.ai/search"
		payload = map[string]any{"query": query, "numResults": limit, "type": "auto", "contents": map[string]any{"highlights": true}}
	case "linkup":
		endpoint = "https://api.linkup.so/v1/search"
		payload = map[string]any{"q": query, "depth": "standard", "outputType": "searchResults", "maxResults": limit, "includeImages": false}
	default:
		return nil, fmt.Errorf("unsupported research provider")
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.backend == "exa" {
		req.Header.Set("x-api-key", p.apiKey)
	}
	if p.backend == "linkup" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ResearchHTTPError(resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFetchBytes {
		return nil, fmt.Errorf("search response exceeded size limit")
	}
	return parseResearchResults(raw, limit)
}

func parseResearchResults(raw []byte, limit int) ([]SearchResult, error) {
	raw = bytes.TrimSpace(raw)
	var rows []struct {
		Title       json.RawMessage `json:"title"`
		Name        string          `json:"name"`
		URL         string          `json:"url"`
		Extract     json.RawMessage `json:"extract"`
		Content     string          `json:"content"`
		Description string          `json:"description"`
		Highlights  []string        `json:"highlights"`
	}
	if len(raw) > 0 && raw[0] == '[' {
		if json.Unmarshal(raw, &rows) != nil {
			return nil, fmt.Errorf("invalid search results")
		}
	} else {
		var wrapper struct {
			Results json.RawMessage `json:"results"`
		}
		if json.Unmarshal(raw, &wrapper) != nil || len(wrapper.Results) == 0 || json.Unmarshal(wrapper.Results, &rows) != nil {
			return nil, fmt.Errorf("invalid search results")
		}
	}
	out := make([]SearchResult, 0, min(limit, len(rows)))
	for _, row := range rows {
		if len(out) >= limit {
			break
		}
		u, err := url.Parse(row.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			continue
		}
		title := researchText(row.Title)
		if title == "" {
			title = row.Name
		}
		description := researchText(row.Extract)
		if description == "" {
			description = row.Content
		}
		if description == "" {
			description = strings.Join(row.Highlights, "\n")
		}
		if description == "" {
			description = row.Description
		}
		out = append(out, SearchResult{Title: truncate(title, 500), URL: row.URL, Description: truncate(description, 3000), Position: len(out) + 1})
	}
	return out, nil
}

func researchText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var parts []struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(part.Value)
	}
	return b.String()
}
