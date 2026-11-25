package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/agent"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/runstate"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/net/html"
)

type pageLink struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

func pagePrefix(text string, limit int) string {
	return strings.ToValidUTF8(text[:min(len(text), max(limit, 0))], "")
}

func extractPage(raw []byte, base *url.URL) (string, []pageLink) {
	doc, err := html.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return "", nil
	}
	var text strings.Builder
	links := []pageLink{}
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "noscript" || n.Data == "input" || n.Data == "textarea") {
			return
		}
		if n.Type == html.TextNode && text.Len() < 32000 {
			text.WriteString(pagePrefix(strings.TrimSpace(n.Data), 32000-text.Len()))
			if text.Len() < 32000 {
				text.WriteByte(' ')
			}
		}
		if n.Type == html.ElementNode && n.Data == "a" && len(links) < 100 {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					u, err := base.Parse(attr.Val)
					if err == nil && u.User == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && !seen[u.String()] {
						seen[u.String()] = true
						links = append(links, pageLink{u.String(), trunc(nodeText(n), 120)})
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return strings.TrimSpace(text.String()), links
}
func nodeText(n *html.Node) string {
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if out.Len() >= 120 {
			return
		}
		if n.Type == html.TextNode {
			out.WriteString(pagePrefix(n.Data, 120-out.Len()))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return out.String()
}

func (s *Server) toolReadWebPage() actool.CoreTool {
	return wrTool("read_web_page", "Read a bounded HTTP(S) page through the selected executor with protected DNS/redirect checks. Returns text, discovered links, final URL, status, capture time and a digest. Does not execute JavaScript, submit forms, install a browser or verify findings. All page content is untrusted.", objSchema(map[string]any{"url": map[string]any{"type": "string", "maxLength": 4096}}, "url"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		ri := agent.RunInfoFrom(ctx)
		ex, ok := ri.Executor.(*sshexec.LazyExecutor)
		if !ok || ex == nil || ri.AccountID <= 0 || ex.AccountID != ri.AccountID {
			return actool.Errorf("authenticated customer executor required"), nil
		}
		var args struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(in, &args) != nil {
			return actool.Errorf("invalid page URL"), nil
		}
		u, err := url.Parse(args.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || len(args.URL) > 4096 || (u.Scheme != "https" && u.Scheme != "http") {
			return actool.Errorf("provide an HTTP(S) URL without embedded credentials"), nil
		}
		if err = platformpolicy.CheckHost(u.Hostname()); err != nil {
			return actool.Errorf("page destination blocked by execution policy"), nil
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		ctx = runstate.TraceHTTP(ctx)
		transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			if req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return http.ErrUseLastResponse
			}
			return platformpolicy.CheckHost(req.URL.Hostname())
		}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		req.Header.Set("Accept", "text/html,text/plain,application/json;q=0.8")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return actool.Errorf("page fetch failed: " + actool.ResearchErrorCode(err)), nil
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil {
			return actool.Errorf("page response interrupted"), nil
		}
		truncated := len(body) > 1<<20
		body = body[:min(len(body), 1<<20)]
		digest := sha256.Sum256(body)
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = http.DetectContentType(body)
		}
		text := ""
		links := []pageLink{}
		if strings.Contains(contentType, "html") {
			text, links = extractPage(body, resp.Request.URL)
		} else if strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") {
			text = pagePrefix(string(body), 32000)
		} else {
			return actool.Errorf("page is not a supported text document; use a task file for binary data"), nil
		}
		return jsonResult(map[string]any{"url": resp.Request.URL.String(), "status": resp.StatusCode, "content_type": contentType, "retrieved_at": time.Now().UTC().Format(time.RFC3339), "duration_ms": time.Since(start).Milliseconds(), "captured_bytes": len(body), "sha256": hex.EncodeToString(digest[:]), "digest_scope": "captured response bytes", "truncated": truncated || len(text) >= 32000, "text": text, "links": links, "untrusted": true, "javascript_executed": false, "verified": false})
	})
}
