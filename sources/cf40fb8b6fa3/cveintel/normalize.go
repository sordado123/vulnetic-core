package cveintel

import (
	"regexp"
	"strings"
)

// productVersionRE matches the common "<product> <version>" and
// "<product>/<version>" shapes seen in the free-text technologies fingerprint
// field (e.g. "nginx 1.25", "Apache httpd 2.4.54", "OpenSSH/8.9p1"). It is
// deliberately not exhaustive — technologies is unstructured text with no
// fixed convention (agent/tools_insert.go), so this covers the common cases
// and is honest about failing on the rest (see NormalizeProductVersion's ok
// return) instead of guessing.
var productVersionRE = regexp.MustCompile(`(?i)^\s*([A-Za-z][\w.+-]*(?:[ \t]+[A-Za-z][\w.+-]*)?)[ \t/]+v?(\d+(?:\.\d+){0,3}[a-z]?\d*)\s*$`)

// NormalizeProductVersion best-effort parses a raw fingerprint string into a
// (product, version) pair. ok=false means "could not parse this string" —
// callers must not confuse that with "parsed fine, found no CVEs": the two
// are different kinds of "nothing found" and lookup_cve reports them
// differently so the LLM is not misled into treating an unparsed fingerprint
// as a clean bill of health.
func NormalizeProductVersion(raw string) (product, version string, ok bool) {
	raw = strings.TrimSpace(raw)
	m := productVersionRE.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	product = strings.ToLower(strings.TrimSpace(m[1]))
	version = m[2]
	return product, version, true
}

// osvEcosystems maps a lowercased product name to the OSV.dev ecosystem it
// should be queried under. OSV is strong for language-package ecosystems and
// OS package feeds (Debian/Alpine), weak for edge/infra software identified
// only by an HTTP banner — this list only covers the latter, common in
// recon fingerprints; language packages (npm/PyPI/Go/etc.) are expected to
// come from a more specific source already carrying their own ecosystem.
var osvEcosystems = map[string]string{
	"nginx":        "Debian",
	"apache":       "Debian",
	"apache httpd": "Debian",
	"httpd":        "Debian",
	"openssh":      "Debian",
	"openssl":      "Debian",
	"php":          "Debian",
	"mysql":        "Debian",
	"postgresql":   "Debian",
	"redis":        "Debian",
	"docker":       "Debian",
}

// ToOSVEcosystem returns the OSV ecosystem for a normalized product name, or
// ok=false when this package has no mapping for it — the caller then skips
// straight to the NVD fallback instead of sending OSV a query it cannot
// usefully answer.
func ToOSVEcosystem(product string) (ecosystem string, ok bool) {
	eco, ok := osvEcosystems[strings.ToLower(strings.TrimSpace(product))]
	return eco, ok
}
