package assessment

import (
	"strings"
	"testing"
)

func TestScannerFormatsRemainCandidates(t *testing.T) {
	for _, test := range []struct{ format, input, kind string }{
		{"nmap", `<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="192.0.2.1"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="fixture" version="1"/></port></ports></host></nmaprun>`, "service"},
		{"httpx", `{"url":"https://example.test/","status_code":200,"title":"Fixture"}`, "endpoint"},
		{"katana", `{"request":{"endpoint":"https://example.test/login"}}`, "endpoint"},
		{"ffuf", `{"results":[{"url":"https://example.test/api","status":403}]}`, "endpoint"},
		{"nuclei", `{"matched-at":"https://example.test/","template-id":"fixture","info":{"name":"Candidate","severity":"low"}}`, "candidate"},
	} {
		t.Run(test.format, func(t *testing.T) {
			rows, err := Parse(test.format, []byte(test.input))
			if err != nil || len(rows) != 1 || rows[0].Kind != test.kind {
				t.Fatalf("%+v %v", rows, err)
			}
		})
	}
	for _, test := range []struct{ format, input string }{
		{"httpx", `{"url":"file:///etc/passwd"}`}, {"nuclei", `{"matched-at":"https://name:secret@example.test/"}`},
		{"nmap", `<!DOCTYPE nmaprun [<!ENTITY test SYSTEM "file:///etc/passwd">]><nmaprun/>`},
		{"katana", `not JSON`}, {"shell", `echo fixture`}, {"ffuf", `{}`}, {"nmap", `<other/>`},
	} {
		if _, err := Parse(test.format, []byte(test.input)); err == nil {
			t.Fatalf("accepted invalid %s", test.input)
		}
	}
	if _, err := Parse("httpx", []byte(strings.Repeat("x", MaxOutput+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
}
