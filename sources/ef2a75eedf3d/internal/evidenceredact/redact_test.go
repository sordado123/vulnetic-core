package evidenceredact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceMasksCredentialsWithoutChangingRaw(t *testing.T) {
	raw := []byte(`{"headers":{"Authorization":"Bearer abc.def.ghi","Set-Cookie":["session=secret"]},"body":"password=sensitive api_key=hidden https://u:pass@fixture.invalid/?token=abc","status":200}`)
	before := string(raw)
	got := string(JSON(raw))
	for _, secret := range []string{"abc.def.ghi", "session=secret", "sensitive", "hidden", "u:pass", "token=abc"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret remained: %s", secret)
		}
	}
	if string(raw) != before || !strings.Contains(got, `"status":200`) {
		t.Fatal("raw changed or context lost")
	}
}

func TestEvidenceMasksEscapedTextHeaders(t *testing.T) {
	for _, raw := range []string{
		`printf 'fixture\nAuthorization: Basic fixture-escaped-secret\n'; id -u`,
		`printf 'fixture\r\nCookie: a=fixture-escaped-secret; b=second-secret\r\n'`,
		`printf 'fixture\x0aProxy-Authorization: Basic fixture-escaped-secret\n'`,
		`printf 'fixture\u000aAuthorization: Basic fixture-escaped-secret\n'`,
	} {
		input, err := json.Marshal(map[string]string{"command": raw})
		if err != nil {
			t.Fatal(err)
		}
		for _, preview := range []string{Text(raw), string(JSON(input))} {
			if strings.Contains(preview, "fixture-escaped-secret") || strings.Contains(preview, "second-secret") {
				t.Fatal("escaped header secret remained")
			}
		}
	}
}

func TestEvidenceMasksWholeTextHeaders(t *testing.T) {
	for _, raw := range []string{
		"Authorization: Basic fixture-basic-secret\nAccept: text/plain",
		"Cookie: first=fixture-cookie-one; second=fixture-cookie-two\nContent-Type: text/plain",
		"curl -H 'Authorization: Basic fixture-basic-secret' -H 'Cookie: first=fixture-cookie-one; second=fixture-cookie-two' https://fixture.invalid",
		"Proxy-Authorization: Basic fixture-proxy-secret\n",
	} {
		got := Text(raw)
		for _, secret := range []string{"fixture-basic-secret", "fixture-cookie-one", "fixture-cookie-two", "fixture-proxy-secret"} {
			if strings.Contains(got, secret) {
				t.Fatal("text header secret remained")
			}
		}
	}
}
