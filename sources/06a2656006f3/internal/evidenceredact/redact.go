package evidenceredact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const Mask = "[REDACTED]"

var bearer = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]+`)

// Header values can contain spaces and several cookies; redact the whole value.
var quotedHeaders = regexp.MustCompile(`(?i)(["'])(?:proxy-authorization|authorization|set-cookie|cookie)\s*:\s*[^\r\n]*?["']`)
var headerLines = regexp.MustCompile(`(?im)((?:\b|\\(?:[rn]|x0[ad]|u000[ad]))(?:proxy-authorization|authorization|set-cookie|cookie)\s*:\s*)[^\r\n]*`)
var credentials = regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|client[_-]?secret|refresh[_-]?token|password|passwd|senha|authorization|set-cookie|cookie)\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
var portuguesePassword = regexp.MustCompile(`(?i)(senha\s+fornecida\s+pelo\s+operador\s*\()[^)]+\)`)
var privateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
var urls = regexp.MustCompile(`https?://[^\s"'<>]+`)

func sensitive(s string) bool {
	s = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), "_", ""))
	for _, k := range []string{"authorization", "cookie", "setcookie", "password", "passwd", "token", "accesstoken", "refreshtoken", "apikey", "secret", "clientsecret", "privatekey"} {
		if s == k {
			return true
		}
	}
	return false
}
func Text(s string) string {
	s = portuguesePassword.ReplaceAllString(s, "${1}"+Mask+")")
	s = privateKey.ReplaceAllString(s, Mask)
	s = quotedHeaders.ReplaceAllString(s, `${1}`+Mask+`${1}`)
	s = headerLines.ReplaceAllString(s, `${1}`+Mask)
	s = bearer.ReplaceAllString(s, "${1}"+Mask)
	s = credentials.ReplaceAllString(s, "${1}"+Mask)
	return urls.ReplaceAllStringFunc(s, func(raw string) string {
		u, e := url.Parse(raw)
		if e != nil {
			return raw
		}
		if u.User != nil {
			u.User = url.User(Mask)
		}
		q := u.Query()
		for k := range q {
			if sensitive(k) {
				q.Set(k, Mask)
			}
		}
		u.RawQuery = q.Encode()
		return u.String()
	})
}
func JSON(raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return []byte(Text(string(raw)))
	}
	var clean func(any, int) any
	clean = func(v any, depth int) any {
		if depth > 32 {
			return Mask
		}
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if sensitive(k) {
					x[k] = Mask
				} else {
					x[k] = clean(c, depth+1)
				}
			}
		case []any:
			for i, c := range x {
				x[i] = clean(c, depth+1)
			}
		case string:
			var nested any
			if len(x) > 1 && (x[0] == '{' || x[0] == '[') && json.Unmarshal([]byte(x), &nested) == nil {
				b, _ := json.Marshal(clean(nested, depth+1))
				return string(b)
			}
			return Text(x)
		}
		return v
	}
	b, _ := json.Marshal(clean(v, 0))
	return b
}
