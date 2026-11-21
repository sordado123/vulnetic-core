package operatorinput

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"golang.org/x/net/publicsuffix"
)

type Spec struct {
	Type            string `json:"type"`
	TargetURL       string `json:"target_url,omitempty"`
	Delivery        string `json:"delivery,omitempty"`
	DestinationHint string `json:"destination_hint,omitempty"`
}

func (s *Spec) Validate() error {
	if s.Type == "" {
		s.Type = "text"
	}
	switch s.Type {
	case "text", "action", "confirm_send_code", "one_time_code", "session":
	default:
		return errors.New("unsupported input type")
	}
	if len(s.TargetURL) > 2048 || len(s.DestinationHint) > 160 {
		return errors.New("input description too long")
	}
	switch s.Delivery {
	case "", "email", "sms", "totp", "push", "browser", "other":
	default:
		return errors.New("unsupported delivery channel")
	}
	if s.TargetURL == "" {
		if s.Type != "text" && s.Type != "action" {
			return errors.New("authentication requests require the exact target URL")
		}
		return nil
	}
	u, err := url.Parse(s.TargetURL)
	if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("invalid input target")
	}
	u.RawQuery = ""
	u.Fragment = ""
	s.TargetURL = u.String()
	if err = platformpolicy.CheckHost(u.Hostname()); err != nil {
		return err
	}
	return nil
}

func Prepare(spec Spec, answer string) (string, []string, error) {
	if err := spec.Validate(); err != nil {
		return "", nil, err
	}
	if len(answer) > MaxValueBytes || strings.ContainsRune(answer, 0) {
		return "", nil, errors.New("input exceeds size limit")
	}
	answer = strings.TrimSpace(answer)
	if spec.Type == "one_time_code" {
		if len(answer) < 3 || len(answer) > 128 || strings.ContainsAny(answer, "\r\n") {
			return "", nil, errors.New("enter the current code only")
		}
		return answer, nil, nil
	}
	if spec.Type != "session" {
		return "", nil, errors.New("request does not accept sensitive data")
	}
	u, _ := url.Parse(spec.TargetURL)
	host := strings.ToLower(u.Hostname())
	var cookies []http.Cookie
	type cookieJSON struct {
		Name           string  `json:"name"`
		Value          string  `json:"value"`
		Domain         string  `json:"domain"`
		Path           string  `json:"path"`
		Secure         bool    `json:"secure"`
		HTTPOnly       bool    `json:"httpOnly"`
		Expires        float64 `json:"expires,omitempty"`
		ExpirationDate float64 `json:"expirationDate,omitempty"`
		SameSite       string  `json:"sameSite,omitempty"`
	}
	var input []cookieJSON
	if strings.HasPrefix(answer, "[") {
		if json.Unmarshal([]byte(answer), &input) != nil {
			return "", nil, errors.New("invalid cookie JSON")
		}
	} else if strings.HasPrefix(answer, "{") {
		var wrapper struct {
			Cookies []cookieJSON `json:"cookies"`
			Origin  string       `json:"origin"`
		}
		if json.Unmarshal([]byte(answer), &wrapper) != nil {
			return "", nil, errors.New("invalid cookie JSON")
		}
		if wrapper.Origin != "" {
			origin, err := url.Parse(wrapper.Origin)
			if err != nil || origin.User != nil || !strings.EqualFold(origin.Scheme, u.Scheme) || !strings.EqualFold(origin.Host, u.Host) {
				return "", nil, errors.New("session belongs to a different site")
			}
		}
		input = wrapper.Cookies
	} else {
		header := answer
		if len(header) >= 7 && strings.EqualFold(header[:7], "Cookie:") {
			header = header[7:]
		}
		header = strings.TrimSpace(header)
		if strings.ContainsAny(header, "\r\n") {
			return "", nil, errors.New("paste one Cookie header, not an entire HTTP request")
		}
		req := http.Request{Header: http.Header{"Cookie": []string{header}}}
		for _, c := range req.Cookies() {
			input = append(input, cookieJSON{Name: c.Name, Value: c.Value})
		}
	}
	if len(input) == 0 || len(input) > 256 {
		return "", nil, errors.New("provide cookies for this site; the console helper cannot include HttpOnly cookies")
	}
	for i := range input {
		c := &input[i]
		subdomains := strings.HasPrefix(c.Domain, ".")
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == "" {
			domain = host
		}
		suffix, _ := publicsuffix.PublicSuffix(domain)
		if domain != host && (!strings.HasSuffix(host, "."+domain) || suffix == domain) {
			return "", nil, errors.New("cookie domain is outside the requested site")
		}
		if platformpolicy.CheckHost(domain) != nil {
			return "", nil, errors.New("protected cookie domain")
		}
		if c.Path == "" {
			c.Path = "/"
		}
		if !strings.HasPrefix(c.Path, "/") {
			return "", nil, errors.New("invalid cookie path")
		}
		cookie := http.Cookie{Name: c.Name, Value: c.Value, Domain: domain, Path: c.Path, Secure: c.Secure, HttpOnly: c.HTTPOnly}
		if err := cookie.Valid(); err != nil {
			return "", nil, errors.New("invalid cookie name or value")
		}
		cookies = append(cookies, cookie)
		if c.ExpirationDate > 0 && c.Expires == 0 {
			c.Expires = c.ExpirationDate
		}
		if c.Expires > 0 && c.Expires < float64(time.Now().Unix()) {
			return "", nil, errors.New("the supplied session contains an expired cookie; export a current session")
		}
		switch strings.ToLower(c.SameSite) {
		case "", "unspecified":
			c.SameSite = ""
		case "lax":
			c.SameSite = "Lax"
		case "strict":
			c.SameSite = "Strict"
		case "none", "no_restriction":
			c.SameSite = "None"
		default:
			return "", nil, errors.New("invalid SameSite attribute")
		}
		c.Domain = domain
		if subdomains {
			c.Domain = "." + domain
		}
		c.ExpirationDate = 0
	}
	masks := []string{}
	for _, c := range cookies {
		if len(c.Value) >= 4 {
			masks = append(masks, c.Value)
		}
	}
	raw, err := json.Marshal(map[string]any{"origin": u.Scheme + "://" + u.Host, "cookies": input})
	if err != nil || len(raw) > MaxValueBytes {
		return "", nil, errors.New("cookie data exceeds size limit")
	}
	return string(raw), masks, nil
}
