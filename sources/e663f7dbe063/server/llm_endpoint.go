package server

import (
	"net/url"
	"strings"

	"github.com/sordado123/vulnetic/agent"
)

func sameLLMEndpoint(providerA, baseA, providerB, baseB string) bool {
	a := agent.ConfigFrom(providerA, "", baseA, "", "")
	b := agent.ConfigFrom(providerB, "", baseB, "", "")
	canonical := func(c agent.Config) string {
		base := c.BaseURL
		if base == "" {
			switch c.Provider() {
			case "openai", "openai-responses":
				base = "https://api.openai.com/v1"
			case "ollama":
				base = "http://127.0.0.1:11434/v1"
			default:
				base = "https://api.anthropic.com"
			}
		}
		u, err := url.Parse(base)
		if err != nil || u.User != nil || u.Host == "" {
			return ""
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimRight(u.Path, "/")
		u.Fragment = ""
		return u.String()
	}
	aa, bb := canonical(a), canonical(b)
	return a.Format == b.Format && aa != "" && aa == bb
}

func sameLLMKeyDestination(provider, base, proxy string, storedProvider, storedBase, storedProxy string) bool {
	return sameLLMEndpoint(provider, base, storedProvider, storedBase) && strings.TrimSpace(proxy) == strings.TrimSpace(storedProxy)
}

// A provider redirect must not forward a saved key to a different origin.
