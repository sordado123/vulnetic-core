package agent

import "testing"

func TestOllamaNeverInheritsCloudKey(t *testing.T) {
	t.Setenv("VULNETIC_LLM_PROVIDER", "ollama")
	t.Setenv("VULNETIC_LLM_BASE_URL", "")
	t.Setenv("OPENAI_API_KEY", "synthetic-cloud-secret")
	t.Setenv("ANTHROPIC_API_KEY", "synthetic-cloud-secret")
	c, ok := FromEnv()
	if !ok || c.Provider() != "ollama" || c.APIKey != "" || c.NeedsAPIKey() || c.BaseURL != DefaultOllamaBaseURL {
		t.Fatalf("invalid keyless remote Ollama config: %s %s", c.Provider(), c.BaseURL)
	}
	if c := ConfigFrom("OLLAMA", "model", "http://192.168.1.10:11434", "", ""); c.BaseURL != "http://192.168.1.10:11434/v1" {
		t.Fatal("LAN endpoint normalization failed")
	}
}
