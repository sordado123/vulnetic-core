package server

// ModelMetadata contains provider-reported hints, not tested capabilities or execution budgets.
type ModelMetadata struct {
	ID                  string   `json:"id"`
	ContextLength       int      `json:"context_length,omitempty"`
	ContextWindow       int      `json:"context_window,omitempty"`
	MaxModelLen         int      `json:"max_model_len,omitempty"`
	MaxOutputTokens     int      `json:"max_output_tokens,omitempty"`
	SupportedParameters []string `json:"supported_parameters,omitempty"`
	Architecture        struct {
		ContextLength int `json:"context_length"`
	} `json:"architecture,omitempty"`
}

func (m ModelMetadata) contextTokens() int {
	for _, n := range []int{m.ContextLength, m.ContextWindow, m.MaxModelLen, m.Architecture.ContextLength} {
		if n > 0 && n <= 100000000 {
			return n
		}
	}
	return 0
}
func (m ModelMetadata) publicMetadata() map[string]any {
	return map[string]any{"context_tokens": m.contextTokens(), "max_output_tokens": m.MaxOutputTokens, "supported_parameters": m.SupportedParameters, "source": "provider_model_list", "runtime_tested": false}
}
