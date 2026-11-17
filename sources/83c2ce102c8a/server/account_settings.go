package server

import (
	"net/http"
)

var customerSettingKeys = []string{settingLLMPoolOn, settingLLMPoolBindFallback}

func (s *Server) accountSettings(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	if r.Method == http.MethodPut {
		values := map[string]bool{}
		if err := decode(r, &values); err != nil {
			writeErr(w, 400, "invalid settings")
			return
		}
		for key := range values {
			if key != settingLLMPoolOn && key != settingLLMPoolBindFallback {
				writeErr(w, 400, "unsupported account setting")
				return
			}
		}
		for key, value := range values {
			if err := pg.SetBool(key, value); err != nil {
				writeErr(w, 503, "Unable to save settings")
				return
			}
		}
		s.invalidateAccountAgents(mustRequestAccount(r))
	}
	values := map[string]bool{}
	for _, key := range customerSettingKeys {
		values[key] = pg.GetBool(key, false)
	}
	writeJSON(w, 200, values)
}
