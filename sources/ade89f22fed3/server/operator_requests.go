package server

import "net/http"

func (s *Server) operatorRequests(w http.ResponseWriter, r *http.Request) {
	if mustRequestAccount(r) <= 0 {
		writeErr(w, 401, "Authenticated account required")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	items, err := pg.OperatorRequests()
	if err != nil {
		writeErr(w, 503, "Operator notifications unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
