package server

import (
	"net/http"
	"strconv"
)

// assetCVECandidates is GET /api/assets/{id}/cve-candidates (Peça 5 of the
// CVE intelligence plan): the UI's read-only view of what lookup_cve has
// already mirrored for this asset. Never calls OSV/NVD itself — this is a
// display route over the asset_cve_candidates cache, populated only when an
// agent's lookup_cve call passed asset_ids (agent/tools_cve.go).
func (s *Server) assetCVECandidates(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid asset id")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	as := pg.Assets()
	assets, err := as.GetByIDs([]int64{id})
	if err != nil {
		writeErr(w, 503, "Asset unavailable")
		return
	}
	if len(assets) != 1 {
		writeErr(w, 404, "Asset not found")
		return
	}
	rows, err := pg.AssetCVECandidates(id)
	if err != nil {
		writeErr(w, 500, "cve candidates query failed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"asset_id":   id,
		"candidates": rows,
	})
}
