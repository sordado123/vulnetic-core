package server

import (
	"github.com/sordado123/vulnetic/internal/agentassets"
	"net/http"
)

const agentInstallScript = agentassets.InstallScript

func (s *Server) agentInstaller(w http.ResponseWriter, r *http.Request) { agentassets.Installer(w, r) }
func (s *Server) agentBinary(w http.ResponseWriter, r *http.Request)    { agentassets.Binary(w, r) }
func (s *Server) agentChecksum(w http.ResponseWriter, r *http.Request)  { agentassets.Checksum(w, r) }
