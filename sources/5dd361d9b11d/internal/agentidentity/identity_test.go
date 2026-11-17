package agentidentity

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsProductMetadata(t *testing.T) {
	m := Windows()
	if m.ProductName != "Vulnetic Executor" || m.FileName != "VulneticExecutor.exe" || filepath.Base(m.FileName) != m.FileName || !strings.Contains(m.Description, "remote command executor") || m.Brand != "Vulnetic" {
		t.Fatal("product identity is incomplete or misleading")
	}
	if m.Version != "0.2.0-preview" || m.FileVersion != [4]uint16{0, 2, 0, 0} {
		t.Fatal("Windows preview version is inconsistent")
	}
}
