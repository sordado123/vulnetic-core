package agent

import (
	"os"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/agentcore"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestBetaRemoteOutputDoesNotSpillOnPlatform(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	dir := t.TempDir()
	output := actool.Capture(&actool.ToolContext{OutputDir: cmdOutDir(dir)}, strings.Repeat("x", 100000))
	if !strings.Contains(output, "characters truncated]") {
		t.Fatal("missing explicit output truncation")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("remote output created local files", err)
	}
	if env := proxyEnv("http://platform.internal:8080", "platform-ca"); len(env) != 0 {
		t.Fatal("platform proxy environment reached a remote run")
	}
	opts := agentcore.Options{}
	enableNoa(&opts, func() bool { return true }, dir, "fixture", nil)
	if opts.Compactor != nil {
		t.Fatal("unbounded local NOA archive enabled for a customer")
	}
}
