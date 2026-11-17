package platformpolicy

import (
	"errors"
	"testing"
)

func TestProtectedPlatformTargets(t *testing.T) {
	t.Setenv("VULNETIC_PUBLIC_URL", "")
	t.Setenv("VULNETIC_AGENT_PUBLIC_URL", "")
	t.Setenv("VULNETIC_PROTECTED_TARGETS", "2001:db8::19,10.20.30.40/32")
	for _, target := range []string{"https://VULNETIC.SITE./chat/", "agent.vulnetic.site", "a.b.vulnetic.site", "136.64.138.78:443", "[::ffff:136.64.138.78]:80", "[2001:db8::19]:443", "10.20.30.40", "169.254.169.254", "metadata.google.internal", "136.64.0.0/16"} {
		t.Run(target, func(t *testing.T) {
			if !errors.Is(CheckHost(target), ErrProtectedTarget) {
				t.Fatalf("protected target accepted: %q", target)
			}
		})
	}
	for _, target := range []string{"https://example.com", "vulnetic.site.example.org", "notvulnetic.site", "10.20.30.41", "192.168.1.12", "1.1.1.1"} {
		if err := CheckHost(target); err != nil {
			t.Fatalf("legitimate target rejected: %q %v", target, err)
		}
	}
}
func TestImmutableToolPolicy(t *testing.T) {
	for _, input := range []string{`{"command":"curl https://vulnetic.site"}`, `{"target":"136.64.138.78"}`, `{"url":"https:\/\/agent.vulnetic.site"}`} {
		if !errors.Is(CheckTool("Bash", []byte(input)), ErrProtectedTarget) {
			t.Fatalf("protected tool input accepted: %s", input)
		}
	}
	if CheckTool("Write", []byte(`{"path":"/tmp/secret"}`)) == nil {
		t.Fatal("local tool accepted")
	}
	if err := CheckTool("create_tool", []byte(`{"description":"Mention vulnetic.site in documentation"}`)); err != nil {
		t.Fatal("configuration autonomy was removed", err)
	}
	if err := CheckText("curl https://example.com; printf hello"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNETIC_PROTECTED_TARGETS", "https://")
	if CheckHost("example.com") == nil {
		t.Fatal("invalid policy did not fail closed")
	}
}

func TestSourceCodeIsNotATargetAddress(t *testing.T) {
	if err := CheckText(`python3 -c 'import shutil; print(shutil.disk_usage(".")); f.write(b"fixture")'`); err != nil {
		t.Fatal(err)
	}
}

func TestTargetTextSentencePunctuationPreservesProtection(t *testing.T) {
	for _, text := range []string{
		"Review http://fixture:8080. Use synthetic data.",
		"Review (https://example.org:8443).",
	} {
		if err := CheckText(text); err != nil {
			t.Fatalf("sentence punctuation rejected: %q: %v", text, err)
		}
	}
	for _, text := range []string{
		"Review https://vulnetic.site:443.",
		"Review (https://agent.vulnetic.site:443).",
		"Review http://136.64.138.78:80.",
	} {
		if !errors.Is(CheckText(text), ErrProtectedTarget) {
			t.Fatalf("punctuation bypassed protected target: %q", text)
		}
	}
	if err := CheckText("Review http://fixture:badport."); err == nil {
		t.Fatal("malformed port was accepted")
	}
}

func TestPlatformCannotEnrollAsExecutor(t *testing.T) {
	t.Setenv("VULNETIC_PROTECTED_TARGETS", "2001:db8::10,198.51.100.0/28")
	for _, source := range []string{"136.64.138.78", "::ffff:136.64.138.78", "2001:db8::10", "198.51.100.2"} {
		if !errors.Is(CheckExecutorSource(source), ErrProtectedTarget) {
			t.Fatalf("platform executor admitted: %s", source)
		}
	}
	if err := CheckExecutorSource("198.51.100.20"); err != nil {
		t.Fatal(err)
	}
}
