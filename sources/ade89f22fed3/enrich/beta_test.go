package enrich

import "testing"

func TestBetaSaaSDisablesPlatformAssetProbes(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	engine := New(nil, nil, 4)
	if engine != nil {
		engine.Close()
		t.Fatal("customer asset enrichment initialized platform network clients")
	}
	// A typed nil is also passed through the existing agent trigger interface.
	engine.ResolveDomain(1, "must-not-resolve.invalid")
	engine.ProbeSite(2, "http://127.0.0.1:1/private-platform-service")
	engine.Close()
}
