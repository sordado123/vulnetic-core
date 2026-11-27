package compaction

import "testing"

func TestToolSchemaEstimateDoesNotDoubleCountProviderUsage(t *testing.T) {
	c := New(Config{}, nil)
	c.SetToolSchemaTokens(5000)
	if c.count(nil, 0) != 5000 || c.count(nil, 123) != 123 {
		t.Fatal("schema cost missing or usage double counted")
	}
	c.SetToolSchemaTokens(-1)
	if c.count(nil, 0) != 0 {
		t.Fatal("negative schema budget accepted")
	}
}
