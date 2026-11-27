package cvecheck

import (
	"strings"
	"testing"
)

func TestCVEIndividualCertificationRequiresPairedControls(t *testing.T) {
	r := laboratoryRecipe(Catalogue()[0])
	good := CertifiedRun{Outcome: "reproduced", Healthy: true, ControlValid: true, BoundaryProtected: true, NegativeClean: true, Reproductions: 2}
	fixed := good
	fixed.Outcome = "not_reproduced"
	fixed.Reproductions = 0
	c := Certificate{RecipeID: r.ID, RecipeDigest: r.Digest(), ReportSHA256: strings.Repeat("a", 64), Cases: []CertifiedCase{{Expected: "vulnerable", Version: "vulnerable", ImageID: "sha256:" + strings.Repeat("a", 64), Isolated: true, CanaryPreserved: true, Runs: []CertifiedRun{good, good, good}}, {Expected: "patched", Version: "fixed", ImageID: "sha256:" + strings.Repeat("b", 64), Isolated: true, CanaryPreserved: true, Runs: []CertifiedRun{fixed, fixed, fixed}}}}
	if !validCertificate(r, c) {
		t.Fatal("valid controlled pair rejected")
	}
	c.Cases[1].Runs[0].Outcome = "inconclusive"
	if validCertificate(r, c) {
		t.Fatal("inconclusive pair promoted")
	}
}
