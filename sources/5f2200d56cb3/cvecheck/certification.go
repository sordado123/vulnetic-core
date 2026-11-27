package cvecheck

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed certifications.json
var certificationData []byte

type Certificate struct {
	RecipeID     string          `json:"recipe_id"`
	RecipeDigest string          `json:"recipe_digest"`
	ReportSHA256 string          `json:"report_sha256"`
	Cases        []CertifiedCase `json:"cases"`
}
type CertifiedCase struct {
	Expected        string         `json:"expected"`
	Version         string         `json:"version"`
	ImageID         string         `json:"image_id"`
	Isolated        bool           `json:"isolated"`
	CanaryPreserved bool           `json:"canary_preserved"`
	Runs            []CertifiedRun `json:"runs"`
}
type CertifiedRun struct {
	Outcome           string `json:"outcome"`
	Healthy           bool   `json:"healthy"`
	ControlValid      bool   `json:"control_valid"`
	BoundaryProtected bool   `json:"boundary_protected"`
	NegativeClean     bool   `json:"negative_clean"`
	Reproductions     int    `json:"reproductions"`
}

func validCertificate(recipe Recipe, c Certificate) bool {
	if c.RecipeID != recipe.ID || c.RecipeDigest != recipe.Digest() || len(c.ReportSHA256) != 64 || len(c.Cases) != 2 {
		return false
	}
	var vulnerable, fixed *CertifiedCase
	for i := range c.Cases {
		entry := &c.Cases[i]
		if !entry.Isolated || !entry.CanaryPreserved || len(entry.Runs) != 3 || !strings.HasPrefix(entry.ImageID, "sha256:") || len(entry.ImageID) != 71 || entry.Version == "" {
			return false
		}
		if entry.Expected == "vulnerable" {
			if vulnerable != nil {
				return false
			}
			vulnerable = entry
		} else if entry.Expected == "patched" {
			if fixed != nil {
				return false
			}
			fixed = entry
		} else {
			return false
		}
		for _, run := range entry.Runs {
			if !run.Healthy || !run.ControlValid || !run.BoundaryProtected || !run.NegativeClean {
				return false
			}
			if entry.Expected == "vulnerable" {
				if run.Outcome != "reproduced" || run.Reproductions != 2 {
					return false
				}
			} else if run.Outcome != "not_reproduced" || run.Reproductions != 0 {
				return false
			}
		}
	}
	return vulnerable != nil && fixed != nil && vulnerable.ImageID != fixed.ImageID && vulnerable.Version != fixed.Version
}
func certified(recipe Recipe) bool {
	var certificates []Certificate
	if json.Unmarshal(certificationData, &certificates) != nil {
		return false
	}
	for _, certificate := range certificates {
		if validCertificate(recipe, certificate) {
			return true
		}
	}
	return false
}

func laboratoryRecipe(recipe Recipe) Recipe { recipe.LaboratoryOnly = true; return recipe }
