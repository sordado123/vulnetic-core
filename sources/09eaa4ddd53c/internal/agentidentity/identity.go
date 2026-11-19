package agentidentity

import (
	_ "embed"
	"encoding/json"
)

type Metadata struct {
	ProductName string    `json:"product_name"`
	FileName    string    `json:"file_name"`
	Description string    `json:"description"`
	Brand       string    `json:"brand"`
	Version     string    `json:"version"`
	FileVersion [4]uint16 `json:"file_version"`
}

//go:embed windows.json
var windowsJSON []byte

func Windows() Metadata {
	var metadata Metadata
	if err := json.Unmarshal(windowsJSON, &metadata); err != nil {
		panic("invalid embedded Windows product metadata")
	}
	return metadata
}
