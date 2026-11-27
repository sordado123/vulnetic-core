package executor

import _ "embed"

// DocumentToolsScript is shared by the standalone setup and agent installer.
//
//go:embed install-document-tools.sh
var DocumentToolsScript string
