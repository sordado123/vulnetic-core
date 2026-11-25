package assessment

type Check struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}
type Methodology struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Checks []Check `json:"checks"`
}

// Versioned coverage records are observations, never execution permissions or finding confirmation.
var Methodologies = []Methodology{
	{"web", "Web application", []Check{{"inventory", "Hosts, services and application inventory"}, {"authentication", "Authentication and session lifecycle"}, {"authorization", "Role and object access boundaries"}, {"input", "Input handling and output encoding"}, {"workflow", "Business workflows and state changes"}, {"configuration", "Headers, TLS and exposed configuration"}, {"dependencies", "Component/version applicability"}, {"reproduction", "Candidate reproduction and negative controls"}}},
	{"api", "API", []Check{{"inventory", "Endpoint and method inventory"}, {"authentication", "Authentication and token lifecycle"}, {"authorization", "Object, property and function authorization"}, {"validation", "Schema and input validation"}, {"limits", "Pagination, quotas and bounded resource use"}, {"workflow", "State transitions and duplicate requests"}, {"reproduction", "Candidate reproduction and negative controls"}}},
	{"network", "Network services", []Check{{"inventory", "Approved hosts and explicit ports"}, {"services", "Service and version identification"}, {"transport", "TLS and protocol configuration"}, {"access", "Authentication and exposed interfaces"}, {"dependencies", "Applicable advisories and prerequisites"}, {"reproduction", "Candidate reproduction and negative controls"}}},
	{"ad", "Directory environment", []Check{{"inventory", "Approved domain and service inventory"}, {"accounts", "Test identities and account policy"}, {"permissions", "Delegation and access boundaries"}, {"authentication", "Authentication configuration and expiry"}, {"transport", "Directory transport protections"}, {"logging", "Audit visibility and evidence availability"}, {"reproduction", "Candidate reproduction and negative controls"}}},
}

func ValidCheck(profile, check string) bool {
	for _, m := range Methodologies {
		if m.ID == profile {
			for _, c := range m.Checks {
				if c.ID == check {
					return true
				}
			}
		}
	}
	return false
}
func ValidCheckState(state string) bool {
	return state == "tested" || state == "not_tested" || state == "blocked" || state == "inconclusive" || state == "candidate"
}

type Coverage struct {
	Profile   string  `json:"profile"`
	Check     string  `json:"check"`
	State     string  `json:"state"`
	Note      string  `json:"note"`
	ProofIDs  []int64 `json:"proof_ids"`
	UpdatedAt string  `json:"updated_at"`
}
