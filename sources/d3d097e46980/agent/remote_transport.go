package agent

import (
	"fmt"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"net/http"

	"github.com/sordado123/vulnetic/sshexec"
)

// Every customer-configured endpoint leaves through that run's VPS.
type remoteTransport struct{ template *http.Transport }

func (t remoteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := platformpolicy.CheckHost(request.URL.Hostname()); err != nil {
		return nil, err
	}
	owner := RunInfoFrom(request.Context())
	ex, ok := owner.Executor.(*sshexec.LazyExecutor)
	if !ok || owner.AccountID <= 0 {
		return nil, fmt.Errorf("LLM requests require this account's verified VPS")
	}
	transport := t.template.Clone()
	transport.DialContext = ex.DialContext
	transport.DisableKeepAlives = true
	return transport.RoundTrip(request)
}
