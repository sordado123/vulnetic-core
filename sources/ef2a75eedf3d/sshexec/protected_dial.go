package sshexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthorizeTarget is supplied by the application after mandatory platform checks.
var AuthorizeTarget func(context.Context, int64, int64, string, string, []string) error

// Resolve on the customer's VPS, validate every answer, then pin the connection to an IP.
// This never asks the platform resolver to contact a customer-controlled DNS server.
func (l *LazyExecutor) protectedAddress(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("invalid destination port")
	}
	if err = platformpolicy.CheckHost(host); err != nil {
		return "", err
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if AuthorizeTarget != nil {
			if err := AuthorizeTarget(ctx, l.AccountID, l.TargetID, host, port, []string{ip.Unmap().String()}); err != nil {
				return "", err
			}
		}
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	result, err := l.resolveRemoteDNS(ctx, host)
	if err != nil {
		return "", err
	}
	for _, address := range result.Addresses {
		ip, e := netip.ParseAddr(address)
		if e != nil {
			return "", errors.New("invalid resolved address")
		}
		if e = platformpolicy.CheckHost(ip.Unmap().String()); e != nil {
			return "", e
		}
	}
	for _, name := range result.Names {
		if err := platformpolicy.CheckHost(name); err != nil {
			return "", err
		}
	}
	if AuthorizeTarget != nil {
		if err := AuthorizeTarget(ctx, l.AccountID, l.TargetID, host, port, result.Addresses); err != nil {
			return "", err
		}
	}
	sort.SliceStable(result.Addresses, func(i, j int) bool {
		a, _ := netip.ParseAddr(result.Addresses[i])
		b, _ := netip.ParseAddr(result.Addresses[j])
		return a.Is4() && !b.Is4()
	})
	return net.JoinHostPort(result.Addresses[0], port), nil
}

const remoteDNSCommand = `import socket,json,sys
try:
 rows=socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM,flags=socket.AI_CANONNAME)
 print(json.dumps({'addresses':sorted({r[4][0] for r in rows}),'names':sorted({r[3] for r in rows if r[3]})}))
except socket.gaierror as e:
 code='temporary' if e.errno==socket.EAI_AGAIN else 'not_found' if e.errno in (socket.EAI_NONAME,getattr(socket,'EAI_NODATA',socket.EAI_NONAME)) else 'resolver_failed'
 print(json.dumps({'error':code}))
`

type remoteDNSResult struct {
	Addresses []string `json:"addresses"`
	Names     []string `json:"names"`
	Error     string   `json:"error"`
}

func (l *LazyExecutor) resolveRemoteDNS(ctx context.Context, host string) (remoteDNSResult, error) {
	var result remoteDNSResult
	lookupCtx := ctx
	command := "python3 -c " + shellSingleQuote(remoteDNSCommand) + " " + shellSingleQuote(host)
	if l.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "resolve", Name: host})
	}
	for attempt := 0; attempt < 2; attempt++ {
		var out limitedDNS
		handle, err := l.Start(lookupCtx, "", nil, command, &out)
		if err != nil {
			return result, err
		}
		err = handle.Wait()
		if ctx.Err() != nil {
			return result, context.Cause(ctx)
		}
		if err != nil {
			code := handle.ExitCode(err)
			reason := fmt.Sprintf("remote DNS command failed (exit %d); verify the executor resolver and runtime", code)
			category := "command_failed"
			output := out.String()
			if strings.Contains(output, "Permission denied") || strings.Contains(output, "cannot create directory") || strings.Contains(output, "Read-only file system") {
				category = "workspace_unavailable"
				reason = "executor DNS probe could not access its workspace; verify the agent user's directory permissions"
			} else if l.ExecutionOS() != "windows" && code == 127 {
				category = "runtime_missing"
				reason = "executor DNS runtime unavailable: python3 was not found"
			}
			log.Printf("[remote-dns] account=%d target=%d category=%s exit=%d", l.AccountID, l.TargetID, category, code)
			return result, fmt.Errorf("%s: %w", reason, err)
		}
		result = remoteDNSResult{}
		if out.overflow || json.Unmarshal(out.Bytes(), &result) != nil {
			return result, errors.New("invalid remote DNS response")
		}
		if result.Error != "" {
			if result.Error == "temporary" && attempt == 0 {
				timer := time.NewTimer(200 * time.Millisecond)
				select {
				case <-lookupCtx.Done():
					timer.Stop()
					return result, context.Cause(ctx)
				case <-timer.C:
				}
				continue
			}
			message := "executor DNS resolver failed; verify DNS on the executor"
			switch result.Error {
			case "temporary":
				message = "executor DNS temporarily unavailable; verify DNS or VPN on the executor"
			case "not_found":
				message = "executor DNS could not resolve this hostname; verify DNS on the executor"
			case "resolver_failed":
			default:
				return result, errors.New("invalid remote DNS response")
			}
			log.Printf("[remote-dns] account=%d target=%d category=%s", l.AccountID, l.TargetID, result.Error)
			return result, &net.DNSError{Name: host, Err: message, IsTemporary: result.Error == "temporary", IsNotFound: result.Error == "not_found"}
		}
		if len(result.Addresses) == 0 || len(result.Addresses) > 64 || len(result.Names) > 64 {
			return result, errors.New("invalid remote DNS response")
		}
		return result, nil
	}
	return result, errors.New("remote DNS resolution failed")
}

type limitedDNS struct {
	bytes.Buffer
	overflow bool
}

func (w *limitedDNS) Write(p []byte) (int, error) {
	n := len(p)
	if w.Len()+n > 8192 {
		w.overflow = true
		return n, nil
	}
	_, err := w.Buffer.Write(p)
	return n, err
}
