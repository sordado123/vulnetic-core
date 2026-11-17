package sshexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"net"
	"net/netip"
	"sort"
	"strconv"
)

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
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	var out limitedDNS
	command := "python3 -c " + shellSingleQuote("import socket,json,sys; rows=socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM,flags=socket.AI_CANONNAME); print(json.dumps({'addresses':sorted({r[4][0] for r in rows}),'names':sorted({r[3] for r in rows if r[3]})}))") + " " + shellSingleQuote(host)
	if l.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "resolve", Name: host})
	}
	handle, err := l.Start(ctx, "", nil, command, &out)
	if err != nil {
		return "", err
	}
	if err = handle.Wait(); err != nil {
		return "", errors.New("remote DNS resolution failed")
	}
	var result struct {
		Addresses []string `json:"addresses"`
		Names     []string `json:"names"`
	}
	if out.overflow || json.Unmarshal(out.Bytes(), &result) != nil || len(result.Addresses) == 0 || len(result.Addresses) > 64 {
		return "", errors.New("invalid remote DNS response")
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
	sort.SliceStable(result.Addresses, func(i, j int) bool {
		a, _ := netip.ParseAddr(result.Addresses[i])
		b, _ := netip.ParseAddr(result.Addresses[j])
		return a.Is4() && !b.Is4()
	})
	return net.JoinHostPort(result.Addresses[0], port), nil
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
