// Package platformpolicy enforces operator-owned restrictions outside model prompts.
package platformpolicy

import (
	"errors"
	"golang.org/x/net/idna"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var ErrUnavailable = errors.New("execution_policy_unavailable: invalid operator inventory")
var ErrProtectedTarget = errors.New("protected_platform_target: the Vulnetic infrastructure cannot be used as a test target")

func LocalTool(name string) bool {
	switch name {
	case "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "WebFetch", "WebSearch", "Monitor", "Terminal":
		return true
	}
	return strings.HasPrefix(name, "shell_")
}

// Inventory is operator configuration; tenant prompts and intercept rules cannot override it.
func inventory() []string {
	items := []string{"vulnetic.site", "136.64.138.78", "169.254.169.254", "metadata.google.internal"}
	for _, key := range []string{"VULNETIC_PUBLIC_URL", "VULNETIC_AGENT_PUBLIC_URL", "VULNETIC_PROTECTED_TARGETS"} {
		items = append(items, strings.FieldsFunc(os.Getenv(key), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })...)
	}
	return items
}

func Host(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" {
			return "", errors.New("invalid target address")
		}
		value = u.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(strings.TrimSuffix(strings.ToLower(value), "."), "[]")
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Unmap().String(), nil
	}
	if strings.ContainsAny(value, "%/\\\x00\r\n@: ") {
		return "", errors.New("ambiguous target address")
	}
	host, err := idna.Lookup.ToASCII(value)
	if err != nil || host == "" {
		return "", errors.New("invalid target address")
	}
	return host, nil
}

func CheckHost(value string) error {
	if target, e := netip.ParsePrefix(strings.TrimSpace(value)); e == nil {
		for _, item := range inventory() {
			if p, err := netip.ParsePrefix(item); err == nil {
				if target.Overlaps(p) {
					return ErrProtectedTarget
				}
				continue
			}
			host, err := Host(item)
			if err != nil {
				return ErrUnavailable
			}
			ip, err := netip.ParseAddr(host)
			if err == nil && target.Contains(ip) {
				return ErrProtectedTarget
			}
		}
		return nil
	}

	host, err := Host(value)
	if err != nil {
		return err
	}
	ip, _ := netip.ParseAddr(host)
	for _, item := range inventory() {
		if prefix, e := netip.ParsePrefix(item); e == nil {
			if ip.IsValid() && prefix.Contains(ip) {
				return ErrProtectedTarget
			}
			continue
		}
		protected, e := Host(item)
		if e != nil {
			return ErrUnavailable
		}
		if host == protected || strings.HasSuffix(host, "."+protected) {
			return ErrProtectedTarget
		}
	}
	return nil
}

var addresses = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://[^\s<>"']+|(?:[a-z0-9_-]+\.)+[a-z0-9_-]+\.?(?:/[0-9]{1,3})?|\[[0-9a-f:.]+\])`)

// CheckText covers explicit destinations, not opaque programs. Network enforcement is separate.
func CheckText(text string) error {
	if err := Validate(); err != nil {
		return err
	}
	for _, address := range addresses.FindAllString(text, -1) {
		address = strings.TrimRight(address, ".),;}`")
		if err := CheckHost(address); err != nil {
			if errors.Is(err, ErrProtectedTarget) || errors.Is(err, ErrUnavailable) || strings.Contains(address, "://") {
				return err
			}
		}
	}
	return nil
}

func Validate() error {
	for _, item := range inventory() {
		if _, err := netip.ParsePrefix(item); err == nil {
			continue
		}
		if _, err := Host(item); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// Enrollment must not turn the platform's own dedicated address into an executor.
// Public URL hostnames are checked at execution; source checks use dedicated IP/CIDR inventory.
func CheckExecutorSource(value string) error {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return errors.New("invalid executor source")
	}
	ip = ip.Unmap()
	items := []string{"136.64.138.78", "169.254.169.254"}
	items = append(items, strings.FieldsFunc(os.Getenv("VULNETIC_PROTECTED_TARGETS"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })...)
	for _, item := range items {
		if prefix, e := netip.ParsePrefix(item); e == nil {
			if prefix.Contains(ip) {
				return ErrProtectedTarget
			}
			continue
		}
		if protected, e := netip.ParseAddr(item); e == nil && protected.Unmap() == ip {
			return ErrProtectedTarget
		}
	}
	return nil
}
