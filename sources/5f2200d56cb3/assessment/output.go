// Package assessment normalizes scanner observations; it never confirms findings.
package assessment

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const MaxOutput = 2 << 20
const MaxObservations = 1000

type Observation struct {
	Kind     string `json:"kind"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	URL      string `json:"url,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Template string `json:"template,omitempty"`
	Severity string `json:"severity,omitempty"`
}

func Parse(format string, raw []byte) ([]Observation, error) {
	if len(raw) == 0 || len(raw) > MaxOutput {
		return nil, errors.New("scanner output must be nonempty and at most 2 MiB")
	}
	if format == "nmap" {
		return parseNmap(raw)
	}
	if format != "httpx" && format != "katana" && format != "ffuf" && format != "nuclei" {
		return nil, errors.New("unsupported scanner format")
	}
	var out []Observation
	appendRow := func(row map[string]any) error {
		var o Observation
		switch format {
		case "httpx":
			o = Observation{Kind: "endpoint", URL: str(row, "url"), Title: str(row, "title"), Status: number(row, "status_code"), Service: str(row, "webserver")}
		case "katana":
			request, _ := row["request"].(map[string]any)
			o = Observation{Kind: "endpoint", URL: str(request, "endpoint")}
		case "ffuf":
			o = Observation{Kind: "endpoint", URL: str(row, "url"), Status: number(row, "status")}
		case "nuclei":
			info, _ := row["info"].(map[string]any)
			o = Observation{Kind: "candidate", URL: str(row, "matched-at"), Template: str(row, "template-id"), Title: str(info, "name"), Severity: str(info, "severity")}
		}
		if o.URL != "" {
			u, err := url.Parse(o.URL)
			if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
				return errors.New("invalid observation URL")
			}
			o.Host = u.Hostname()
		}
		if o.URL == "" {
			return errors.New("scanner row lacks a supported URL")
		}
		if len(out) >= MaxObservations {
			return errors.New("scanner observation limit exceeded; split the source")
		}
		out = append(out, o)
		return nil
	}
	if format == "ffuf" {
		var doc struct {
			Results []map[string]any `json:"results"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Results == nil {
			return nil, errors.New("expected ffuf JSON results")
		}
		for _, row := range doc.Results {
			if err := appendRow(row); err != nil {
				return nil, err
			}
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 4096), MaxOutput)
		for scanner.Scan() {
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				return nil, errors.New("expected scanner JSONL without banners")
			}
			if err := appendRow(row); err != nil {
				return nil, err
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseNmap(raw []byte) ([]Observation, error) {
	var doc struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Addresses []struct {
				Value string `xml:"addr,attr"`
			} `xml:"address"`
			Ports []struct {
				Port     int    `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					Value string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	// encoding/xml does not resolve external entities. Reject directives to keep imports data-only.
	if bytes.Contains(bytes.ToUpper(raw), []byte("<!ENTITY")) || bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) && !bytes.Contains(raw, []byte("<!DOCTYPE nmaprun>")) {
		return nil, errors.New("XML entity declarations are not allowed")
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid nmap XML: %w", err)
	}
	var out []Observation
	for _, host := range doc.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		for _, p := range host.Ports {
			if p.State.Value != "open" {
				continue
			}
			if p.Port < 1 || p.Port > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") {
				return nil, errors.New("invalid nmap port")
			}
			if len(out) >= MaxObservations {
				return nil, errors.New("scanner observation limit exceeded")
			}
			out = append(out, Observation{Kind: "service", Host: host.Addresses[0].Value, Port: p.Port, Protocol: p.Protocol, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version})
		}
	}
	return out, nil
}
func str(row map[string]any, key string) string {
	v, _ := row[key].(string)
	return strings.TrimSpace(v)
}
func number(row map[string]any, key string) int { v, _ := row[key].(float64); return int(v) }
