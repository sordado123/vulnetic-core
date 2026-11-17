package reverseagent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const NativePrefix = "vulnetic-exec-v1:"

type NativeCommand struct {
	Kind      string   `json:"kind"`
	Directory string   `json:"directory,omitempty"`
	Env       []string `json:"env,omitempty"`
	Command   string   `json:"command,omitempty"`
	Name      string   `json:"name,omitempty"`
	Expected  string   `json:"expected,omitempty"`
}

func EncodeNative(c NativeCommand) string {
	b, _ := json.Marshal(c)
	return NativePrefix + base64.RawStdEncoding.EncodeToString(b)
}
func DecodeNative(raw string) (NativeCommand, error) {
	var c NativeCommand
	if len(raw) > 1<<20 || !strings.HasPrefix(raw, NativePrefix) {
		return c, errors.New("native executor command required")
	}
	b, e := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(raw, NativePrefix))
	if e != nil || json.Unmarshal(b, &c) != nil || len(c.Env) > 128 {
		return c, errors.New("invalid native command")
	}
	if c.Kind != "exec" && c.Kind != "upload" && c.Kind != "metadata" && c.Kind != "resolve" && c.Kind != "skill" {
		return c, errors.New("unsupported native operation")
	}
	return c, nil
}
