package reverseagent

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type credentialInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (c credentialInfo) Name() string       { return "vulnetic-state-key" }
func (c credentialInfo) Size() int64        { return 32 }
func (c credentialInfo) Mode() os.FileMode  { return c.mode }
func (c credentialInfo) ModTime() time.Time { return time.Time{} }
func (c credentialInfo) IsDir() bool        { return false }
func (c credentialInfo) Sys() any           { return &c.stat }

func TestPrivateStateCredential(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     os.FileMode
		uid, gid uint32
		want     bool
	}{
		{"private", 0400, 10001, 10001, true},
		{"private writable", 0600, 10001, 10001, true},
		{"systemd root group", 0440, 0, 0, true},
		{"world readable", 0444, 0, 0, false},
		{"group writable", 0460, 0, 0, false},
		{"owner writable group readable", 0640, 0, 0, false},
		{"other owner", 0440, 10001, 0, false},
		{"other group", 0440, 0, 10001, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := credentialInfo{mode: tc.mode, stat: syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}}
			if got := privateStateCredential(info); got != tc.want {
				t.Fatalf("privateStateCredential = %v; want %v", got, tc.want)
			}
		})
	}
}
