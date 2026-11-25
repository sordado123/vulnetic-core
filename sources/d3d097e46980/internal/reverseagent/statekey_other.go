//go:build !windows

package reverseagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sordado123/vulnetic/vault"
)

func clientPlatform() string                           { return runtime.GOOS }
func privateStateFile(_ string, info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }

// systemd delivers the machine-encrypted key in a private read-only credential mount.
func cryptClientState(ctx context.Context, encrypt bool, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directory) {
		return nil, errors.New("private systemd state credential is required")
	}
	info, err := os.Lstat(filepath.Join(directory, "vulnetic-state-key"))
	if err != nil || !info.Mode().IsRegular() || !privateStateCredential(info) || info.Size() != 32 {
		return nil, errors.New("invalid private state credential")
	}
	key, err := os.ReadFile(filepath.Join(directory, "vulnetic-state-key"))
	if err != nil {
		return nil, errors.New("private state credential unavailable")
	}
	if encrypt {
		sealed, err := vault.Seal(key, data)
		if err != nil {
			return nil, err
		}
		return append(append([]byte("VSC1"), sealed.Nonce...), sealed.Ciphertext...), nil
	}
	if len(data) < 32 || string(data[:4]) != "VSC1" {
		return nil, errors.New("invalid encrypted reconnect state")
	}
	return vault.Open(key, vault.Sealed{Nonce: data[4:16], Ciphertext: data[16:]})
}
