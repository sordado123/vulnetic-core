package reverseagent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func nativeUpload(ctx context.Context, directory, name, expected string, source io.Reader, out io.Writer) error {
	if name == "" || !filepath.IsLocal(name) || strings.ContainsAny(name, "/\\:\x00\r\n") || name == "." || name == ".." {
		return errors.New("invalid upload name")
	}
	if expected != "" {
		b, e := hex.DecodeString(expected)
		if e != nil || len(b) != sha256.Size {
			return errors.New("invalid expected digest")
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.MkdirAll("uploads", 0700); err != nil {
		return err
	}
	info, err := root.Lstat("uploads")
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe upload directory")
	}
	uploads, err := root.OpenRoot("uploads")
	if err != nil {
		return err
	}
	defer uploads.Close()
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	tmp := ".vulnetic-" + hex.EncodeToString(id[:])
	defer uploads.Remove(tmp)
	f, err := uploads.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(source, (20<<20)+1))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if size > 20<<20 {
		return errors.New("upload exceeds 20 MiB")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if expected != "" && expected != digest {
		return errors.New("transfer checksum mismatch")
	}
	if err = uploads.Link(tmp, name); err != nil {
		if !errors.Is(err, os.ErrExist) || expected == "" {
			return err
		}
		info, e := uploads.Lstat(name)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("existing upload is not a regular file")
		}
		old, e := uploads.Open(name)
		if e != nil {
			return e
		}
		defer old.Close()
		previous := sha256.New()
		if _, e = io.Copy(previous, io.LimitReader(old, (20<<20)+1)); e != nil {
			return e
		}
		if hex.EncodeToString(previous.Sum(nil)) != digest {
			return errors.New("existing upload differs")
		}
	}
	return json.NewEncoder(out).Encode(map[string]string{"path": filepath.ToSlash(filepath.Join(directory, "uploads", name)), "sha256": digest})
}
