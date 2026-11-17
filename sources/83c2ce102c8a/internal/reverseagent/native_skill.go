package reverseagent

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var nativeSkillName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func nativeSkill(ctx context.Context, directory, archive, name, expected string) (string, error) {
	if !nativeSkillName.MatchString(name) || archive == "" || !filepath.IsLocal(archive) || strings.ContainsAny(archive, "/\\:\x00\r\n") || len(expected) != 64 {
		return "", errors.New("invalid skill snapshot")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	input, err := root.Open(filepath.Join("uploads", archive))
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(input, (20<<20)+1))
	closeErr := input.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if len(data) > 20<<20 {
		return "", errors.New("skill archive exceeds 20 MiB")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return "", errors.New("skill archive checksum mismatch")
	}
	packageFile, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	if len(packageFile.File) > 4000 {
		return "", errors.New("too many skill entries")
	}
	if err = root.MkdirAll("skills", 0700); err != nil {
		return "", err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	relativeDir := filepath.Join("skills", "."+name+"-"+hex.EncodeToString(random[:]))
	if err = root.Mkdir(relativeDir, 0700); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = root.RemoveAll(relativeDir)
		}
	}()
	extracted, err := root.OpenRoot(relativeDir)
	if err != nil {
		return "", err
	}
	defer extracted.Close()
	var total uint64
	for _, entry := range packageFile.File {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		relative := path.Clean(entry.Name)
		if len(relative) > 512 || relative == "." || !filepath.IsLocal(filepath.FromSlash(relative)) || strings.ContainsAny(relative, "\\:\x00\r\n") || entry.Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > 20<<20 {
			return "", errors.New("unsafe skill entry")
		}
		total += entry.UncompressedSize64
		if total > 100<<20 {
			return "", errors.New("skill exceeds uncompressed limit")
		}
		if entry.FileInfo().IsDir() {
			if err = extracted.MkdirAll(filepath.FromSlash(relative), 0700); err != nil {
				return "", err
			}
			continue
		}
		if err = extracted.MkdirAll(filepath.Dir(filepath.FromSlash(relative)), 0700); err != nil {
			return "", err
		}
		in, e := entry.Open()
		if e != nil {
			return "", e
		}
		out, e := extracted.OpenFile(filepath.FromSlash(relative), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			in.Close()
			return "", e
		}
		size, e := io.Copy(out, io.LimitReader(in, (20<<20)+1))
		in.Close()
		closeErr = out.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return "", e
		}
		if size > 20<<20 || uint64(size) != entry.UncompressedSize64 {
			return "", errors.New("invalid extracted skill size")
		}
	}
	info, err := extracted.Stat("SKILL.md")
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("missing SKILL.md")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = root.Remove(filepath.Join("uploads", archive)); err != nil {
		return "", err
	}
	complete = true
	return filepath.Join(directory, relativeDir), nil
}
