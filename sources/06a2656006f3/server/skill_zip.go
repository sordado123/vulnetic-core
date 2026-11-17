package server

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/internal/artifactquota"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func (s *Server) installSkillZip(accountID int64, name, prefix string, entries []skillZipEntry, overwrite bool) (int, error) {
	var expected int64
	count := 0
	for _, entry := range entries {
		if prefix != "" && !strings.HasPrefix(entry.name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(entry.name, prefix)
		if rel == "" {
			continue
		}
		if _, message := skillRelPath(rel); message != "" {
			return 0, fmt.Errorf("archive contains an illegal path %s: %s", entry.name, message)
		}
		if entry.f.Mode()&os.ModeSymlink != 0 {
			return 0, fmt.Errorf("symbolic links are not accepted in skill archives")
		}
		if entry.f.UncompressedSize64 > maxSkillFileBytes {
			return 0, fmt.Errorf("file too large: %s", rel)
		}
		expected += int64(entry.f.UncompressedSize64)
		count++
		if expected > maxSkillTotalBytes || count > maxSkillEntries {
			return 0, fmt.Errorf("skill archive exceeds extraction limits")
		}
	}
	root, err := s.accountStorage(accountID)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	destination := filepath.Join("skills", name)
	err = artifactquota.Write(root, destination, expected, false, func() error {
		_, statErr := root.Lstat(destination)
		exists := statErr == nil
		if exists && !overwrite {
			return os.ErrExist
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
		staged := filepath.Join("skills", ".upload-"+uuid.NewString())
		if err := root.MkdirAll(staged, 0700); err != nil {
			return err
		}
		defer root.RemoveAll(staged)
		for _, entry := range entries {
			if prefix != "" && !strings.HasPrefix(entry.name, prefix) {
				continue
			}
			rel := strings.TrimPrefix(entry.name, prefix)
			if rel == "" {
				continue
			}
			clean, _ := skillRelPath(rel)
			filePath := filepath.Join(staged, filepath.FromSlash(clean))
			if entry.f.FileInfo().IsDir() {
				if err := root.MkdirAll(filePath, 0700); err != nil {
					return err
				}
				continue
			}
			if err := root.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
				return err
			}
			reader, err := entry.f.Open()
			if err != nil {
				return err
			}
			file, err := root.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				reader.Close()
				return err
			}
			n, copyErr := io.Copy(file, io.LimitReader(reader, maxSkillFileBytes+1))
			closeErr := file.Close()
			reader.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if n != int64(entry.f.UncompressedSize64) || n > maxSkillFileBytes {
				return fmt.Errorf("invalid extracted file size: %s", rel)
			}
		}
		if info, err := root.Stat(filepath.Join(staged, "SKILL.md")); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("SKILL.md missing after extraction")
		}
		backup := filepath.Join("skills", ".previous-"+uuid.NewString())
		if exists {
			if err := root.Rename(destination, backup); err != nil {
				return err
			}
		}
		if err := root.Rename(staged, destination); err != nil {
			if exists {
				if rollbackErr := root.Rename(backup, destination); rollbackErr != nil {
					return fmt.Errorf("installation failed; original skill preserved at %s: %w", backup, rollbackErr)
				}
			}
			return err
		}
		if exists {
			return root.RemoveAll(backup)
		}
		return nil
	})
	return count, err
}

// Go's archive/zip ships only Store(0) and Deflate(8) decompressors; any other
// method returns "zip: unsupported compression algorithm". Archivers at
// non-default settings often write other methods (7-Zip's bzip2, WinZip's
// zstd), so the two a pure-Go build can decode are registered here; the ones we
// truly cannot decode (Deflate64 / LZMA / XZ / PPMd / encrypted archives) get a
// clear error message before extraction instead of surfacing the raw
// underlying error to the user.
const (
	zipMethodStore     = 0
	zipMethodDeflate   = 8
	zipMethodDeflate64 = 9
	zipMethodBzip2     = 12
	zipMethodLZMA      = 14
	zipMethodZstdPKW   = 20 // the number PKWARE originally assigned to zstd
	zipMethodZstd      = 93
	zipMethodXZ        = 95
	zipMethodJPEG      = 96
	zipMethodWavPack   = 97
	zipMethodPPMd      = 98
	zipMethodAES       = 99
)

var zipMethodNames = map[uint16]string{
	zipMethodStore:     "Store",
	zipMethodDeflate:   "Deflate",
	zipMethodDeflate64: "Deflate64",
	zipMethodBzip2:     "bzip2",
	zipMethodLZMA:      "LZMA",
	zipMethodZstdPKW:   "Zstandard",
	zipMethodZstd:      "Zstandard",
	zipMethodXZ:        "XZ",
	zipMethodJPEG:      "JPEG",
	zipMethodWavPack:   "WavPack",
	zipMethodPPMd:      "PPMd",
	zipMethodAES:       "AES encrypted",
}

func zipMethodName(m uint16) string {
	if n, ok := zipMethodNames[m]; ok {
		return n
	}
	return "unknown"
}

// newSkillZipReader parses an uploaded archive and registers the extra decompressors
// we can support beyond the stdlib's Store/Deflate.
func newSkillZipReader(buf []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("cannot parse archive (must be zip format): %w", err)
	}
	zr.RegisterDecompressor(zipMethodBzip2, func(r io.Reader) io.ReadCloser {
		return io.NopCloser(bzip2.NewReader(r))
	})
	zdec := zstd.ZipDecompressor(zstd.WithDecoderConcurrency(1))
	zr.RegisterDecompressor(zipMethodZstd, zdec)
	zr.RegisterDecompressor(zipMethodZstdPKW, zdec)
	return zr, nil
}

// skillZipEntry pairs a zip entry with its decoded (UTF-8) name — f.Name may hold
// raw GBK bytes, see zipEntryName.
type skillZipEntry struct {
	f    *zip.File
	name string
}

// skillZipEntries lists the archive's real files (no directory entries, no archiver
// junk) with their names decoded to UTF-8.
func skillZipEntries(zr *zip.Reader) []skillZipEntry {
	out := make([]skillZipEntry, 0, len(zr.File))
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := zipEntryName(f)
		if strings.HasPrefix(name, "__MACOSX/") || strings.Contains(name, "/__MACOSX/") ||
			path.Base(name) == ".DS_Store" {
			continue // macOS archiving leftovers
		}
		out = append(out, skillZipEntry{f: f, name: name})
	}
	return out
}

// zipEntryName returns the entry path as UTF-8. 7-Zip / WinRAR / Explorer on
// Windows write Chinese filenames as GBK bytes when the UTF-8 flag is not set,
// and Go keeps those bytes verbatim, leaving a name that is neither valid UTF-8
// nor able to pass path validation — fall back to GBK decoding here.
func zipEntryName(f *zip.File) string {
	if utf8.ValidString(f.Name) {
		return f.Name
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().String(f.Name); err == nil && utf8.ValidString(dec) {
		return dec
	}
	return f.Name
}

// checkSkillZipMethods rejects archives we cannot extract, naming the offending
// entry and method instead of letting f.Open() fail with an opaque English error.
func checkSkillZipMethods(entries []skillZipEntry) error {
	for _, e := range entries {
		if e.f.Flags&0x1 != 0 || e.f.Method == zipMethodAES {
			return fmt.Errorf("archive is encrypted (%s); please upload an unencrypted zip", e.name)
		}
		switch e.f.Method {
		case zipMethodStore, zipMethodDeflate, zipMethodBzip2, zipMethodZstd, zipMethodZstdPKW:
		default:
			return fmt.Errorf("archive uses unsupported compression method %s (method %d): %s. "+
				"Please repack with \"Store\" or \"Deflate\" (choose Deflate as the compression "+
				"method in 7-Zip/WinRAR, use the built-in \"Compress/Send to compressed folder\", "+
				"or the zip -r command)",
				zipMethodName(e.f.Method), e.f.Method, e.name)
		}
	}
	return nil
}
