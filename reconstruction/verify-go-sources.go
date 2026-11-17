// Verifies source archives with the standard Go h1 directory-hash algorithm.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type sourceFile struct{ Path, SHA256 string }
type module struct {
	Name, Version, Sum string
	Files              []sourceFile
}

func check(root string) error {
	b, err := os.ReadFile(filepath.Join(root, "dependency-source-index.json"))
	if err != nil {
		return err
	}
	var index struct{ Go []module }
	if err = json.Unmarshal(b, &index); err != nil {
		return err
	}
	if len(index.Go) != 52 {
		return fmt.Errorf("expected 52 module source archives")
	}
	for _, m := range index.Go {
		var archive string
		for _, f := range m.Files {
			if !strings.HasSuffix(f.Path, "/source.zip") {
				continue
			}
			if !strings.HasPrefix(f.Path, "dependency-sources/go/") || strings.Contains(f.Path, "\\") || path.Clean(f.Path) != f.Path {
				return fmt.Errorf("invalid source path")
			}
			archive = filepath.Join(root, filepath.FromSlash(f.Path))
			data, err := os.ReadFile(archive)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != f.SHA256 {
				return fmt.Errorf("archive SHA256 mismatch: %s", m.Name)
			}
		}
		if archive == "" {
			return fmt.Errorf("missing archive: %s", m.Name)
		}
		z, err := zip.OpenReader(archive)
		if err != nil {
			return err
		}
		err = func() error {
			defer z.Close()
			files := make(map[string]*zip.File)
			names := make([]string, 0, len(z.File))
			for _, f := range z.File {
				if f.FileInfo().IsDir() {
					continue
				}
				if _, exists := files[f.Name]; exists {
					return fmt.Errorf("duplicate ZIP path")
				}
				if !strings.HasPrefix(f.Name, m.Name+"@"+m.Version+"/") || path.Clean(f.Name) != f.Name || strings.ContainsAny(f.Name, "\n\r\\") || f.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("unsafe module path: %s", m.Name)
				}
				files[f.Name] = f
				names = append(names, f.Name)
			}
			sort.Strings(names)
			combined := sha256.New()
			for _, name := range names {
				r, err := files[name].Open()
				if err != nil {
					return err
				}
				h := sha256.New()
				_, copyErr := io.Copy(h, r)
				closeErr := r.Close()
				if copyErr != nil {
					return copyErr
				}
				if closeErr != nil {
					return closeErr
				}
				fmt.Fprintf(combined, "%x  %s\n", h.Sum(nil), name)
			}
			if "h1:"+base64.StdEncoding.EncodeToString(combined.Sum(nil)) != m.Sum {
				return fmt.Errorf("Go h1 mismatch: %s", m.Name)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	fmt.Println("52 source archives verified: SHA256, Go h1, paths and duplicates")
	return nil
}

func main() {
	root := flag.String("root", ".", "source package directory")
	flag.Parse()
	if err := check(*root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
