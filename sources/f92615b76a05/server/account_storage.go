package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sordado123/vulnetic/internal/artifactquota"
)

func (s *Server) accountStorage(accountID int64) (*os.Root, error) {
	if accountID <= 0 {
		return nil, fmt.Errorf("account is required")
	}
	base, err := os.OpenRoot(s.m.dir)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	rel := filepath.Join("accounts", fmt.Sprint(accountID))
	if err = base.MkdirAll(rel, 0700); err != nil {
		return nil, err
	}
	return base.OpenRoot(rel)
}

func (s *Server) writeAccountFile(accountID int64, relative string, data []byte) error {
	if err := checkArtifactQuota(0, int64(len(data))); err != nil {
		return err
	}
	root, err := s.accountStorage(accountID)
	if err != nil {
		return err
	}
	defer root.Close()
	return artifactquota.Write(root, relative, int64(len(data)), false, func() error {
		if err := root.MkdirAll(filepath.Dir(relative), 0700); err != nil {
			return err
		}
		return replaceRootBytes(root, relative, data)
	})
}

func (s *Server) readAccountFile(accountID int64, relative string) ([]byte, error) {
	root, err := s.accountStorage(accountID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (20<<20)+1))
	if err == nil && len(data) > 20<<20 {
		return nil, fmt.Errorf("file exceeds the 20 MiB limit")
	}
	return data, err
}

func (s *Server) createAccountSkill(accountID int64, name string, data []byte, mcps []string) error {
	if !validSkillName(name) {
		return fmt.Errorf("invalid skill name")
	}
	if err := checkArtifactQuota(0, int64(len(data))); err != nil {
		return err
	}
	root, err := s.accountStorage(accountID)
	if err != nil {
		return err
	}
	defer root.Close()
	directory := filepath.Join("skills", name)
	return artifactquota.Write(root, directory, int64(len(data)), false, func() error {
		if err := root.MkdirAll("skills", 0700); err != nil {
			return err
		}
		if err := root.Mkdir(directory, 0700); err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = root.RemoveAll(directory)
			}
		}()
		if err := replaceRootBytes(root, filepath.Join(directory, "SKILL.md"), data); err != nil {
			return err
		}
		if err := verifySkillFile(filepath.Join(root.Name(), directory), name, mcps); err != nil {
			return err
		}
		committed = true
		return nil
	})
}
