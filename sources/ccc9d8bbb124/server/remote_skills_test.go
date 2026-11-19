package server

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBetaSkillSnapshotIsReproducibleAndConfined(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.MkdirAll("scripts", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("SKILL.md", []byte("---\nname: fixture\ndescription: private\n---\npython3 ${SKILL_DIR}/scripts/run.py"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("scripts/run.py", []byte("print('remote fixture')"), 0600); err != nil {
		t.Fatal(err)
	}
	first, metadata, err := skillSnapshot(root)
	if err != nil || metadata.Name != "fixture" {
		t.Fatal(metadata, err)
	}
	second, _, err := skillSnapshot(root)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unchanged package produced a different snapshot", err)
	}
	archive, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range archive.File {
		if entry.Name == "scripts/run.py" {
			reader, _ := entry.Open()
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || string(data) != "print('remote fixture')" {
				t.Fatal("snapshot lost script content", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("script missing from package")
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("must never be exported"), 0600); err != nil {
		t.Fatal(err)
	}
	linkTestDirectory(t, outside, filepath.Join(directory, "escape"))
	if _, _, err := skillSnapshot(root); err == nil {
		t.Fatal("snapshot accepted a filesystem escape")
	}
}

func TestBetaSkillListingCannotFollowDirectoryLinks(t *testing.T) {
	parent, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	linkTestDirectory(t, outside, linked)
	if _, err := walkSkillFiles(linked); err == nil {
		t.Fatal("listing followed a skill directory outside its account")
	}
	directory := filepath.Join(parent, "regular")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte("private skill"), 0600); err != nil {
		t.Fatal(err)
	}
	linkTestDirectory(t, outside, filepath.Join(directory, "escape"))
	files, err := walkSkillFiles(directory)
	if err != nil || !slices.Equal(files, []string{"SKILL.md"}) {
		t.Fatalf("unexpected confined listing: %v, %v", files, err)
	}
}
