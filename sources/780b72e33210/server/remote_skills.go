package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/internal/norma/skill"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
)

type skillArchiveBuffer struct{ bytes.Buffer }

func (b *skillArchiveBuffer) Write(data []byte) (int, error) {
	if len(data) > maxSkillZipBytes-b.Len() {
		return 0, fmt.Errorf("skill package exceeds the 20 MiB transport limit")
	}
	return b.Buffer.Write(data)
}

func skillSnapshot(root *os.Root) ([]byte, skill.Skill, error) {
	var buffer skillArchiveBuffer
	writer := zip.NewWriter(&buffer)
	var metadata skill.Skill
	foundMetadata := false
	var total int64
	count := 0
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("skill packages cannot contain symbolic links")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxSkillFileBytes {
			return fmt.Errorf("unsupported or oversized skill file: %s", path)
		}
		total += info.Size()
		count++
		if total > maxSkillTotalBytes || count > maxSkillEntries {
			return fmt.Errorf("skill exceeds package limits")
		}
		input, err := root.Open(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := writer.Create(path)
		if err != nil {
			return err
		}
		if path == "SKILL.md" {
			foundMetadata = true
			data, err := io.ReadAll(io.LimitReader(input, maxSkillFileBytes+1))
			if err != nil {
				return err
			}
			if int64(len(data)) != info.Size() {
				return fmt.Errorf("skill changed during snapshot; retry")
			}
			metadata = skill.Parse(data)
			_, err = output.Write(data)
			return err
		}
		n, err := io.Copy(output, io.LimitReader(input, maxSkillFileBytes+1))
		if err == nil && n != info.Size() {
			return fmt.Errorf("skill changed during snapshot; retry")
		}
		return err
	})
	closeErr := writer.Close()
	if err != nil {
		return nil, skill.Skill{}, err
	}
	if closeErr != nil {
		return nil, skill.Skill{}, closeErr
	}
	if !foundMetadata {
		return nil, skill.Skill{}, fmt.Errorf("SKILL.md is missing from this package")
	}
	return buffer.Bytes(), metadata, nil
}

func prepareRemoteSkill(ctx context.Context, accountID int64, directory string, value skill.Skill) (skill.Skill, error) {
	run := agent.RunInfoFrom(ctx)
	executor, ok := run.Executor.(*sshexec.LazyExecutor)
	if !ok || run.AccountID != accountID || accountID <= 0 {
		return value, fmt.Errorf("select this account's verified VPS")
	}
	name := filepath.Base(value.Dir)
	if !validSkillName(name) {
		return value, fmt.Errorf("invalid skill package")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return value, err
	}
	defer root.Close()
	packageRoot, err := root.OpenRoot(name)
	if err != nil {
		return value, fmt.Errorf("skill package escapes its account or is unavailable")
	}
	defer packageRoot.Close()
	data, current, err := skillSnapshot(packageRoot)
	if err != nil {
		return value, err
	}
	if current.Name != "" && current.Name != value.Name || !slices.Equal(current.MCPs, value.MCPs) {
		return value, fmt.Errorf("skill configuration changed; start a new turn")
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	account, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		return value, err
	}
	defer account.Close()
	if err = account.MkdirAll("artifacts", 0700); err != nil {
		return value, err
	}
	artifacts, err := account.OpenRoot("artifacts")
	if err != nil {
		return value, err
	}
	defer artifacts.Close()
	snapshot := filepath.Join("skills", name, hash+".zip")
	if err = artifacts.MkdirAll(filepath.Dir(snapshot), 0700); err != nil {
		return value, err
	}
	if err = saveRootBytes(artifacts, snapshot, data); err != nil {
		return value, err
	}
	archive, err := executor.Upload(ctx, "skill-"+uuid.NewString()+".zip", bytes.NewReader(data))
	if err != nil {
		return value, err
	}
	command := "python3 -c " + shellQuote(remoteSkillInstall) + " " + shellQuote(archive) + " " + shellQuote(name) + " " + shellQuote(hash)
	if executor.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "skill", Name: name, Expected: hash, Command: filepath.Base(archive)})
	}
	var output bytes.Buffer
	handle, err := executor.Start(ctx, "", nil, command, &output)
	if err != nil {
		return value, err
	}
	if err = handle.Wait(); err != nil {
		return value, fmt.Errorf("remote skill installation failed")
	}
	remote := strings.TrimSpace(output.String())
	absolute := strings.HasPrefix(remote, "/") || (executor.ExecutionOS() == "windows" && len(remote) > 3 && remote[1] == ':' && remote[2] == '/')
	if !absolute || strings.ContainsAny(remote, "\r\n\x00") || len(remote) > 4096 {
		return value, fmt.Errorf("remote skill installation was not acknowledged")
	}
	value.Instructions = current.Instructions + "\n\nReproduction package SHA256: " + hash + ". Account workspace snapshot: " + filepath.ToSlash(snapshot)
	value.Dir = remote
	return value, nil
}

const remoteSkillInstall = `import hashlib,os,posixpath,shutil,stat,sys,tempfile,zipfile
archive,name,expected=sys.argv[1:]
base=os.path.realpath('.')
os.makedirs('skills',mode=0o700,exist_ok=True)
parent=os.path.realpath('skills')
if os.path.commonpath([base,parent])!=base: raise RuntimeError('skill directory escapes workspace')
temporary=tempfile.mkdtemp(prefix='.'+name+'-',dir=parent)
installed=False
try:
 with open(archive,'rb') as source:
  digest=hashlib.sha256()
  for block in iter(lambda: source.read(65536),b''): digest.update(block)
  if digest.hexdigest()!=expected: raise RuntimeError('skill package hash mismatch')
 with zipfile.ZipFile(archive) as package:
  entries=package.infolist()
  if len(entries)>4000 or sum(entry.file_size for entry in entries)>100*1024*1024: raise RuntimeError('skill package exceeds limits')
  for entry in entries:
   relative=posixpath.normpath(entry.filename)
   if relative.startswith('/') or relative=='..' or relative.startswith('../') or '\\' in relative or stat.S_ISLNK(entry.external_attr>>16) or entry.file_size>20*1024*1024: raise RuntimeError('invalid skill package path')
   destination=os.path.join(temporary,*relative.split('/'))
   if entry.is_dir(): os.makedirs(destination,mode=0o700,exist_ok=True); continue
   os.makedirs(os.path.dirname(destination),mode=0o700,exist_ok=True)
   with package.open(entry) as source,open(destination,'xb') as target: shutil.copyfileobj(source,target)
 if not os.path.isfile(os.path.join(temporary,'SKILL.md')): raise RuntimeError('missing SKILL.md')
 installed=True
 print(temporary)
finally:
 os.unlink(archive)
 if not installed: shutil.rmtree(temporary)
`
