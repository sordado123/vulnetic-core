package sshexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"io"
	"strings"
)

// Upload writes a new file through the existing SSH session, never a local process.
func (l *LazyExecutor) Upload(ctx context.Context, name string, source io.Reader) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\\x00\r\n") || name == "." || name == ".." {
		return "", fmt.Errorf("invalid upload name")
	}
	return l.upload(ctx, name, source, "")
}

// RestoreUpload is idempotent only for identical files; existing data is never overwritten.
func (l *LazyExecutor) RestoreUpload(ctx context.Context, name string, data []byte) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\\x00\r\n") || name == "." || name == ".." {
		return "", fmt.Errorf("invalid upload name")
	}
	sum := sha256.Sum256(data)
	return l.upload(ctx, name, bytes.NewReader(data), hex.EncodeToString(sum[:]))
}

func (l *LazyExecutor) upload(ctx context.Context, name string, source io.Reader, expected string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	code := `import os,sys,hashlib,json,tempfile,stat
base=os.path.realpath('.')
os.makedirs('uploads',mode=0o700,exist_ok=True)
directory=os.path.realpath('uploads')
if os.path.commonpath([base,directory])!=base or os.path.islink('uploads'): raise RuntimeError('upload directory escapes workspace')
path=os.path.join(directory,sys.argv[1])
fd,tmp=tempfile.mkstemp(prefix='.vulnetic-',dir=directory)
try:
 h=hashlib.sha256()
 with os.fdopen(fd,'wb') as f:
  while True:
   data=sys.stdin.buffer.read(65536)
   if not data: break
   f.write(data); h.update(data)
  f.flush(); os.fsync(f.fileno())
 digest=h.hexdigest()
 expected=sys.argv[2]
 if expected and expected!=digest: raise RuntimeError('transfer checksum mismatch')
 try: os.link(tmp,path)
 except FileExistsError:
  if not expected: raise
  oldfd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(oldfd,'rb') as old:
   if not stat.S_ISREG(os.fstat(old.fileno()).st_mode): raise RuntimeError('existing destination is not a file')
   oldhash=hashlib.sha256()
   for chunk in iter(lambda:old.read(65536),b''): oldhash.update(chunk)
   if oldhash.hexdigest()!=digest: raise RuntimeError('existing destination differs')
 print(json.dumps({'path':path,'sha256':digest}))
finally:
 os.unlink(tmp)
`
	command := "python3 -c " + shellSingleQuote(code) + " " + shellSingleQuote(name) + " " + shellSingleQuote(expected)
	if l.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "upload", Name: name, Expected: expected})
	}
	r, w, closeSession, err := l.OpenStdio(ctx, command, nil)
	if err != nil {
		return "", err
	}
	defer closeSession.Close()
	hasher := sha256.New()
	if _, err = io.Copy(w, io.TeeReader(source, hasher)); err != nil {
		return "", err
	}
	if closer, ok := w.(io.Closer); ok {
		if err = closer.Close(); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("SSH stdin cannot be closed")
	}
	out, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return "", err
	}
	var ack struct {
		Path   string `json:"path"`
		Digest string `json:"sha256"`
	}
	if len(out) > 4096 || json.Unmarshal(out, &ack) != nil {
		return "", fmt.Errorf("invalid remote upload acknowledgement")
	}
	absolute := strings.HasPrefix(ack.Path, "/")
	if l.ExecutionOS() == "windows" {
		absolute = len(ack.Path) > 3 && ack.Path[1] == ':' && ack.Path[2] == '/' && ((ack.Path[0] >= 'A' && ack.Path[0] <= 'Z') || (ack.Path[0] >= 'a' && ack.Path[0] <= 'z'))
	}
	if ack.Digest != hex.EncodeToString(hasher.Sum(nil)) || !absolute || strings.ContainsAny(ack.Path, "\r\n\x00") {
		return "", fmt.Errorf("remote upload did not acknowledge file integrity; check for a conflicting file or unsafe uploads directory")
	}
	return ack.Path, nil
}
