package sshexec

import (
	"bytes"
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestBetaRemoteOutputLimit(t *testing.T) {
	var output bytes.Buffer
	writer := &syncWriter{w: &output, limit: 4}
	if _, err := writer.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("oversize")); err == nil {
		t.Fatal("output limit was bypassed")
	}
	if output.String() != "1234" || writer.Err() == nil {
		t.Fatal("bounded output or failure state was lost")
	}
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("failed output stream resumed")
	}
	handle := &execHandle{outputError: writer.Err}
	if handle.ExitCode(&ssh.ExitError{}) != -1 {
		t.Fatal("remote exit status hid the output-limit error")
	}
}
