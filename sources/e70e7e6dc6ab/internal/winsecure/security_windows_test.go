package winsecure

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateWindowsACL(t *testing.T) {
	sid, err := UserSID()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = Restrict(dir, sid, true); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "credential")
	if err = os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Private(file); err != nil {
		t.Fatal("private ACL rejected:", err)
	}
	acl, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := acl.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err = Private(file); err == nil {
		t.Fatal("publicly readable credential was accepted")
	}
	if err = Restrict(file, sid, true); err != nil {
		t.Fatal(err)
	}
}
