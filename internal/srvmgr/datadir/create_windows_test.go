package datadir

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// openFolder is a folder whose ACL lets Everyone read what is created in
// it, as a folder outside the data directory may.
func openFolder(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)(A;OICI;FR;;;WD)", tu.User.Sid.String()))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A file made by Create in such a folder is owner-only from the start,
// and stays so when Replace puts it in place of another.
func TestCreateOwnerOnlyInOpenFolder(t *testing.T) {
	dir := openFolder(t)
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, []byte("x"), 0o600)
	if err := Check(plain, false); err == nil {
		t.Fatal("the folder is not open: the test proves nothing")
	}
	tmp := filepath.Join(dir, "key.new")
	f, err := Create(tmp)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("secret")
	f.Close()
	if err := Check(tmp, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(tmp); !os.IsExist(err) {
		t.Fatalf("Create over an existing file: %v", err)
	}
	dst := filepath.Join(dir, "key")
	os.WriteFile(dst, []byte("old"), 0o600)
	if err := Replace(tmp, dst); err != nil {
		t.Fatal(err)
	}
	if err := Check(dst, false); err != nil {
		t.Fatalf("after Replace: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "secret" {
		t.Fatalf("content %q", b)
	}
}
