package hysteria

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// Until Hysteria has read its config, the file in the user's RunDir can be
// read but not rewritten, replaced or deleted by the user's other programs.
func TestSecretFileHeldUntilReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), configName())
	closeFile, err := writeSecretFile(path, []byte("server: 198.51.100.1:443\n"))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(closeFile) }
	defer release()
	if b, err := os.ReadFile(path); err != nil || string(b) != "server: 198.51.100.1:443\n" {
		t.Fatalf("Hysteria cannot read the config: %q %v", b, err)
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Fatal("config opened for writing while held")
	}
	if err := os.Rename(path, path+".old"); err == nil {
		t.Fatal("config renamed while held")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("config deleted while held")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		tu, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(sd.String(), tu.User.Sid.String()) {
			t.Fatalf("elevated: the user keeps access to the config: %s", sd)
		}
	}
	release()
	if err := os.Remove(path); err != nil {
		t.Fatalf("config not removable after release: %v", err)
	}
}
