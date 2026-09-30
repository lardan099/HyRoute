package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	os.Mkdir(dir, 0o700)
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "master.key")
	os.WriteFile(key, []byte("fake"), 0o600)
	if err := File(key); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, key} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		s := sd.String()
		// Protected, and no entry for Users or Everyone.
		if !strings.Contains(s, "D:P") || strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;WD)") || !strings.Contains(s, ";;;SY)") {
			t.Fatalf("%s: %s", p, s)
		}
	}
}
