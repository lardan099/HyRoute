package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// HYROUTE_MASTER_KEY of white space is no key: the key file is read, so a
// file outside the data directory gets the controller's ACL too.
func TestBlankEnvKeyFileGetsACL(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "keys", "master.key")
	os.MkdirAll(filepath.Dir(keyFile), 0o700)
	text, err := secrets.NewKeyText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	env := func(k string) string {
		switch k {
		case "HYROUTE_SERVER_DATA_DIR":
			return dir
		case secrets.EnvMasterKey:
			return " \n"
		}
		return ""
	}
	if err := runOnceEnv(env, "-master-key-file", keyFile); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(keyFile, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	// Protected: nothing inherited from the folder the file is in.
	if s := sd.String(); !strings.Contains(s, "D:P") {
		t.Fatalf("key file ACL %s", s)
	}
}
