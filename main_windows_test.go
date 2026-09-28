package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/runtimefiles"
)

// TestSleepHelper is the process TestWaitProcess starts.
func TestSleepHelper(t *testing.T) {
	if os.Getenv("HYROUTE_TEST_SLEEP") == "1" {
		time.Sleep(time.Minute)
	}
}

// After a move the new copy waits for the old one without a limit, so a
// process that only reuses the old copy's number (started later) must not
// be waited for.
func TestWaitProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestSleepHelper$")
	cmd.Env = append(os.Environ(), "HYROUTE_TEST_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	done := make(chan struct{})
	go func() {
		waitProcess(uint32(cmd.Process.Pid))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waited for a process started after this one")
	}

	// The process that started this one (as the old copy starts the new).
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getppid()))
	if err != nil {
		t.Skip("parent process gone:", err)
	}
	defer windows.CloseHandle(h)
	if startedAfter(h, windows.CurrentProcess()) {
		t.Fatal("the parent process counts as started later")
	}
}

// WebView2's data are kept out of the user's profile, in HyRoute's
// protected folder, one folder per Windows user. (Tests do not run under
// Administrator protection: this process is its own limited user.)
func TestWebviewDataDir(t *testing.T) {
	dir, protect, err := webviewDataDir()
	if err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(core.DefaultDir("webview"), u.User.Sid.String()); !strings.EqualFold(dir, want) || !protect {
		t.Fatalf("WebView2 data in %s (protected %v), want %s protected", dir, protect, want)
	}
	if deElevatedLocalAppData(u.User.Sid) != "" {
		t.Fatal("a process without a separate admin account counts as de-elevated")
	}
}

// Administrator protection elevates as another account (WebView2 then
// runs as the limited user); plain UAC elevates the same account.
func TestProfileSeparated(t *testing.T) {
	user, _ := windows.StringToSid("S-1-5-21-1-2-3-1000")
	same, _ := windows.StringToSid("S-1-5-21-1-2-3-1000")
	admin, _ := windows.StringToSid("S-1-5-21-1-2-3-1002")
	if profileSeparated(user, same) || !profileSeparated(admin, user) {
		t.Fatal("wrong account comparison")
	}
}

// A process whose number is the updater's but that was created after the
// swap began (the number was taken again, say after a restart of Windows)
// is not the updater: the interrupted update is recovered.
func TestUpdaterAlive(t *testing.T) {
	self := uint32(os.Getpid())
	if !updaterAlive(self, time.Now()) {
		t.Fatal("a process running since before the swap is not taken for the updater")
	}
	if updaterAlive(self, time.Now().Add(-time.Hour)) {
		t.Fatal("a process created after the swap began is taken for the updater")
	}
}

// The shared runtime folder holds a different copy that is in use
// (another user's HyRoute of another version runs it): this build's
// copies go to a folder of its own, and HyRoute starts.
func TestStageRuntimeInUse(t *testing.T) {
	src, runtimeDir := t.TempDir(), t.TempDir()
	content := []byte("hysteria of this build")
	if err := os.WriteFile(filepath.Join(src, "hysteria.exe"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	busy := filepath.Join(runtimeDir, "hysteria.exe")
	if err := os.WriteFile(busy, []byte("hysteria of another version"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(busy)
	if err != nil {
		t.Fatal(err)
	}
	// As a running exe: no one may write, rename or remove it.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	sum := sha256.Sum256(content)
	files := []runtimefiles.File{{Name: "hysteria.exe", SHA256: hex.EncodeToString(sum[:])}}
	protect := func(dir string) error { return os.MkdirAll(dir, 0o755) }
	dir, _, err := stageRuntime(src, runtimeDir, files, nil, protect)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(dir) != runtimeDir {
		t.Fatalf("staged into %s, want a folder under %s", dir, runtimeDir)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "hysteria.exe")); err != nil || string(b) != string(content) {
		t.Fatalf("staged copy %q (%v)", b, err)
	}

	// Nothing in use: the shared folder, as always.
	windows.CloseHandle(h)
	h = 0
	if dir, _, err := stageRuntime(src, runtimeDir, files, nil, protect); err != nil || dir != runtimeDir {
		t.Fatalf("staged into %s (%v), want %s", dir, err, runtimeDir)
	}
}
