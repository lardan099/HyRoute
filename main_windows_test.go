package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/core"
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
// protected folder, one folder per Windows user.
func TestWebviewDataDir(t *testing.T) {
	dir, err := webviewDataDir()
	if err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(core.DefaultDir("webview"), u.User.Sid.String()); !strings.EqualFold(dir, want) {
		t.Fatalf("WebView2 data in %s, want %s", dir, want)
	}
}
