//go:build windows

package divert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A failed load is not remembered: after an antivirus lets the file
// through, the next Connect loads it.
func TestLoadRetriesAfterFailure(t *testing.T) {
	for _, dir := range []string{t.TempDir(), t.TempDir()} {
		err := Load(dir)
		if err == nil {
			t.Fatal("loaded WinDivert.dll from an empty folder")
		}
		if !strings.Contains(err.Error(), dir) {
			t.Fatalf("error from an earlier attempt: %v (want %s)", err, dir)
		}
	}
	if dllLoaded || procOpen != nil {
		t.Fatal("failed load left state behind")
	}
}

// A DLL without the WinDivert exports is unloaded again: LoadLibrary would
// hand the next Load the same module even after the file is replaced.
func TestLoadUnloadsWrongDLL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "version.dll"))
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "WinDivert.dll")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Load(dir); err == nil || !strings.Contains(err.Error(), "WinDivertOpen") {
		t.Fatalf("DLL without WinDivert exports: %v", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var h windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &h); err == nil {
		t.Fatal("DLL without WinDivert exports stays loaded")
	}
	if dllLoaded || procOpen != nil {
		t.Fatal("failed load left state behind")
	}
}

// A closed handle never passes its value to WinDivert again: Windows may
// have given it to another handle since. The DLL is not loaded in tests,
// so a call reaching it would panic.
func TestClosedHandleUnused(t *testing.T) {
	h := &Handle{h: 0x2a4}
	h.closed.Store(true)
	buf := make([]byte, 64)
	addrs := make([]Address, 1)
	if _, _, err := h.RecvEx(buf, addrs); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("RecvEx: %v", err)
	}
	if _, err := h.Recv(buf, &addrs[0]); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("Recv: %v", err)
	}
	if err := h.Send(buf, &addrs[0]); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("Send: %v", err)
	}
	if err := h.Shutdown(ShutdownBoth); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := h.SetParam(ParamQueueLength, 1); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("SetParam: %v", err)
	}
	if _, err := h.GetParam(ParamVersionMajor); err != windows.ERROR_INVALID_HANDLE {
		t.Fatalf("GetParam: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
