package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/attrib"
)

func TestPanelHealthy(t *testing.T) {
	for body, want := range map[string]bool{
		`{"status":"ok","version":"v1.3.7","schemaVersion":27}`: true,
		`{"status":"ok"}`:                      false,
		`{"status":"down","version":"v1.3.7"}`: false,
		`<html>another program</html>`:         false,
		``:                                     false,
	} {
		if got := panelHealthy(strings.NewReader(body)); got != want {
			t.Errorf("%q: %v, want %v", body, got, want)
		}
	}
}

func TestPanelListener(t *testing.T) {
	ap := netip.MustParseAddrPort
	listen := func(addr string, pid uint32) attrib.TCPRow {
		return attrib.TCPRow{Local: ap(addr), State: attrib.TCPStateListen, PID: pid}
	}
	conn := attrib.TCPRow{Local: ap("127.0.0.1:8480"), Remote: ap("127.0.0.1:50000"), State: 5, PID: 9}
	cases := []struct {
		rows []attrib.TCPRow
		pid  uint32
		ok   bool
	}{
		{nil, 0, false},
		{[]attrib.TCPRow{conn, listen("127.0.0.1:8481", 2)}, 0, false},
		{[]attrib.TCPRow{listen("127.0.0.2:8480", 2)}, 0, false},
		{[]attrib.TCPRow{listen("127.0.0.1:8480", 3)}, 3, true},
		{[]attrib.TCPRow{listen("0.0.0.0:8480", 4)}, 4, true},
		// The exact address takes the connection, not the wildcard.
		{[]attrib.TCPRow{listen("0.0.0.0:8480", 4), listen("127.0.0.1:8480", 3)}, 3, true},
	}
	for i, c := range cases {
		pid, ok := panelListener(c.rows, panelAddr)
		if pid != c.pid || ok != c.ok {
			t.Errorf("case %d: %d %v, want %d %v", i, pid, ok, c.pid, c.ok)
		}
	}
}

func TestPanelURL(t *testing.T) {
	tok := "Abc-def_0123456789xyzXYZ-_abcdefghijklmnopq"
	if got := panelURL(tok); got != "http://127.0.0.1:8480/#setup="+tok {
		t.Errorf("with a code: %s", got)
	}
	for _, bad := range []string{"", "short", tok + `" /x`, tok + "&a=b", strings.Repeat("a", 129), "абвгдеёжзийклмнопрст"} {
		if got := panelURL(bad); got != "http://127.0.0.1:8480/" {
			t.Errorf("%q: %s", bad, got)
		}
	}
}

func TestSamePath(t *testing.T) {
	if !samePath(`C:\HyRoute\hyroute-server.exe`, `c:\hyroute\HYROUTE-SERVER.EXE`) {
		t.Error("paths that differ in case only")
	}
	if samePath("", "") || samePath(`C:\a.exe`, "") || samePath(`C:\a.exe`, `C:\b.exe`) {
		t.Error("different paths are the same")
	}
}

func TestCheckPanelExe(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "hyroute-server.exe")
	os.WriteFile(exe, []byte("panel"), 0o600)
	sum := sha256.Sum256([]byte("panel"))
	own := hex.EncodeToString(sum[:])
	if err := checkPanelExe(exe, ""); err != nil {
		t.Errorf("without a pin: %v", err)
	}
	if err := checkPanelExe(exe, strings.ToUpper(own)); err != nil {
		t.Errorf("its own hash: %v", err)
	}
	if err := checkPanelExe(exe, strings.Repeat("0", 64)); err == nil {
		t.Error("another file passed")
	}
	if err := checkPanelExe(filepath.Join(t.TempDir(), "none.exe"), own); err == nil {
		t.Error("a missing file passed")
	}
}
