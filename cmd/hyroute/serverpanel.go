package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/lardan099/hyroute/internal/attrib"
)

// HyRoute Server (docs/SERVER_MANAGER.md) ships in HyRoute's folder as
// hyroute-server.exe: the servers page starts it and opens its admin in
// the browser (serverpanel_windows.go).

// panelAddr is where HyRoute starts the panel: the panel's own default.
var panelAddr = netip.MustParseAddrPort("127.0.0.1:8480")

// panelSHA256 is the SHA-256 of the hyroute-server.exe built with this
// HyRoute (scripts/build.ps1: -X main.panelSHA256=…).
var panelSHA256 string

// checkPanelExe: the file at path is the hyroute-server.exe of this
// HyRoute (SHA-256 want). A build without the pin (go build by hand)
// takes the file as it is.
func checkPanelExe(path, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		return errors.New("hyroute-server.exe не от этой версии HyRoute (файл заменён или повреждён): скачайте архив HyRoute заново")
	}
	return nil
}

// panelHealthy reads the panel's GET /api/v1/health: its "ok", not just
// any program's answer on the port.
func panelHealthy(body io.Reader) bool {
	var h struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	return json.NewDecoder(body).Decode(&h) == nil && h.Status == "ok" && h.Version != ""
}

// panelListener is the process a connection to addr reaches: the one
// listening at addr itself, otherwise at a wildcard address on its port.
func panelListener(rows []attrib.TCPRow, addr netip.AddrPort) (uint32, bool) {
	var wild uint32
	found := false
	for _, r := range rows {
		if r.State != attrib.TCPStateListen || r.Local.Port() != addr.Port() {
			continue
		}
		switch {
		case r.Local.Addr() == addr.Addr():
			return r.PID, true
		case r.Local.Addr().IsUnspecified() && !found:
			wild, found = r.PID, true
		}
	}
	return wild, found
}

// panelURL is the admin's address. A setup code goes into the fragment,
// which the browser never sends: the page puts it into its form and wipes
// it from the address (web/admin: setupFromURL).
func panelURL(token string) string {
	u := "http://" + panelAddr.String() + "/"
	if validSetupToken(token) {
		u += "#setup=" + token
	}
	return u
}

// validSetupToken: the panel's codes are base64url (32 random bytes). The
// URL goes to the shell: nothing else may get into it.
func validSetupToken(s string) bool {
	if len(s) < 16 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// samePath compares Windows paths (case-insensitive).
func samePath(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
