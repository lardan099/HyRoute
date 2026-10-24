//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/attrib"
)

// panelWait is how long OpenServerPanel waits for a panel it started.
const panelWait = 20 * time.Second

// OpenServerPanel starts HyRoute Server unless it already answers, and
// opens its admin in the default browser, with the setup code while the
// panel has no owner. The panel runs with the user's normal rights, as the
// browser does: it needs no more, and the program folder may be the
// user's to write (runtimefiles: what runs elevated is checked first). It
// gets a minimized console window of its own; closing it stops the panel.
func (g *GUI) OpenServerPanel() error {
	exe := filepath.Join(g.dllDir, "hyroute-server.exe")
	ctx, cancel := context.WithTimeout(g.life, panelWait)
	defer cancel()
	if !panelUp(ctx) {
		if _, err := os.Stat(exe); err != nil {
			return errors.New("в папке HyRoute нет hyroute-server.exe: панель входит в архив HyRoute начиная с версии 1.3.7")
		}
		if err := checkPanelExe(exe, panelSHA256); err != nil {
			return err
		}
		if panelSHA256 != "" {
			// Unpacked by Explorer from a downloaded zip, the file has the
			// mark of the web, and the shell would stop it at SmartScreen
			// while HyRoute waits. It is checked above to be the panel
			// built with this HyRoute, which the user already runs: the
			// mark goes, as Unblock-File would remove it.
			os.Remove(exe + ":Zone.Identifier")
		}
		if err := shellExecuteShow(exe, "-listen "+panelAddr.String(), swShowMinNoActive); err != nil {
			return fmt.Errorf("панель не запустилась: %w", err)
		}
		g.ctl.Log.Info("server panel started", "exe", exe)
		for !panelUp(ctx) {
			select {
			case <-ctx.Done():
				return errors.New("панель не ответила за 20 секунд. Почему — написано в её окне «HyRoute Server» на панели задач")
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	return shellExecuteInExplorer(panelURL(panelSetupToken(exe)))
}

var panelClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// panelUp: HyRoute Server answers at panelAddr.
func panelUp(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+panelAddr.String()+"/api/v1/health", nil)
	if err != nil {
		return false
	}
	resp, err := panelClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && panelHealthy(io.LimitReader(resp.Body, 4096))
}

// panelSetupToken is the panel's setup code (its data directory's
// setup-token, there while it has no owner), only when the program on
// panelAddr is exe, the panel this HyRoute ships: another user's program
// that took the port first gets no code.
func panelSetupToken(exe string) string {
	rows, _ := attrib.ReadTCPTable()
	pid, ok := panelListener(rows, panelAddr)
	if !ok || !samePath(processImage(pid), exe) {
		return ""
	}
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(dir, "HyRoute Server", "setup-token"))
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 256))
	return strings.TrimSpace(string(b))
}

// processImage is the full path of process pid's exe ("" if unknown).
func processImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
