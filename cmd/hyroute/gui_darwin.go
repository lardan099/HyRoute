//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/uirpc"
	"github.com/lardan099/hyroute/internal/update"
)

// GUI serves the windows connected to the service (hub_darwin.go): every
// exported method is callable from the page, as on Windows.
type GUI struct {
	ctl     *app.Controller
	dataDir string
	// binDir holds the service's own copies of HyRoute, hysteria and xray
	// (root's, installed with the service).
	binDir string
	life   context.Context
	win    *winHost
	core   *core.Manager

	dispatchOnce sync.Once
	dispatchFn   uirpc.Handler

	notice   string
	quitOnce sync.Once
	quitCh   chan struct{}

	cli cliState // hyroutectl's socket (cli_darwin.go)
}

func (g *GUI) emitStatus() { g.win.notify("status") }

func (g *GUI) showWindow() { g.win.open("normal") }

func (g *GUI) quit() { g.quitOnce.Do(func() { close(g.quitCh) }) }

// The kill switch check at sign-in is Windows' (the service starts with
// the Mac).
func (g *GUI) syncKillSwitchCheck() {}

var errMac = errors.New("на macOS этого пока нет")

// ---- start with the Mac: the service always runs (launchd) ----

func (g *GUI) Autostart() AutostartInfo {
	return AutostartInfo{Enabled: true, Allowed: true, Current: true, Command: filepath.Join(g.binDir, "HyRoute")}
}

func (g *GUI) SetAutostart(on bool) error {
	if !on {
		return errors.New("служба HyRoute запускается вместе с Mac всегда; подключение при запуске включается в «Настройках»")
	}
	return nil
}

func (g *GUI) BrowseExe() (string, error) {
	// No filter: Wails turns "*.app" into a file type that bundles, being
	// folders, never match, and every program is greyed out. Bundles are
	// picked as files (packages are not opened as folders); what was
	// picked is checked here.
	p, err := g.win.openFile(runtime.OpenDialogOptions{
		Title:                      "Выберите программу",
		DefaultDirectory:           "/Applications",
		TreatPackagesAsDirectories: false,
	})
	if err != nil || p == "" {
		return p, err
	}
	if !isProgram(p) {
		return "", errors.New("это не программа: выберите программу (.app) или исполняемый файл")
	}
	return appExecutable(p), nil
}

// isProgram: an application bundle or an executable file.
func isProgram(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return strings.HasSuffix(p, ".app")
	}
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// appExecutable is the program a .app bundle starts
// (Contents/Info.plist CFBundleExecutable): rules match its name.
func appExecutable(p string) string {
	if !strings.HasSuffix(p, ".app") {
		return p
	}
	out, err := exec.Command("/usr/bin/defaults", "read", filepath.Join(p, "Contents", "Info"), "CFBundleExecutable").Output()
	if name := strings.TrimSpace(string(out)); err == nil && name != "" && !strings.ContainsAny(name, "/\x00") {
		return filepath.Join(p, "Contents", "MacOS", name)
	}
	return p
}

func (g *GUI) OpenLogDir() error {
	dir := g.ctl.LogDir()
	if dir == "" {
		dir = filepath.Join(g.dataDir, "logs")
	}
	return errors.New("логи HyRoute лежат в " + dir + " (папка администратора: откройте её в Терминале через sudo)")
}

func (g *GUI) OpenDataDir() error {
	return errors.New("данные HyRoute лежат в " + g.dataDir + " (папка администратора)")
}

// OpenTelegramProxy opens the tg://proxy link of «Telegram без VPN».
func (g *GUI) OpenTelegramProxy() error {
	u := g.ctl.TelegramLink()
	if u == "" {
		return errors.New("прокси для Telegram не запущен")
	}
	return g.win.openPath(u)
}

func (g *GUI) OpenSubscriptionSupport(id string) error {
	u, err := g.ctl.SupportLink(id)
	if err != nil {
		return err
	}
	return g.win.openPath(u)
}

// reconnectMarker in the data folder tells the next service to connect
// (it was connected before an update).
const reconnectMarker = "reconnect-after-update"

// ApplyAppUpdate installs the verified package: the service's files from
// the new bundle, the bundle itself over the app the window runs from,
// then the service exits and launchd starts the new one. The windows and
// the menu bar icon start their new versions.
func (g *GUI) ApplyAppUpdate() error {
	dir, ver, err := g.ctl.ReadyUpdate()
	if err != nil {
		return err
	}
	bundle := filepath.Join(dir, update.AppBundle)
	exe := filepath.Join(bundle, "Contents", "MacOS", "HyRoute")
	if err := installFiles(exe, filepath.Join(bundle, "Contents", "Resources")); err != nil {
		return fmt.Errorf("файлы службы не обновлены: %w", err)
	}
	// A copy everyone can read: the window replaces its app from it when
	// the service cannot, and an older app opened later updates itself.
	staged := ""
	if err := stageAppCopy(bundle); err != nil {
		g.ctl.Log.Warn("HyRoute.app copy for the window not made", "err", err)
	} else {
		staged = filepath.Join(appStageDir, update.AppBundle)
	}
	target := g.win.appPath()
	if target != "" {
		// From macOS 13 only the app itself may change its bundle
		// («Управление приложениями»), not the service, root as it is.
		if err := replaceBundle(bundle, target); err != nil {
			g.ctl.Log.Info("HyRoute.app not replaced by the service: the window replaces it", "app", target, "err", err)
		} else {
			staged = "" // done
		}
	}
	g.ctl.StopNetModes()
	g.ctl.BeginExit() // no connect from here to the exit
	if routingOn(g.ctl.Status()) {
		os.WriteFile(filepath.Join(g.dataDir, reconnectMarker), nil, 0o600)
	}
	g.ctl.Log.Info("installing update: the service restarts with the new version", "to", ver)
	g.ctl.HoldKillSwitch()
	g.ctl.Disconnect()
	g.win.notify("service.updated", target, staged)
	go func() {
		time.Sleep(500 * time.Millisecond)
		g.quit() // launchd starts the new service (KeepAlive)
	}()
	return nil
}

// stageAppCopy copies the verified bundle to appStageDir, readable by
// everyone, writable by root only.
func stageAppCopy(bundle string) error {
	os.RemoveAll(appStageDir)
	if err := os.MkdirAll(appStageDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(appStageDir, update.AppBundle)
	if out, err := exec.Command("/usr/bin/ditto", bundle, dst).CombinedOutput(); err != nil {
		os.RemoveAll(appStageDir)
		return fmt.Errorf("ditto: %v: %s", err, strings.TrimSpace(string(out)))
	}
	exec.Command("/usr/sbin/chown", "-R", "0:0", appStageDir).Run()
	exec.Command("/bin/chmod", "-R", "go-w,a+rX", appStageDir).Run()
	return nil
}

// dropStaleAppCopy removes a copy of another version than the service's.
func dropStaleAppCopy() {
	if m, err := update.VerifyApp(appStageDir); err != nil || release.Compare(m.Version, version) != 0 {
		os.RemoveAll(appStageDir)
	}
}

// replaceBundle puts the new HyRoute.app in the place of the one at
// target (a HyRoute.app the window ran from): copied beside it first, then
// swapped, the old one removed.
func replaceBundle(src, target string) error {
	if filepath.Base(target) != update.AppBundle || !filepath.IsAbs(target) {
		return errors.New("не HyRoute.app")
	}
	if fi, err := os.Lstat(target); err != nil || !fi.IsDir() {
		return errors.New("HyRoute.app не найден")
	}
	tmp, old := target+".new", target+".old"
	os.RemoveAll(tmp)
	os.RemoveAll(old)
	if out, err := exec.Command("/usr/bin/ditto", src, tmp).CombinedOutput(); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("ditto: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// The app stays its user's, as the user put it there.
	if fi, err := os.Stat(target); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			exec.Command("/usr/sbin/chown", "-R", fmt.Sprintf("%d:%d", st.Uid, st.Gid), tmp).Run()
		}
	}
	if err := os.Rename(target, old); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Rename(old, target)
		return err
	}
	os.RemoveAll(old)
	return nil
}

func (g *GUI) System() SystemInfo {
	info := SystemInfo{Build: build, DataDir: g.dataDir, ProgramDir: g.binDir, RuntimeDir: g.binDir,
		Legacy: []string{}, Missing: []string{}, ProxyRules: []string{}, ProtectedLocation: true,
		Driver: "utun (встроен в macOS)", FirewallRuleOK: true}
	for _, f := range []string{"hysteria", "xray"} {
		if _, err := os.Stat(filepath.Join(g.binDir, f)); err != nil {
			info.Missing = append(info.Missing, f)
		}
	}
	info.Hysteria, info.HysteriaPath = g.coreVersion(), g.ctl.Base.HysteriaPath()
	return info
}

func (g *GUI) systemLines() []string {
	info := g.System()
	lines := []string{
		"macOS: " + macVersion(),
		"Служба: " + info.ProgramDir,
		"Данные: " + info.DataDir,
		g.cliLine(),
		g.browserLine(),
	}
	if len(info.Missing) > 0 {
		lines = append(lines, "Нет файлов: "+strings.Join(info.Missing, ", "))
	}
	return lines
}

func macVersion() string {
	out, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(out))
}

func (g *GUI) RemoveFirewallRule() error       { return errMac }
func (g *GUI) DeleteStaleDriverService() error { return errMac }
func (g *GUI) MoveToProgramFiles() error       { return errMac }
func (g *GUI) OpenServerPanel() error {
	return errors.New("панель серверов (hyroute-server) запускается на Windows или Linux")
}

// ServiceVersion lets the window see whether the service is its own
// version (else it installs its copy).
func (g *GUI) ServiceVersion() string { return version + " " + build }

// Platform tells the page which system it runs on.
func (g *GUI) Platform() string { return "macos" }

// The panel by the tray icon is the Windows tray's (panel_windows.go): the
// menu bar icon has its menu.
func (g *GUI) PanelOpenWindow() {}
func (g *GUI) PanelQuit()       {}
