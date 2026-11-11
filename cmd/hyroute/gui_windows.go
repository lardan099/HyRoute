//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/autostart"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/fwrule"
	"github.com/lardan099/hyroute/internal/uirpc"
	"github.com/lardan099/hyroute/internal/update"
)

// GUI serves the window: every exported method is callable from the page,
// which runs in the window process (window_windows.go) and reaches them
// through Bridge.Call, as Wails bound them before.
type GUI struct {
	ctl     *app.Controller
	dataDir string
	dllDir  string // the program folder (HyRoute.exe, updater target)
	// runtimeDir holds the verified hysteria.exe and WinDivert copies that
	// actually run (administrators-only folder).
	runtimeDir string
	// life ends when HyRoute exits (long calls of the page stop).
	life  context.Context
	win   *winHost
	panel *winHost // the panel by the tray icon (panel_windows.go)

	dispatchOnce sync.Once
	dispatchFn   uirpc.Handler

	core        *core.Manager
	updateEvent string // signal when up (after an update)
	notice      string // shown once at startup
	// After an update the new version is "healthy" when the window is up
	// (window.ready) and, with --reconnect, the filters are in place again.
	uiUp, connUp atomic.Bool

	tray     trayState
	quitting atomic.Bool // a real exit: the close button no longer hides
	updating atomic.Bool // ApplyAppUpdate started the updater: HyRoute is exiting
	quitOnce sync.Once
	quitCh   chan struct{} // closed by quit: main ends HyRoute

	cli *cliState // cli: the control pipe (ctl_windows.go)
}

// shutdown: HyRoute exits. An exit is never taken as the user's
// Disconnect: with the kill switch on the internet stays closed until
// HyRoute connects again or the user opens it.
func (g *GUI) shutdown() {
	g.panel.close()
	g.win.close()
	g.ctl.StopNetModes() // netmodes: no network rule acts during the exit
	g.ctl.Shutdown()
	g.quitTray()
}

// reconnectAfterUpdate restores the connection the old version had; the
// updater is told the update works only if the filters come up.
func (g *GUI) reconnectAfterUpdate() {
	if err := g.ctl.Connect(); err != nil {
		g.ctl.Log.Error("reconnect after update failed: the updater will restore the previous version", "err", err)
		return
	}
	g.connUp.Store(true)
	g.signalHealthy()
}

// noteConnected: after an update with --reconnect, any connect that
// brings the filters up shows the new version works, including the
// user's own after the automatic one failed.
func (g *GUI) noteConnected() {
	switch g.ctl.Status().State {
	case "connected", "connecting", "tunnel-down":
		g.connUp.Store(true)
		g.signalHealthy()
	}
}

var healthMu sync.Mutex

func (g *GUI) signalHealthy() {
	healthMu.Lock()
	defer healthMu.Unlock()
	if g.updateEvent == "" || !g.uiUp.Load() || !g.connUp.Load() {
		return
	}
	name, _ := windows.UTF16PtrFromString(g.updateEvent)
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		g.ctl.Log.Error("cannot signal the updater", "err", err)
		return
	}
	windows.SetEvent(h)
	windows.CloseHandle(h)
	g.updateEvent = ""
}

func (g *GUI) emitStatus() {
	g.win.notify("status")
	g.panel.notify("status")
	go g.updateTray()
	if !g.connUp.Load() {
		go g.noteConnected()
	}
}

// ---- status and connection ----

// ---- start with Windows ----

func (g *GUI) Autostart() AutostartInfo {
	exe, _ := os.Executable()
	in := AutostartInfo{Allowed: protectedLocation(g.dllDir)}
	cmd, err := autostart.Command()
	switch {
	case errors.Is(err, autostart.ErrNoTask):
	case err != nil:
		in.Error = err.Error()
	default:
		in.Enabled, in.Command = true, cmd
		in.Current = strings.EqualFold(filepath.Clean(cmd), filepath.Clean(exe))
	}
	return in
}

// SetAutostart creates or removes the sign-in task. The kill switch check
// follows: the autostart task makes it unneeded.
func (g *GUI) SetAutostart(on bool) error {
	defer func() { go g.syncKillSwitchCheck() }()
	if !on {
		if err := autostart.Disable(); err != nil {
			return err
		}
		g.ctl.Log.Info("start with Windows: off")
		return nil
	}
	if !protectedLocation(g.dllDir) {
		return errors.New("сначала перенесите HyRoute в Program Files, в папку, куда могут писать только администраторы (кнопка на главной): задача запускает программу с правами администратора, и файл, который может подменить любая программа, запускать так нельзя")
	}
	exe, _ := os.Executable()
	if err := autostart.Enable(exe); err != nil {
		return err
	}
	g.ctl.Log.Info("start with Windows: on", "exe", exe)
	return nil
}

// ---- profiles ----

// ---- subscriptions ----

// ---- rules and settings ----

func (g *GUI) BrowseExe() (string, error) {
	return g.win.openFile(runtime.OpenDialogOptions{
		Title:   "Выберите программу",
		Filters: []runtime.FileFilter{{DisplayName: "Программы (*.exe)", Pattern: "*.exe"}},
	})
}

// ---- connections and logs ----

func (g *GUI) OpenLogDir() error {
	dir := g.ctl.LogDir()
	if dir == "" {
		dir = filepath.Join(g.dataDir, "logs")
	}
	os.MkdirAll(dir, 0o700)
	return openFolder(dir)
}

// ---- checks and diagnostics ----

func (g *GUI) systemLines() []string {
	info := g.System()
	lines := []string{
		"Windows: " + windowsVersion(),
		"Папка программы: " + info.ProgramDir,
		"Данные: " + info.DataDir,
		"Драйвер: " + info.Driver,
	}
	if len(info.Legacy) > 0 {
		lines = append(lines, "WinDivert 1.x: "+strings.Join(info.Legacy, ", "))
	}
	if len(info.Missing) > 0 {
		lines = append(lines, "Нет файлов: "+strings.Join(info.Missing, ", "))
	}
	rule := "нет (создаётся при подключении)"
	if info.FirewallRuleOK {
		rule = "есть"
	}
	lines = append(lines, "Правило брандмауэра «"+info.FirewallRule+"»: "+rule)
	proxyRules := "нет"
	if len(info.ProxyRules) > 0 {
		proxyRules = strings.Join(info.ProxyRules, ", ")
	}
	lines = append(lines, "Правила брандмауэра для прокси: "+proxyRules)
	lines = append(lines, g.cliLine())     // cli
	lines = append(lines, g.browserLine()) // browser
	return lines
}

// ---- updates ----

// errUpdaterWaits: an updater already runs. It waits for HyRoute to exit
// and then installs the update, so exiting is all it takes.
var errUpdaterWaits = errors.New("обновление уже запущено и ждёт, пока HyRoute закроется. Выйдите из HyRoute (значок в трее → «Выход»): обновление установится само")

// updaterRunning reports whether a hyroute-updater holds its mutex (one
// an elevated process made: update.UpdaterRunning).
func updaterRunning() bool { return update.UpdaterRunning() }

// ApplyAppUpdate hands the verified package to hyroute-updater and exits:
// filters are removed and every Hysteria stops first. The updater waits
// for this process to end, swaps the files, starts the new version and
// rolls back if it does not come up.
func (g *GUI) ApplyAppUpdate() error {
	if g.updating.Load() {
		return errors.New("обновление уже устанавливается: HyRoute сейчас закроется")
	}
	if updaterRunning() {
		return errUpdaterWaits
	}
	dir, ver, err := g.ctl.ReadyUpdate()
	if err != nil {
		return err
	}
	m, err := update.Verify(dir)
	if err != nil {
		return err
	}
	runDir := filepath.Join(filepath.Dir(dir), "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	helper := filepath.Join(runDir, update.UpdaterExe)
	b, err := os.ReadFile(filepath.Join(dir, update.UpdaterExe))
	if err != nil {
		return err
	}
	if err := os.WriteFile(helper, b, 0o755); err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			// The copy runs: an updater of an earlier attempt (one from
			// before 1.3.21 holds no mutex) waits for HyRoute to exit.
			return errUpdaterWaits
		}
		return err
	}
	if sum, err := update.FileSHA256(helper); err != nil || !strings.EqualFold(sum, m.Files[update.UpdaterExe]) {
		return errors.New("копия программы обновления повреждена")
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	event := fmt.Sprintf(`Local\HyRouteUpdate-%x`, rnd)
	args := []string{"--pid", fmt.Sprint(os.Getpid()), "--staging", dir, "--target", g.dllDir,
		"--event", event, "--from", g.ctl.Version}
	// A renamed exe is replaced under its own name: shortcuts and the
	// sign-in task start it, and a rollback restarts it.
	if exe, err := os.Executable(); err == nil && !strings.EqualFold(filepath.Base(exe), update.MainExe) {
		args = append(args, "--exe", filepath.Base(exe))
	}
	// netmodes: no network rule acts between this decision and the exit.
	g.ctl.StopNetModes()
	// cli: no connect (hyroutectl, tray, networks) between this check and
	// the exit.
	undo := g.ctl.BeginExit()
	if routingOn(g.ctl.Status()) {
		// The new version reconnects and reports healthy only once the
		// driver and filters are up again.
		args = append(args, "--reconnect")
	}
	cmd := exec.Command(helper, args...)
	if err := cmd.Start(); err != nil {
		undo()
		g.ctl.ResumeNetModes()
		return fmt.Errorf("программа обновления не запустилась: %w", err)
	}
	g.updating.Store(true)
	g.ctl.Log.Info("installing update: HyRoute exits, hyroute-updater replaces the files", "to", ver)
	// The kill switch keeps the internet closed until the new version
	// reconnects (or the user unblocks it there).
	g.ctl.HoldKillSwitch()
	g.ctl.Disconnect()
	go func() {
		time.Sleep(200 * time.Millisecond)
		g.quit()
	}()
	return nil
}

// ---- system ----

func (g *GUI) System() SystemInfo {
	info := SystemInfo{Build: build, DataDir: g.dataDir, ProgramDir: g.dllDir, FirewallRule: fwrule.Name, Legacy: []string{}, Missing: []string{},
		ProtectedLocation: protectedLocation(g.dllDir), RuntimeDir: g.runtimeDir, MoveTarget: moveTarget()}
	for _, f := range runtimeFilesList {
		if _, err := os.Stat(filepath.Join(g.runtimeDir, f)); err != nil {
			info.Missing = append(info.Missing, f)
		}
	}
	// Each check runs netsh: side by side, the page waits for one.
	proxyRules := make(chan []string, 1)
	go func() { proxyRules <- fwrule.ProxyRules() }()
	info.FirewallRuleOK = fwrule.Exists()
	info.ProxyRules = <-proxyRules
	info.Hysteria, info.HysteriaPath = g.coreVersion(), g.ctl.Base.HysteriaPath()
	d, err := divert.InspectDriver(filepath.Join(g.runtimeDir, "WinDivert64.sys"))
	switch {
	case err != nil:
		info.Driver = "не удалось проверить: " + err.Error()
	case !d.Exists:
		info.Driver = "служба WinDivert не установлена (появится при подключении)"
	case d.Ours:
		info.Driver = "служба WinDivert: наш драйвер, " + state(d.Running)
	default:
		info.Driver = fmt.Sprintf("служба WinDivert принадлежит другой программе (%s), %s", d.ImagePath, state(d.Running))
		if _, err := os.Stat(d.ImagePath); err != nil && !d.Running {
			info.DriverStale = true
			info.Driver += "; файл драйвера не найден — служба устарела"
		}
	}
	if d != nil && d.Legacy != nil {
		info.Legacy = d.Legacy
	}
	return info
}

func state(running bool) string {
	if running {
		return "запущена"
	}
	return "остановлена"
}

func (g *GUI) RemoveFirewallRule() error {
	if g.ctl.Status().State != "disconnected" && g.ctl.Status().State != "error" {
		return errors.New("сначала отключитесь: правило нужно, пока фильтры активны")
	}
	return fwrule.Remove()
}

func (g *GUI) DeleteStaleDriverService() error { return divert.DeleteStaleService() }

func (g *GUI) OpenDataDir() error { return openFolder(g.dataDir) }

func windowsVersion() string {
	maj, min, b := windows.RtlGetNtVersionNumbers()
	return fmt.Sprintf("%d.%d.%d", maj, min, b)
}

// Platform tells the page which system it runs on (macos: the page hides
// what only Windows has).
func (g *GUI) Platform() string { return "windows" }
