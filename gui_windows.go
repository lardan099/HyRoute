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

	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/autostart"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/fwrule"
	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/update"
)

// GUI is bound to the frontend: every exported method is callable from JS
// as window.go.main.GUI.<Method>.
type GUI struct {
	ctl     *app.Controller
	dataDir string
	dllDir  string // the program folder (HyRoute.exe, updater target)
	// runtimeDir holds the verified hysteria.exe and WinDivert copies that
	// actually run (administrators-only folder).
	runtimeDir string
	ctx        atomic.Pointer[context.Context]

	core        *core.Manager
	updateEvent string // signal when up (after an update)
	notice      string // shown once at startup
	// After an update the new version is "healthy" when the window is up
	// and, with --reconnect, the filters are in place again.
	uiUp, connUp atomic.Bool

	tray     trayState
	quitting atomic.Bool // a real exit: the close button no longer hides

	backupMu sync.Mutex
	backup   []byte // the backup file ChooseBackup read, for RestoreBackup
}

func (g *GUI) startup(ctx context.Context) {
	g.ctx.Store(&ctx)
	g.startTray()
}

// shutdown: the window closed. Windows closes it the same way for "End
// task" in Task Manager as for the close button, so an exit is never taken
// as the user's Disconnect: with the kill switch on the internet stays
// closed until HyRoute connects again or the user opens it.
func (g *GUI) shutdown(context.Context) {
	g.ctl.Shutdown()
	g.quitTray()
}

// domReady: the window works. After an update this tells hyroute-updater
// that the new version is healthy (otherwise it rolls back).
func (g *GUI) domReady(context.Context) {
	g.uiUp.Store(true)
	g.signalHealthy()
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

// routingOn: the user connected and did not disconnect, so a restart of
// HyRoute (an update, a move) connects again. A session whose engine
// failed ("error" with stats) counts: HyRoute was reconnecting it.
func routingOn(st app.Status) bool {
	return st.State != "disconnected" && (st.State != "error" || st.Stats != nil)
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

// StartupNotice is a one-time message (update result).
func (g *GUI) StartupNotice() string {
	n := g.notice
	g.notice = ""
	return n
}

func (g *GUI) context() context.Context {
	if p := g.ctx.Load(); p != nil {
		return *p
	}
	return nil
}

func (g *GUI) secondInstance(options.SecondInstanceData) { g.showWindow() }

func (g *GUI) emitStatus() {
	if ctx := g.context(); ctx != nil {
		runtime.EventsEmit(ctx, "status")
	}
	go g.updateTray()
	if !g.connUp.Load() {
		go g.noteConnected()
	}
}

// emitSettings tells the pages that the settings changed (revision rev).
func (g *GUI) emitSettings(rev uint64) {
	if ctx := g.context(); ctx != nil {
		runtime.EventsEmit(ctx, "settings", rev)
	}
}

// ---- status and connection ----

func (g *GUI) Status() app.Status { return g.ctl.Status() }
func (g *GUI) Connect() error     { return g.ctl.Connect() }
func (g *GUI) Disconnect()        { g.ctl.Disconnect() }
func (g *GUI) Reconnect() error   { return g.ctl.Reconnect() }

// autoConnect turns routing on at start ("Подключаться при запуске").
func (g *GUI) autoConnect() {
	g.connectAtStart("connecting at start (setting \"connect when HyRoute starts\")")
}

// reconnectAfterRollback: an update was rolled back and HyRoute was
// connected before it, so this (previous) version connects again,
// whatever "Подключаться при запуске" says.
func (g *GUI) reconnectAfterRollback() {
	g.connectAtStart("connecting again: the update was rolled back, HyRoute was connected before it")
}

func (g *GUI) connectAtStart(why string) {
	if len(g.ctl.Profiles()) == 0 {
		return
	}
	// The default rules send everything direct: not what the user set.
	if err := g.ctl.SettingsError(); err != nil {
		g.ctl.Log.Error("not connecting at start: settings.json did not load, the rules would be the defaults", "err", err)
		return
	}
	g.ctl.Log.Info(why)
	if err := g.ctl.Connect(); err != nil {
		g.ctl.Log.Error("connect at start failed", "err", err)
	}
}

// ---- start with Windows ----

type AutostartInfo struct {
	Enabled bool `json:"enabled"`
	// Command is the exe the task starts; Current: it is this copy.
	Command string `json:"command"`
	Current bool   `json:"current"`
	// Allowed: this copy is in Program Files, in a folder only
	// administrators can write to (a task starting a program from a
	// folder anyone can write to would hand out admin rights).
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

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

// ReleaseKillSwitch opens the internet the kill switch closed.
func (g *GUI) ReleaseKillSwitch() error { return g.ctl.ReleaseKillSwitch() }

// ---- profiles ----

func (g *GUI) Profiles() []app.ProfileSummary { return g.ctl.Profiles() }
func (g *GUI) Profile(id string) (hysteria.Profile, error) {
	return g.ctl.Profile(id)
}
func (g *GUI) ImportURIs(text string) (app.ImportResult, error) { return g.ctl.ImportURIs(text) }

// ImportClipboard imports links from the clipboard.
func (g *GUI) ImportClipboard() (app.ImportResult, error) {
	text, err := runtime.ClipboardGetText(g.context())
	if err != nil {
		return app.ImportResult{}, err
	}
	return g.ctl.ImportURIs(text)
}

// ClipboardText reads the clipboard for the setup's «Вставить из буфера»,
// which takes a server link or a subscription link alike.
func (g *GUI) ClipboardText() (string, error) {
	return runtime.ClipboardGetText(g.context())
}

func (g *GUI) SaveProfile(p hysteria.Profile) (app.ProfileSummary, error) {
	return g.ctl.SaveProfile(p)
}
func (g *GUI) DeleteProfile(id string) error       { return g.ctl.DeleteProfile(id) }
func (g *GUI) SetMain(id string) error             { return g.ctl.SetMain(id) }
func (g *GUI) MoveProfile(id string, to int) error { return g.ctl.MoveProfile(id, to) }

// CopyURI puts the profile's share link (with secrets) on the clipboard.
func (g *GUI) CopyURI(id string) error {
	uri, err := g.ctl.ExportURI(id)
	if err != nil {
		return err
	}
	return runtime.ClipboardSetText(g.context(), uri)
}

// ---- subscriptions ----

func (g *GUI) Subscriptions() []app.SubView { return g.ctl.Subscriptions() }
func (g *GUI) PreviewSubscription(url string) (app.Preview, error) {
	return g.ctl.PreviewSubscription(url)
}
func (g *GUI) AddSubscription(in app.SubInput) (app.SubView, error) { return g.ctl.AddSubscription(in) }
func (g *GUI) EditSubscription(in app.SubInput) error               { return g.ctl.EditSubscription(in) }
func (g *GUI) UpdateSubscription(id string) (app.MergeStats, error) {
	return g.ctl.UpdateSubscription(id)
}
func (g *GUI) RollbackSubscription(id string) (app.MergeStats, error) {
	return g.ctl.RollbackSubscription(id)
}
func (g *GUI) DeleteSubscription(id string) error { return g.ctl.DeleteSubscription(id) }

// CopyText puts text on the clipboard (navigator.clipboard is not
// reliable in the WebView).
func (g *GUI) CopyText(text string) error { return runtime.ClipboardSetText(g.context(), text) }

// ---- rules and settings ----

// Settings is a page's copy of the settings with the revision its saves
// send back (SaveSettings refuses a stale one).
func (g *GUI) Settings() app.SettingsView      { return g.ctl.SettingsView() }
func (g *GUI) RuleWarnings() []app.RuleWarning { return g.ctl.RuleWarnings() }

// Rules as text (many at once): of the rule profile the page shows (its
// token; "" = the active one).
func (g *GUI) RulesText(ruleset string) (app.RulesTextView, error) {
	return g.ctl.RulesTextFor(ruleset)
}
func (g *GUI) ParseRulesText(text string) app.RulesTextResult { return g.ctl.ParseRulesText(text) }
func (g *GUI) ApplyRulesText(text string, replace bool, guard app.EditGuard) (app.RulesTextResult, error) {
	_, res, err := g.ctl.ApplyRulesText(text, replace, guard)
	return res, err
}

func (g *GUI) LintRules(s settings.Settings) []rules.Issue {
	return g.ctl.LintRules(s)
}
func (g *GUI) Explain(q app.ExplainQuery, s *settings.Settings) app.Explanation {
	return g.ctl.Explain(q, s)
}

// SaveSettings saves the rules part of v; the engine options of the page's
// copy are ignored (SaveEngineOptions saves them).
func (g *GUI) SaveSettings(v app.SettingsView) (app.SaveResult, error) {
	return g.ctl.SaveRulesIn(app.EditGuard{Ruleset: v.Ruleset, Rev: v.Rev, EditRev: v.EditRev}, v.Config)
}

// SaveEngineOptions saves the engine options («Настройки»); the rules
// stay as they are.
func (g *GUI) SaveEngineOptions(o settings.EngineOptions) (app.SaveResult, error) {
	cur := g.ctl.Settings()
	was := cur.KillSwitchOn()
	res, err := g.ctl.SaveEngineOptions(o)
	var next settings.Settings
	next.SetOptions(o)
	if err == nil && next.KillSwitchOn() != was {
		go g.syncKillSwitchCheck()
	}
	return res, err
}

// BrowseExe picks an executable for an app rule.
// Local proxies (see app/proxies.go).
func (g *GUI) Proxies() []app.ProxyView { return g.ctl.Proxies() }
func (g *GUI) SaveProxy(p app.ProxyInput) (app.ProxyView, error) {
	return g.ctl.SaveProxy(p)
}
func (g *GUI) DeleteProxy(id string) error { return g.ctl.DeleteProxy(id) }

// RunningApps suggests running programs for a rule (see app.RunningApps).
func (g *GUI) RunningApps(query string, all bool, limit int) []procinfo.Running {
	return g.ctl.RunningApps(query, all, limit)
}

func (g *GUI) BrowseExe() (string, error) {
	return runtime.OpenFileDialog(g.context(), runtime.OpenDialogOptions{
		Title:   "Выберите программу",
		Filters: []runtime.FileFilter{{DisplayName: "Программы (*.exe)", Pattern: "*.exe"}},
	})
}

// ---- connections and logs ----

func (g *GUI) Connections(limit int) app.Connections { return g.ctl.Connections(limit) }

func (g *GUI) Logs(kind string, after uint64) []logx.Entry { return g.ctl.Logs(kind, after) }

// SaveLog writes a log to a file chosen by the user; sanitized applies
// Privacy mode (secrets are redacted in both variants).
func (g *GUI) SaveLog(kind string, sanitized bool) (string, error) {
	suffix := ""
	if sanitized {
		suffix = "-sanitized"
	}
	name := fmt.Sprintf("hyroute-%s%s-%s.log", strings.ReplaceAll(kind, ":", "-"), suffix, time.Now().Format("20060102-150405"))
	path, err := runtime.SaveFileDialog(g.context(), runtime.SaveDialogOptions{
		DefaultFilename: name,
		Filters:         []runtime.FileFilter{{DisplayName: "Лог (*.log)", Pattern: "*.log"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, []byte(g.ctl.ExportLog(kind, sanitized)), 0o600)
}

// Sanitize applies Privacy mode to text the UI copies.
func (g *GUI) Sanitize(text string) string { return g.ctl.Sanitize(text) }

func (g *GUI) ClearLogs() error { return g.ctl.ClearLogs() }

func (g *GUI) OpenLogDir() error {
	dir := g.ctl.LogDir()
	if dir == "" {
		dir = filepath.Join(g.dataDir, "logs")
	}
	os.MkdirAll(dir, 0o700)
	return openFolder(dir)
}

func (g *GUI) Prefs() store.Prefs { return g.ctl.Prefs() }

// SavePrefs keeps the fields other calls own: the rule-database ones
// (SetGeoPrefs) and the postponed version (SkipAppVersion, "Позже"). The
// settings page may hold an older copy.
func (g *GUI) SavePrefs(p store.Prefs) error {
	cur := g.ctl.Prefs()
	p.GeoSource, p.GeoSiteURL, p.GeoIPURL, p.GeoAutoOff, p.GeoIntervalHours = cur.GeoSource, cur.GeoSiteURL, cur.GeoIPURL, cur.GeoAutoOff, cur.GeoIntervalHours
	p.SkipVersion = cur.SkipVersion
	return g.ctl.SavePrefs(p)
}

// ---- checks and diagnostics ----

func (g *GUI) CheckProfile(id string) (app.CheckResult, error) { return g.ctl.CheckProfile(id) }

// Diagnostics is the support report (Privacy mode when privacy).
func (g *GUI) Diagnostics(privacy bool) string {
	return g.ctl.Diagnostics(g.systemLines(), privacy)
}

func (g *GUI) CopyDiagnostics(privacy bool) error {
	return runtime.ClipboardSetText(g.context(), g.Diagnostics(privacy))
}

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
	return lines
}

// ---- updates ----

func (g *GUI) Updates() app.UpdatesState      { return g.ctl.Updates() }
func (g *GUI) CheckUpdates() app.UpdatesState { return g.ctl.CheckUpdates() }

// Rule databases (geosite/geoip).
func (g *GUI) GeoInfo() app.GeoInfo { return g.ctl.GeoInfo() }
func (g *GUI) UpdateGeo(force bool) (geodata.Result, error) {
	return g.ctl.UpdateGeo(g.context(), force)
}
func (g *GUI) RollbackGeo() error { return g.ctl.RollbackGeo() }
func (g *GUI) SetGeoPrefs(source, siteURL, ipURL string, auto bool, hours int) error {
	return g.ctl.SetGeoPrefs(source, siteURL, ipURL, auto, hours)
}

// List inspector: which geosite/geoip lists contain a site or IP.
func (g *GUI) Inspect(query string) (app.InspectResult, error) { return g.ctl.Inspect(query) }
func (g *GUI) SiteLists(domain string) []app.InspectHit        { return g.ctl.SiteLists(domain) }
func (g *GUI) GeoList(kind, name, filter string, offset, limit int) (geodata.Listing, error) {
	return g.ctl.GeoList(kind, name, filter, offset, limit)
}
func (g *GUI) ConvertACL(text, mode, suffix, actions string) (app.ConvertResult, error) {
	return g.ctl.ConvertACL(text, mode, suffix, actions)
}
func (g *GUI) GeoCategories(kind, query string) []string {
	return g.ctl.GeoCategories(kind, query, 40)
}
func (g *GUI) InstallCore() error            { return g.ctl.InstallCore() }
func (g *GUI) RollbackCore() error           { return g.ctl.RollbackCore() }
func (g *GUI) DownloadAppUpdate() error      { return g.ctl.DownloadAppUpdate() }
func (g *GUI) SkipAppVersion(v string) error { return g.ctl.SkipAppVersion(v) }

// ApplyAppUpdate hands the verified package to hyroute-updater and exits:
// filters are removed and every Hysteria stops first. The updater waits
// for this process to end, swaps the files, starts the new version and
// rolls back if it does not come up.
func (g *GUI) ApplyAppUpdate() error {
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
	if routingOn(g.ctl.Status()) {
		// The new version reconnects and reports healthy only once the
		// driver and filters are up again.
		args = append(args, "--reconnect")
	}
	cmd := exec.Command(helper, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("программа обновления не запустилась: %w", err)
	}
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

type SystemInfo struct {
	Build        string   `json:"build"`
	DataDir      string   `json:"dataDir"`
	ProgramDir   string   `json:"programDir"`
	FirewallRule string   `json:"firewallRule"`
	Driver       string   `json:"driver"`
	DriverStale  bool     `json:"driverStale"`
	Legacy       []string `json:"legacy"`
	Missing      []string `json:"missing"`
	// FirewallRuleOK: the rule exists.
	FirewallRuleOK bool   `json:"firewallRuleOK"`
	Hysteria       string `json:"hysteria"` // core version
	HysteriaPath   string `json:"hysteriaPath"`
	// ProtectedLocation: the program folder is under Program Files and
	// ordinary programs cannot write to it (cannot replace HyRoute.exe).
	ProtectedLocation bool   `json:"protectedLocation"`
	RuntimeDir        string `json:"runtimeDir"`
	MoveTarget        string `json:"moveTarget"`
}

func (g *GUI) System() SystemInfo {
	info := SystemInfo{Build: build, DataDir: g.dataDir, ProgramDir: g.dllDir, FirewallRule: fwrule.Name, Legacy: []string{}, Missing: []string{},
		ProtectedLocation: protectedLocation(g.dllDir), RuntimeDir: g.runtimeDir, MoveTarget: moveTarget()}
	for _, f := range []string{"hysteria.exe", "WinDivert.dll", "WinDivert64.sys"} {
		if _, err := os.Stat(filepath.Join(g.runtimeDir, f)); err != nil {
			info.Missing = append(info.Missing, f)
		}
	}
	info.FirewallRuleOK = fwrule.Exists()
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

func (g *GUI) coreVersion() string { return g.core.Info().Version }

func windowsVersion() string {
	maj, min, b := windows.RtlGetNtVersionNumbers()
	return fmt.Sprintf("%d.%d.%d", maj, min, b)
}
