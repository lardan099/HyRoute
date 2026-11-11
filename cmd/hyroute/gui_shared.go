//go:build windows || darwin

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/uirpc"
	"github.com/lardan099/hyroute/internal/zapret"
)

// The page's calls that are the same on Windows and macOS: thin wrappers
// around the controller. What differs (the window, the system, updates of
// the program itself) is in gui_windows.go and gui_darwin.go.

// dispatch runs a method of GUI for the page (uirpc.Dispatch).
func (g *GUI) dispatch(method string, args []json.RawMessage) (any, error) {
	g.dispatchOnce.Do(func() { g.dispatchFn = uirpc.Dispatch(g) })
	return g.dispatchFn(method, args)
}

// routingOn: the user connected and did not disconnect, so a restart of
// HyRoute (an update, a move) connects again. A session whose engine
// failed ("error" with stats) counts: HyRoute was reconnecting it.
func routingOn(st app.Status) bool {
	return st.State != "disconnected" && (st.State != "error" || st.Stats != nil)
}

// StartupNotice is a one-time message (update result).
func (g *GUI) StartupNotice() string {
	n := g.notice
	g.notice = ""
	return n
}

// emitSettings tells the pages that the settings changed (revision rev).
func (g *GUI) emitSettings(rev uint64) {
	g.win.notify("settings", rev)
}

func (g *GUI) Status() app.Status { return g.ctl.Status() }

func (g *GUI) Connect() error { return g.ctl.Connect() }

func (g *GUI) Disconnect() { g.ctl.Disconnect() }

func (g *GUI) Reconnect() error { return g.ctl.Reconnect() }

// reconnectAfterRollback: an update was rolled back and HyRoute was
// connected before it, so this (previous) version connects again,
// whatever "Подключаться при запуске" says. «Подключаться при запуске»
// itself is the controller's (RunNetModes: the network rules decide first).
func (g *GUI) reconnectAfterRollback() {
	g.ctl.ConnectAtStart("connecting again: the update was rolled back, HyRoute was connected before it")
}

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

// ReleaseKillSwitch opens the internet the kill switch closed.
func (g *GUI) ReleaseKillSwitch() error { return g.ctl.ReleaseKillSwitch() }

func (g *GUI) Profiles() []app.ProfileSummary { return g.ctl.Profiles() }

func (g *GUI) Profile(id string) (hysteria.Profile, error) {
	return g.ctl.Profile(id)
}

func (g *GUI) ImportURIs(text string) (app.ImportResult, error) { return g.ctl.ImportURIs(text) }

// ImportClipboard imports links from the clipboard.
func (g *GUI) ImportClipboard() (app.ImportResult, error) {
	text, err := g.win.clipboardGet()
	if err != nil {
		return app.ImportResult{}, err
	}
	return g.ctl.ImportURIs(text)
}

// ClipboardText reads the clipboard for the setup's «Вставить из буфера»,
// which takes a server link or a subscription link alike.
func (g *GUI) ClipboardText() (string, error) {
	return g.win.clipboardGet()
}

func (g *GUI) SaveProfile(p hysteria.Profile) (app.ProfileSummary, error) {
	return g.ctl.SaveProfile(p)
}

func (g *GUI) DeleteProfile(id string) error { return g.ctl.DeleteProfile(id) }

func (g *GUI) SetMain(id string) error { return g.ctl.SetMain(id) }

func (g *GUI) MoveProfile(id string, to int) error { return g.ctl.MoveProfile(id, to) }

// CopyURI puts the profile's share link (with secrets) on the clipboard.
func (g *GUI) CopyURI(id string) error {
	uri, err := g.ctl.ExportURI(id)
	if err != nil {
		return err
	}
	return g.win.clipboardSet(uri)
}

func (g *GUI) Subscriptions() []app.SubView { return g.ctl.Subscriptions() }

func (g *GUI) PreviewSubscription(url string) (app.Preview, error) {
	return g.ctl.PreviewSubscription(url)
}

func (g *GUI) AddSubscription(in app.SubInput) (app.SubView, error) { return g.ctl.AddSubscription(in) }

func (g *GUI) EditSubscription(in app.SubInput) error { return g.ctl.EditSubscription(in) }

func (g *GUI) UpdateSubscription(id string) (app.MergeStats, error) {
	return g.ctl.UpdateSubscription(id)
}

func (g *GUI) RollbackSubscription(id string) (app.MergeStats, error) {
	return g.ctl.RollbackSubscription(id)
}

func (g *GUI) DeleteSubscription(id string) error { return g.ctl.DeleteSubscription(id) }

// ZapretInfo is the «Обход DPI» page.
func (g *GUI) ZapretInfo() app.ZapretView { return g.ctl.ZapretInfo() }

// SaveZapret saves the page and applies it (winws2 and the rules).
func (g *GUI) SaveZapret(in app.ZapretInput) error { return g.ctl.SaveZapret(in) }

// SaveTelegram turns «Telegram без VPN» on or off.
func (g *GUI) SaveTelegram(in app.TelegramInput) error { return g.ctl.SaveTelegram(in) }

// ZapretRoute: where the user's rules send a service (before «через VPN»).
func (g *GUI) ZapretRoute(t zapret.Target) (app.ZapretRoute, error) { return g.ctl.ZapretRoute(t) }

// ZapretViaVPN sends a service through the VPN as chosen.
func (g *GUI) ZapretViaVPN(in app.ZapretViaInput) error { return g.ctl.ZapretViaVPN(in) }

// ZapretPick finds working methods on this network (takes up to a few
// minutes; the page reads the progress with ZapretInfo).
func (g *GUI) ZapretPick() (app.ZapretView, error) { return g.ctl.ZapretPick() }

// ZapretPickCancel stops a pick under way.
func (g *GUI) ZapretPickCancel() { g.ctl.ZapretPickCancel() }

// SetSubscriptionProxies turns a subscription's proxies (one per server)
// on, or off with nil.
func (g *GUI) SetSubscriptionProxies(id string, in *app.SubProxiesInput) error {
	return g.ctl.SetSubscriptionProxies(id, in)
}

// CopyText puts text on the clipboard (navigator.clipboard is not
// reliable in the WebView).
func (g *GUI) CopyText(text string) error { return g.win.clipboardSet(text) }

// Settings is a page's copy of the settings with the revision its saves
// send back (SaveSettings refuses a stale one).
func (g *GUI) Settings() app.SettingsView { return g.ctl.SettingsView() }

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

func (g *GUI) DuplicateRule(list []rules.Rule, r rules.Rule, skip int) int {
	return g.ctl.DuplicateRule(list, r, skip)
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
	path, err := g.win.saveFile(runtime.SaveDialogOptions{
		DefaultFilename: name,
		Filters:         []runtime.FileFilter{{DisplayName: "Лог (*.log)", Pattern: "*.log"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	// As ExportBackup: HyRoute is elevated, and the folder and the name
	// are the user's; writeUserFile writes with the user's rights and never
	// follows a link in the file's place.
	return path, g.writeUserFile(g.win.dialogUser(path), path, []byte(g.ctl.ExportLog(kind, sanitized)))
}

// Sanitize applies Privacy mode to text the UI copies.
func (g *GUI) Sanitize(text string) string { return g.ctl.Sanitize(text) }

func (g *GUI) ClearLogs() error { return g.ctl.ClearLogs() }

func (g *GUI) Prefs() store.Prefs { return g.ctl.Prefs() }

// SavePrefs keeps the fields other calls own: the rule-database ones
// (SetGeoPrefs), the postponed version (SkipAppVersion, "Позже"), the
// command line's mode (SetCLIMode) and the browser extension's access
// (SetBrowserOn: its card is on the same page). The settings page may
// hold an older copy; UpdatePrefs holds the prefs lock across the read
// and the write.
func (g *GUI) SavePrefs(p store.Prefs) error {
	return g.ctl.UpdatePrefs(func(cur *store.Prefs) error {
		p.GeoSource, p.GeoSiteURL, p.GeoIPURL, p.GeoAutoOff, p.GeoIntervalHours = cur.GeoSource, cur.GeoSiteURL, cur.GeoIPURL, cur.GeoAutoOff, cur.GeoIntervalHours
		p.SkipVersion = cur.SkipVersion
		p.CLI = cur.CLI
		p.Browser = cur.Browser
		*cur = p
		return nil
	})
}

func (g *GUI) CheckProfile(id string) (app.CheckResult, error) { return g.ctl.CheckProfile(id) }

// Diagnostics is the support report (Privacy mode when privacy).
func (g *GUI) Diagnostics(privacy bool) string {
	return g.ctl.Diagnostics(g.systemLines(), privacy)
}

func (g *GUI) CopyDiagnostics(privacy bool) error {
	return g.win.clipboardSet(g.Diagnostics(privacy))
}

func (g *GUI) Updates() app.UpdatesState { return g.ctl.Updates() }

func (g *GUI) CheckUpdates() app.UpdatesState { return g.ctl.CheckUpdates() }

// Rule databases (geosite/geoip).
func (g *GUI) GeoInfo() app.GeoInfo { return g.ctl.GeoInfo() }

func (g *GUI) UpdateGeo(force bool) (geodata.Result, error) {
	return g.ctl.UpdateGeo(g.life, force)
}

func (g *GUI) RollbackGeo() error { return g.ctl.RollbackGeo() }

func (g *GUI) SetGeoPrefs(source, siteURL, ipURL string, auto bool, hours int) error {
	return g.ctl.SetGeoPrefs(source, siteURL, ipURL, auto, hours)
}

// List inspector: which geosite/geoip lists contain a site or IP.
func (g *GUI) Inspect(query string) (app.InspectResult, error) { return g.ctl.Inspect(query) }

func (g *GUI) GeoList(kind, name, filter string, offset, limit int) (geodata.Listing, error) {
	return g.ctl.GeoList(kind, name, filter, offset, limit)
}

func (g *GUI) ConvertACL(text, mode, suffix, actions string) (app.ConvertResult, error) {
	return g.ctl.ConvertACL(text, mode, suffix, actions)
}

// ImportRules converts rules of another program (SwitchyOmega, v2rayN,
// Throne, FoxyProxy, Clash, PAC …) into rules text.
func (g *GUI) ImportRules(text, format string, to map[string]string) (app.RulesImport, error) {
	return g.ctl.ImportRules(text, format, to)
}

func (g *GUI) GeoCategories(kind, query string) []string {
	return g.ctl.GeoCategories(kind, query, 40)
}

func (g *GUI) InstallCore() error { return g.ctl.InstallCore() }

func (g *GUI) RollbackCore() error { return g.ctl.RollbackCore() }

func (g *GUI) InstallXray() error { return g.ctl.InstallXray() }

func (g *GUI) RollbackXray() error { return g.ctl.RollbackXray() }

func (g *GUI) DownloadAppUpdate() error { return g.ctl.DownloadAppUpdate() }

func (g *GUI) SkipAppVersion(v string) error { return g.ctl.SkipAppVersion(v) }

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
	// socks-udp: ProxyRules lists the local proxy rules that exist (TCP,
	// UDP), never nil.
	ProxyRules []string `json:"proxyRules"`
}

func (g *GUI) coreVersion() string { return g.core.Info().Version }

// RulesJSON is «Правила текстом» → JSON of the profile the page shows (its
// token; "" = the active one).
func (g *GUI) RulesJSON(ruleset string) (string, error) {
	b, err := g.ctl.RulesJSONFor(ruleset)
	return string(b), err
}

// ParseRulesTextFor is the «Правила текстом» preview: replace = mode «Все
// правила» (a pasted JSON's «Всё остальное» counts only then).
func (g *GUI) ParseRulesTextFor(text string, replace bool) app.RulesTextResult {
	return g.ctl.ParseRulesTextAs(text, "auto", replace)
}

// RulesetsBrief, ConnectOrResume and SwitchRulesetFromTray serve the menu
// bar icon on macOS (the Windows tray calls the controller itself).
func (g *GUI) RulesetsBrief() app.RulesetsBrief { return g.ctl.RulesetsBrief() }
func (g *GUI) ConnectOrResume() error {
	_, err := g.ctl.ConnectOrResume()
	return err
}
func (g *GUI) SwitchRulesetFromTray(id string) error {
	_, err := g.ctl.SwitchRuleset(id, app.SourceTray, app.SwitchOptions{})
	return err
}

// ServersBrief and SetMainFromTray: the menu's «Сервер» submenu, the same
// way.
func (g *GUI) ServersBrief() app.ServersBrief  { return g.ctl.ServersBrief() }
func (g *GUI) SetMainFromTray(id string) error { return g.ctl.SetMain(id) }

// ZapretBrief and SetZapretEnabled: the bypass as the tray and the panel
// show and switch it.
func (g *GUI) ZapretBrief() app.ZapretBrief   { return g.ctl.ZapretBrief() }
func (g *GUI) SetZapretEnabled(on bool) error { return g.ctl.SetZapretEnabled(on) }

func (g *GUI) TidyRules(s settings.Settings, accept []string) app.TidyView {
	return g.ctl.TidyRules(s, accept)
}
