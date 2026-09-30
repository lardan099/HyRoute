//go:build windows

// HyRoute: Windows client for Hysteria 2 with per-application and
// per-domain routing (Tunnel / Direct / Block).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailswin "github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/sys/windows"

	buildfiles "github.com/lardan099/hyroute/build"
	"github.com/lardan099/hyroute/frontend"
	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/autostart"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/fwrule"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/killswitch"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/netwatch"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/runtimefiles"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/sysdns"
	"github.com/lardan099/hyroute/internal/update"
)

// Stamped by scripts/build.ps1: build is the git commit, version the
// release tag (git describe), updateRepo where releases are published.
var (
	build      = "dev"
	version    = "v0.0.0-dev"
	updateRepo = "lardan099/HyRoute"
)

func main() {
	stub := flag.Bool("stub", false, "use an in-process SOCKS5 stub instead of Hysteria (testing)")
	verbose := flag.Bool("v", false, "debug logging")
	updEvent := flag.String("update-event", "", "set by hyroute-updater: signal this event once running")
	updFrom := flag.String("updated-from", "", "set by hyroute-updater: version replaced")
	updFailed := flag.String("update-failed", "", "set by hyroute-updater: the update to this version failed")
	updError := flag.String("update-error", "", "set by hyroute-updater: why")
	waitPID := flag.Uint("wait-pid", 0, "wait for this process to exit first (move to Program Files)")
	movedFrom := flag.String("moved-from", "", "set after a move to Program Files: the old folder")
	reconnect := flag.Bool("reconnect", false, "set by hyroute-updater (then report healthy) and after a move to Program Files: connect again")
	atLogon := flag.Bool("autostart", false, "set by the sign-in task: start minimized")
	ksCheck := flag.Bool("killswitch-check", false, "set by the kill switch sign-in task: start only to show a kill switch block left from before")
	flag.Parse()

	if !windows.GetCurrentProcessToken().IsElevated() {
		messageBox("HyRoute", "HyRoute нужны права администратора (драйвер WinDivert). Запустите программу от имени администратора.")
		os.Exit(1)
	}
	// Started at sign-in by the kill switch check: without a block to show
	// HyRoute ends here, before anything with an effect (the instance
	// claim would bring a running copy's window up).
	if !signInCheck(*ksCheck, killswitch.Leftover) {
		os.Exit(0)
	}
	// After a move the old copy may take long to disconnect: it must be
	// gone first, or the check below would hand over to it and HyRoute
	// would end with it.
	if *waitPID != 0 {
		waitProcess(uint32(*waitPID))
	}
	// A second start only brings the running copy's window up: nothing
	// below may run twice. The instance mutex belongs to this thread.
	runtime.LockOSThread()
	inst, handedOver := claimInstance(instanceID)
	if handedOver {
		os.Exit(0)
	}
	// cli: hyroutectl sees HyRoute starting from here on.
	cs := initCLI()
	exe, _ := os.Executable()
	if *atLogon {
		// Before the packet engine and hysteria.exe start: a task from an
		// earlier version starts HyRoute at background priority.
		autostart.AtLogon(exe)
	}
	dir := filepath.Dir(exe)
	update.CleanAside(dir)
	if *updEvent == "" {
		recoverInterruptedUpdate(exe, *atLogon)
	}
	dataDir, err := store.DefaultDir()
	if err != nil {
		fatalBox(err)
	}
	crashLog(dataDir)
	st, err := store.Open(dataDir)
	if err != nil {
		fatalBox(err)
	}
	// hysteria.exe and WinDivert run from a verified copy in a folder only
	// administrators can write, never from the program folder itself.
	// A file the program folder lacks is downloaded from the URL pinned in
	// deps.json (same hash check).
	runtimeDir := core.DefaultDir("runtime")
	var staged runtimefiles.Result
	files, err := runtimefiles.FromDeps(buildfiles.Deps)
	if err == nil {
		dlCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		get := runtimefiles.HTTPGetter(dlCtx, &http.Client{Timeout: 4 * time.Minute}, "HyRoute/"+version)
		runtimeDir, staged, err = stageRuntime(dir, runtimeDir, files, get, core.ProtectDir)
		cancel()
	}
	if err != nil {
		fatalBox(err)
	}
	// WebView2's processes run elevated with HyRoute and write the window's
	// data by name all over their folder: in the profile, any program of
	// the user could swap one of its subfolders for a link and have them
	// write wherever it leads. So the folder is one only administrators can
	// write to, as runtimeDir (after it: the HyRoute folder above both is
	// protected by then). Under Administrator protection WebView2 does not
	// run elevated, and its folder is the user's own (webviewDataDir).
	webviewDir, protect, err := webviewDataDir()
	if err == nil && protect {
		err = core.ProtectDir(webviewDir)
	}
	if err != nil {
		fatalBox(err)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	ctl := app.New(st, func(cfg session.Config) (app.Session, error) {
		s, err := session.Start(cfg)
		if err != nil {
			return nil, err
		}
		return s, nil
	}, session.Config{
		Dir:    runtimeDir,
		Exe:    exe,
		RunDir: filepath.Join(dataDir, "run"),
		Stub:   *stub,
	}, level)
	// The engine log also goes to logs\hyroute.log (size-rotated) unless
	// the user keeps logs in memory only. The folder is set once the
	// settings are loaded: before, the setting reads as its default (on),
	// and the first lines would reach the disk of a user who turned it off.
	ctl.Log = slog.New(ctl.NewFileHandler(level, ctl.EngineWriter()))
	// dns: HyRoute's own direct connections register their hosts (before
	// anything fetches), the Windows DNS cache is flushed through dnsapi
	// (Load may flush already), and Explain reads the local namespaces.
	ctl.InstallOwnDial()
	ctl.FlushDNS = sysdns.FlushCache
	ctl.LocalSuffixes = func() []string {
		i, _ := sysdns.Snapshot()
		return i.Suffixes
	}
	loadErr := ctl.Load()
	ctl.SetLogDir(filepath.Join(dataDir, "logs"))
	ctl.Log.Info("HyRoute starting", "build", build, "dir", dir, "runtime", runtimeDir, "data", dataDir, "stub", *stub)
	if len(staged.Downloaded) > 0 {
		ctl.Log.Info("files missing next to HyRoute.exe were downloaded and verified", "files", strings.Join(staged.Downloaded, ", "))
	}
	if len(staged.Replaced) > 0 {
		ctl.Log.Warn("files next to HyRoute.exe do not match the ones HyRoute was built with (damaged or replaced); verified copies were downloaded instead",
			"files", strings.Join(staged.Replaced, ", "))
	}
	for _, d := range core.MovedAside() {
		ctl.Log.Warn("a HyRoute folder under ProgramData was not made by HyRoute (another program made it, or takeown gave it to a user): it was renamed and made anew; the renamed folder is not used and can be deleted", "renamed", d)
	}
	if runtimeDir != core.DefaultDir("runtime") {
		ctl.Log.Warn("the shared copies of hysteria.exe and WinDivert are in use by a HyRoute of another version (another Windows user): this one runs its own", "runtime", runtimeDir)
	}
	if !protectedLocation(dir) {
		ctl.Log.Warn("HyRoute runs from a folder other programs can write to; move it to Program Files", "dir", dir)
	}
	if loadErr != nil {
		ctl.Log.Error("settings not loaded", "err", loadErr)
	}

	ctl.Version = version
	coreMgr := &core.Manager{
		Dir:     core.DefaultDir("core"),
		Bundled: filepath.Join(runtimeDir, "hysteria.exe"),
		Client:  &release.Client{UserAgent: "HyRoute/" + version},
		Version: hysteria.ExeVersion,
	}
	ctl.Base.Hysteria = coreMgr.Path
	// The kill switch lets HyRoute and Hysteria through, so they can
	// reconnect while the internet is closed.
	ctl.KillSwitch = &killswitch.Switch{Self: exe, Apps: func() []string {
		return append([]string{exe}, coreMgr.Paths()...)
	}}
	ctl.InitKillSwitch()
	// A block left from before is what a start at sign-in has to show:
	// the autostart task stands in for the kill switch check.
	blocked := ctl.Status().KillSwitch == "blocking"
	if *ksCheck {
		ctl.Log.Info("started at sign-in by the kill switch check: a block from before closes the internet")
	}
	ctl.ListRunning = procinfo.ListRunning
	// netmodes: New only allocates; nothing is read until «Сети» is used.
	ctl.NetWatcher = netwatch.New()
	ctl.ProxyFirewall = func(tcp, udp []int) error { return fwrule.SetProxyPorts(exe, tcp, udp) }
	ctl.LegacyProxyUDP = fwrule.LegacyProxyUDP
	ctl.KeepV12ProxyUDP() // before the window can show a proxy
	ctl.Updater = &app.Updater{Repo: updateRepo, Dir: core.DefaultDir("updates"), Core: coreMgr, Client: coreMgr.Client}
	cleanUpdates(ctl.Updater.Dir)

	gui := &GUI{ctl: ctl, dataDir: dataDir, dllDir: dir, runtimeDir: runtimeDir, core: coreMgr, updateEvent: *updEvent}
	gui.cli = cs
	// Set before any goroutine below can report a change.
	ctl.CoreVersion = func() string { return coreMgr.Info().Version }
	ctl.OnChange = gui.emitStatus
	// Pages holding a copy of the settings reload (Status carries the
	// revision too, for a missed event).
	ctl.OnSettings = gui.emitSettings
	// Automatic reconnects after engine failures stopped: without the
	// window a user in the tray would not know.
	ctl.OnGiveUp = gui.showWindow
	// netmodes: the start checks (a kill switch block from before that
	// stays shows the window) wait for both what connects at start and the
	// window.
	gate := &startGate{fn: gui.startChecks}
	ctl.OnStartDecided = gate.markDecided
	schedCtx, stopSched := context.WithCancel(context.Background())
	defer stopSched()
	go ctl.RunScheduler(schedCtx)
	go ctl.RunUpdateChecks(schedCtx)
	go ctl.RunGeoUpdates(schedCtx)
	go ctl.RunStats(schedCtx) // stats
	go gui.syncKillSwitchCheck()

	// What connects at start follows the launch reason: an update, a
	// rollback or a move restores the state before it (--reconnect: it was
	// connected), a normal start lets the network rules or «Подключаться
	// при запуске» decide.
	plan := planStart(*updEvent, *updFailed, *movedFrom, *reconnect)
	gui.connUp.Store(plan.connUp)
	restore := map[string]func(){"update": gui.reconnectAfterUpdate, "rollback": gui.reconnectAfterRollback, "move": gui.reconnectAfterMove}[plan.restore]
	if restore != nil {
		go func() {
			defer gate.markDecided() // the restore reconnect is the start decision
			restore()
		}()
	}
	go ctl.RunNetModes(schedCtx, plan.mode)
	switch {
	case *movedFrom != "":
		gui.notice = "HyRoute перенесён в " + dir + " и добавлен в меню «Пуск». Старую папку " + *movedFrom + " можно удалить."
		ctl.Log.Info("moved to Program Files", "from", *movedFrom, "to", dir)
	case *updFailed != "":
		gui.notice = "Обновление не установлено: " + *updError + ". Работает прежняя версия " + version + "."
		ctl.Log.Error("update failed, previous version restored", "target", *updFailed, "reason", *updError)
	case *updFrom != "":
		gui.notice = "HyRoute обновлён: " + *updFrom + " → " + version + "."
		ctl.Log.Info("updated", "from", *updFrom, "to", version)
	}
	// Started by the sign-in task: in the tray, or minimized without it.
	// The kill switch check starts HyRoute with its window shown: the
	// block is what the user has to see, and so does the autostart task
	// when it finds one.
	// With network rules on, a block from before may be released by the
	// rule of a trusted network: the start gate shows the window once the
	// start decision is made, if the block stays.
	nm := ctl.NetModes(false)
	if nm.Config.Enabled && nm.LoadError == "" {
		blocked = false
	}
	startState, startHidden := options.Normal, false
	if *atLogon && !blocked {
		if ctl.Prefs().CloseToTrayOn() {
			startHidden = true
		} else {
			startState = options.Minimised
		}
	}
	gui.tray.hidden.Store(startHidden)
	gui.startCLI() // cli: the control pipe for hyroutectl
	err = wails.Run(&options.App{
		Title:            "HyRoute",
		WindowStartState: startState,
		StartHidden:      startHidden,
		Width:            1180,
		Height:           760,
		MinWidth:         900,
		MinHeight:        560,
		BackgroundColour: &options.RGBA{R: 24, G: 26, B: 31, A: 255},
		AssetServer:      &assetserver.Options{Assets: frontend.Dist},
		OnStartup: func(ctx context.Context) {
			gui.startup(ctx)
			// The window exists: a second start now shows it.
			inst.serve(gui.showWindow)
			gate.markUI()
		},
		OnDomReady: gui.domReady,
		OnShutdown: func(ctx context.Context) {
			inst.leaving()
			gui.stopCLI()
			gui.shutdown(ctx)
		},
		OnBeforeClose: func(ctx context.Context) bool {
			if gui.beforeClose(ctx) {
				return true // hidden, still running
			}
			inst.leaving()
			return false
		},
		Bind: []interface{}{gui},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "hyroute-7f3c1a52-single-instance",
			OnSecondInstanceLaunch: gui.secondInstance,
		},
		Windows: &wailswin.Options{
			Theme:               wailswin.SystemDefault,
			WebviewUserDataPath: webviewDir,
		},
	})
	if err != nil {
		fatalBox(err)
	}
}

// webviewDataDir is where WebView2 keeps the window's data (cache, the
// page's own storage), and whether HyRoute protects that folder:
// %ProgramData%\HyRoute\webview\<the user's SID>, one per Windows user as
// in the profile, where it was before (%APPDATA%\HyRoute\webview, no
// longer used).
//
// With Windows 11 Administrator protection the elevated HyRoute runs as a
// hidden admin account of its own, and WebView2 de-elevates itself: its
// processes run as the signed-in user, who may only read the protected
// folder, so the window never opened («Microsoft Edge не может выполнить
// чтение и запись в своем каталоге данных»). They then have no more rights
// than the user's other programs, so the folder is the user's own
// %LOCALAPPDATA%\HyRoute\webview, which WebView2 creates itself: HyRoute
// never touches it.
func webviewDataDir() (dir string, protect bool, err error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", false, err
	}
	if local := deElevatedLocalAppData(u.User.Sid); local != "" {
		return filepath.Join(local, "HyRoute", "webview"), false, nil
	}
	return filepath.Join(core.DefaultDir("webview"), u.User.Sid.String()), true, nil
}

// deElevatedLocalAppData is the signed-in user's %LOCALAPPDATA% when this
// process runs elevated as another account than its limited (linked)
// token, as Administrator protection does; "" otherwise (plain UAC keeps
// one account, and a process that is not elevated has no linked token).
func deElevatedLocalAppData(own *windows.SID) string {
	lt, err := store.LimitedToken()
	if err != nil || lt == 0 {
		return ""
	}
	defer lt.Close()
	lu, err := lt.GetTokenUser()
	if err != nil || !profileSeparated(own, lu.User.Sid) {
		return ""
	}
	if p, err := lt.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY); err == nil && filepath.IsAbs(p) {
		return p
	}
	if p, err := lt.GetUserProfileDirectory(); err == nil && filepath.IsAbs(p) {
		return filepath.Join(p, "AppData", "Local")
	}
	return ""
}

// profileSeparated: the elevated token belongs to another account than
// the limited one (Administrator protection), not to the same user (UAC).
func profileSeparated(own, limited *windows.SID) bool { return !own.Equals(limited) }

// cleanUpdates removes old staging directories (the one the updater may
// still run from is busy and stays until the next start). A folder a
// normal process may have made (and could fill with links) is left alone.
func cleanUpdates(dir string) {
	if core.CheckOwner(dir) != nil {
		return
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

// recoverInterruptedUpdate undoes an update the updater did not finish
// (power loss, killed): the journal lists the swapped files. The restored
// HyRoute is started (from the sign-in task: as such) and this process
// exits, since it may be the new executable that was just set aside.
//
// This runs elevated before %ProgramData%\HyRoute is protected, and a
// normal process can create that folder first: a journal another account
// could have written is ignored, and only this program's own folder is
// ever touched or started from.
func recoverInterruptedUpdate(exe string, atLogon bool) {
	jp := core.DefaultDir(update.JournalName)
	if core.CheckOwner(filepath.Dir(jp)) != nil || core.CheckOwner(jp) != nil {
		return // no journal, or one another account may have written
	}
	j, err := update.ReadJournal(jp)
	dir := filepath.Dir(exe)
	if err != nil || j == nil || !j.For(dir) {
		return
	}
	if j.UpdaterPID != 0 && updaterAlive(uint32(j.UpdaterPID), j.Started) {
		return // the updater is still working on it
	}
	if err := j.Undo(jp); err != nil {
		messageBox("HyRoute", "Обновление до "+j.To+" было прервано, и прежнюю версию не удалось вернуть полностью: "+err.Error()+
			". Скачайте HyRoute заново.")
		os.Exit(1)
	}
	args := []string{"--update-failed", j.To,
		"--update-error", "обновление было прервано (например, выключилось питание), прежняя версия восстановлена"}
	if j.Reconnect {
		// Connected before the update: as after the updater's own rollback.
		args = append(args, "--reconnect")
	}
	if atLogon {
		args = append(args, "--autostart")
	}
	if err := exec.Command(filepath.Join(dir, j.ExeName()), args...).Start(); err != nil {
		messageBox("HyRoute", "Прерванное обновление до "+j.To+" отменено, но HyRoute не запустился: "+err.Error()+". Запустите HyRoute снова.")
	}
	os.Exit(0)
}

// updaterAlive reports whether the updater that began a swap at started
// still runs as pid. A process created after that only took the number of
// one that is gone (after a restart of Windows, any process may have it).
func updaterAlive(pid uint32, started time.Time) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var created, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &created, &x, &k, &u) == nil && !started.IsZero() &&
		time.Unix(0, created.Nanoseconds()).After(started) {
		return false
	}
	r, _ := windows.WaitForSingleObject(h, 0)
	return r == uint32(windows.WAIT_TIMEOUT)
}

// stageRuntime stages the verified copies of files into runtimeDir (see
// runtimefiles.Stage) and returns the folder they run from. That folder is
// shared by the users of the computer: when a different copy there is in
// use (loaded or started by another user's HyRoute of another version),
// this build's copies go to a folder of their own under it instead of
// HyRoute not starting. protect makes a folder writable by administrators
// only (core.ProtectDir).
func stageRuntime(src, runtimeDir string, files []runtimefiles.File, get runtimefiles.Getter, protect func(string) error) (string, runtimefiles.Result, error) {
	if err := protect(runtimeDir); err != nil {
		return runtimeDir, runtimefiles.Result{}, err
	}
	res, err := runtimefiles.Stage(src, runtimeDir, files, get)
	if err == nil || !(errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
		return runtimeDir, res, err
	}
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s %s\n", f.Name, f.SHA256)
	}
	own := filepath.Join(runtimeDir, hex.EncodeToString(h.Sum(nil))[:16])
	if perr := protect(own); perr != nil {
		return runtimeDir, res, err
	}
	res2, err2 := runtimefiles.Stage(src, own, files, get)
	if err2 != nil {
		return runtimeDir, res, err
	}
	return own, res2, nil
}

// waitProcess waits for a process to exit (the old copy after a move).
// Stopping routing may take minutes (local proxies wait for their
// connections) and the old copy exits in any case, so there is no limit:
// starting while it still runs would end with it.
func waitProcess(pid uint32) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return // already gone
	}
	defer windows.CloseHandle(h)
	// The old copy started this one: a process started later only took
	// the number of one that is gone.
	if startedAfter(h, windows.CurrentProcess()) {
		return
	}
	windows.WaitForSingleObject(h, windows.INFINITE)
}

// startedAfter reports whether process a was created after process b
// (false when unknown).
func startedAfter(a, b windows.Handle) bool {
	var ca, cb, x, k, u windows.Filetime
	if windows.GetProcessTimes(a, &ca, &x, &k, &u) != nil || windows.GetProcessTimes(b, &cb, &x, &k, &u) != nil {
		return false
	}
	return ca.Nanoseconds() > cb.Nanoseconds()
}

func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONERROR)
}

func fatalBox(err error) {
	messageBox("HyRoute", fmt.Sprint(err))
	os.Exit(1)
}

// crashLog sends the Go runtime's report of a fatal error (an unrecovered
// panic, a deadlock) to logs\crash.log: a windowed program has no console
// to print it to. The folders are guarded first (store.Guard keeps them
// ordinary and non-empty), so the file is never opened through a link.
func crashLog(dataDir string) {
	dir := filepath.Join(dataDir, "logs")
	if store.Guard(dataDir) != nil || store.Guard(dir) != nil {
		return // store.Open and SetLogDir report it
	}
	path := filepath.Join(dir, "crash.log")
	// Every start adds a line: keep the file small.
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size() > 1<<20 {
		os.Rename(path, path+".1")
	}
	f, err := logx.OpenAppend(path)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "\n==== HyRoute %s (%s) started %s\n", version, build, time.Now().Format(time.RFC3339))
	debug.SetCrashOutput(f, debug.CrashOptions{})
	f.Close() // SetCrashOutput keeps its own duplicate
}
