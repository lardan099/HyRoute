//go:build windows

// HyRoute: Windows client for Hysteria 2 with per-application and
// per-domain routing (Tunnel / Direct / Block).
package main

import (
	"context"
	"embed"
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

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/autostart"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/fwrule"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/killswitch"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/runtimefiles"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/update"
)

//go:embed all:frontend/dist
var assets embed.FS

// deps.json pins the SHA-256 of hysteria.exe and WinDivert: the copies in
// the program folder are checked against it before they run elevated.
//
//go:embed deps.json
var depsJSON []byte

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
	files, err := runtimefiles.FromDeps(depsJSON)
	if err == nil {
		err = core.ProtectDir(runtimeDir)
	}
	if err == nil {
		dlCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		get := runtimefiles.HTTPGetter(dlCtx, &http.Client{Timeout: 4 * time.Minute}, "HyRoute/"+version)
		staged, err = runtimefiles.Stage(dir, runtimeDir, files, get)
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
	// protected by then).
	webviewDir, err := webviewDataDir()
	if err == nil {
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
	// the user keeps logs in memory only.
	ctl.Log = slog.New(ctl.NewFileHandler(level, ctl.EngineWriter()))
	ctl.SetLogDir(filepath.Join(dataDir, "logs"))
	ctl.Log.Info("HyRoute starting", "build", build, "dir", dir, "runtime", runtimeDir, "data", dataDir, "stub", *stub)
	if len(staged.Downloaded) > 0 {
		ctl.Log.Info("files missing next to HyRoute.exe were downloaded and verified", "files", strings.Join(staged.Downloaded, ", "))
	}
	if len(staged.Replaced) > 0 {
		ctl.Log.Warn("files next to HyRoute.exe do not match the ones HyRoute was built with (damaged or replaced); verified copies were downloaded instead",
			"files", strings.Join(staged.Replaced, ", "))
	}
	if !protectedLocation(dir) {
		ctl.Log.Warn("HyRoute runs from a folder other programs can write to; move it to Program Files", "dir", dir)
	}
	if err := ctl.Load(); err != nil {
		ctl.Log.Error("settings not loaded", "err", err)
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
	if *ksCheck {
		ctl.Log.Info("started at sign-in by the kill switch check: a block from before closes the internet")
	}
	ctl.ListRunning = procinfo.ListRunning
	ctl.ProxyFirewall = func(ports []int) error { return fwrule.SetProxyPorts(exe, ports) }
	ctl.Updater = &app.Updater{Repo: updateRepo, Dir: core.DefaultDir("updates"), Core: coreMgr, Client: coreMgr.Client}
	cleanUpdates(ctl.Updater.Dir)

	gui := &GUI{ctl: ctl, dataDir: dataDir, dllDir: dir, runtimeDir: runtimeDir, core: coreMgr, updateEvent: *updEvent}
	// Set before any goroutine below can report a change.
	ctl.CoreVersion = func() string { return coreMgr.Info().Version }
	ctl.OnChange = gui.emitStatus
	// Automatic reconnects after engine failures stopped: without the
	// window a user in the tray would not know.
	ctl.OnGiveUp = gui.showWindow
	schedCtx, stopSched := context.WithCancel(context.Background())
	defer stopSched()
	go ctl.RunScheduler(schedCtx)
	go ctl.RunUpdateChecks(schedCtx)
	go ctl.RunGeoUpdates(schedCtx)
	go gui.syncKillSwitchCheck()

	switch {
	case *updEvent != "" && *reconnect:
		go gui.reconnectAfterUpdate()
	case *updFailed != "" && *reconnect:
		// The update was rolled back: connected before it, so again now.
		gui.connUp.Store(true)
		go gui.reconnectAfterRollback()
	default:
		gui.connUp.Store(true)
		// --reconnect without an update: the copy moved to Program Files
		// was connected.
		if ctl.Prefs().AutoConnect || *reconnect {
			go gui.autoConnect()
		}
	}
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
	// block is what the user has to see.
	startState, startHidden := options.Normal, false
	if *atLogon {
		if ctl.Prefs().CloseToTrayOn() {
			startHidden = true
		} else {
			startState = options.Minimised
		}
	}
	gui.tray.hidden.Store(startHidden)
	err = wails.Run(&options.App{
		Title:            "HyRoute",
		WindowStartState: startState,
		StartHidden:      startHidden,
		Width:            1180,
		Height:           760,
		MinWidth:         900,
		MinHeight:        560,
		BackgroundColour: &options.RGBA{R: 24, G: 26, B: 31, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup: func(ctx context.Context) {
			gui.startup(ctx)
			// The window exists: a second start now shows it.
			inst.serve(gui.showWindow)
		},
		OnDomReady: gui.domReady,
		OnShutdown: func(ctx context.Context) {
			inst.leaving()
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
// page's own storage): %ProgramData%\HyRoute\webview\<the user's SID>,
// one per Windows user as in the profile, where it was before
// (%APPDATA%\HyRoute\webview, no longer used).
func webviewDataDir() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return filepath.Join(core.DefaultDir("webview"), u.User.Sid.String()), nil
}

// cleanUpdates removes old staging directories (the one the updater may
// still run from is busy and stays until the next start).
func cleanUpdates(dir string) {
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
	if j.UpdaterPID != 0 && processAlive(uint32(j.UpdaterPID)) {
		return // the updater is still working on it
	}
	if err := j.Undo(jp); err != nil {
		messageBox("HyRoute", "Обновление до "+j.To+" было прервано, и прежнюю версию не удалось вернуть полностью: "+err.Error()+
			". Скачайте HyRoute заново.")
		os.Exit(1)
	}
	args := []string{"--update-failed", j.To,
		"--update-error", "обновление было прервано (например, выключилось питание), прежняя версия восстановлена"}
	if atLogon {
		args = append(args, "--autostart")
	}
	if err := exec.Command(filepath.Join(dir, j.ExeName()), args...).Start(); err != nil {
		messageBox("HyRoute", "Прерванное обновление до "+j.To+" отменено, но HyRoute не запустился: "+err.Error()+". Запустите HyRoute снова.")
	}
	os.Exit(0)
}

func processAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	r, _ := windows.WaitForSingleObject(h, 0)
	return r == uint32(windows.WAIT_TIMEOUT)
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
