package main

import (
	"context"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"fyne.io/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/killswitch"
)

type trayState struct {
	mu     sync.Mutex
	ready  bool
	state  string
	on     bool
	status *systray.MenuItem
	toggle *systray.MenuItem
	// missing: the icon did not come up, so the window stays in the
	// taskbar instead of hiding (set under mu, read without it).
	missing atomic.Bool
	// hidden: the window is hidden (started in the tray or closed to it).
	hidden atomic.Bool
	// restart: systray.Run returns because watchTray starts it over.
	restart atomic.Bool
	// gen numbers the runs of systray (set under mu, see startTray).
	// build is held while trayReady builds a run's menu, and by
	// restartTray. Lock order: build, then mu.
	gen   uint64
	build sync.Mutex
	// thread runs systray, started: it did (both set under mu). closed:
	// HyRoute exits, no run of systray begins (set under mu, see quitTray).
	thread  uint32
	started bool
	closed  atomic.Bool
	// The icons as files (see trayIconPaths).
	iconsOnce       sync.Once
	iconOn, iconOff string
	// rulesets: the «Профиль правил» submenu (trayrulesets_windows.go).
	rulesets trayRulesets
}

// taskbarWait: how long the tray waits for Explorer's taskbar (HyRoute
// started with Windows may be up first). trayWait: how long the icon may
// then take to come up before the window takes its place in the taskbar,
// and the first pause before systray is started over (see watchTray).
const (
	taskbarWait = time.Minute
	trayWait    = 15 * time.Second
)

// trayRetryMax bounds how often systray is started over: every start
// makes a Windows callback, which Go never frees (2000 in all).
const trayRetryMax = 120

var (
	user32                        = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW               = user32.NewProc("FindWindowW")
	procFindWindowExW             = user32.NewProc("FindWindowExW")
	procPostMessageW              = user32.NewProc("PostMessageW")
	procRegisterWindowMessageW    = user32.NewProc("RegisterWindowMessageW")
	procChangeWindowMessageFilter = user32.NewProc("ChangeWindowMessageFilter")
)

// startTray shows the tray icon. The tray runs its own message loop on a
// locked thread, next to the window's.
//
// systray adds its icon once. When the notification area refuses it
// (Explorer not ready yet at sign-in, or restarting), systray neither
// builds the menu nor calls trayReady, and on Explorer's TaskbarCreated
// it adds back only an empty icon; its hidden window still gets
// WM_ENDSESSION (see trayExit). So while the icon is not up, checkTray
// keeps the window in the taskbar and watchTray starts systray over.
// Once it is up, systray adds it back itself after Explorer restarts
// (see allowTaskbarCreated).
func (g *GUI) startTray() {
	go func() {
		goruntime.LockOSThread()
		waitTaskbar(taskbarWait)
		time.AfterFunc(trayWait, g.checkTray)
		thread := windows.GetCurrentThreadId()
		go g.watchTray(trayWait, func() bool { return g.restartTray(thread) })
		for gen := uint64(1); ; gen++ {
			// The new number before restart is cleared: a trayReady of the
			// run before, late, finds one or the other (see trayCurrent).
			g.tray.mu.Lock()
			if g.tray.closed.Load() {
				g.tray.mu.Unlock()
				return
			}
			g.tray.gen, g.tray.thread, g.tray.started = gen, thread, true
			g.tray.mu.Unlock()
			g.tray.restart.Store(false)
			systray.Run(func() { g.trayReady(gen) }, g.trayExit)
			if !g.tray.restart.Load() {
				return
			}
		}
	}()
}

// waitTaskbar waits up to limit for Explorer's taskbar.
func waitTaskbar(limit time.Duration) {
	for end := time.Now().Add(limit); !taskbarUp() && time.Now().Before(end); {
		time.Sleep(500 * time.Millisecond)
	}
}

func taskbarUp() bool {
	class, _ := windows.UTF16PtrFromString("Shell_TrayWnd")
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(class)), 0)
	return h != 0
}

// watchTray calls restart whenever the icon is not up, first after pause
// and then less often (up to four times pause), until HyRoute exits or
// restart has worked trayRetryMax times. The icon also goes when Windows
// ends the session and the end is cancelled (see trayExit).
func (g *GUI) watchTray(pause time.Duration, restart func() bool) {
	wait := pause
	for n := 0; n < trayRetryMax && !g.quitting.Load(); {
		time.Sleep(wait)
		g.tray.mu.Lock()
		ready := g.tray.ready
		g.tray.mu.Unlock()
		if ready {
			wait = pause
		} else if restart() {
			n++
			wait = min(2*wait, 4*pause)
		}
	}
}

// restartTray closes systray's hidden window, so that systray.Run returns
// and startTray runs it again on thread. Only while Explorer's taskbar is
// there to take the icon, and not under a trayReady building the menu
// (build): that run's icon is up. A run closed before its trayReady came
// gets no menu from it (see trayCurrent): it would draw into the next
// run, while systray sets that one up, and report its icon as up.
func (g *GUI) restartTray(thread uint32) bool {
	if !taskbarUp() {
		return false
	}
	g.tray.build.Lock()
	defer g.tray.build.Unlock()
	g.tray.mu.Lock()
	ready := g.tray.ready
	g.tray.mu.Unlock()
	if ready {
		return false
	}
	w := trayWindow(thread)
	if w == 0 {
		return false
	}
	const wmClose = 0x0010
	g.tray.restart.Store(true)
	if r, _, _ := procPostMessageW.Call(w, wmClose, 0, 0); r == 0 {
		g.tray.restart.Store(false)
		return false
	}
	g.ctl.Log.Debug("the tray icon is not up: starting the tray again")
	return true
}

// trayWindow is systray's hidden window (class SystrayClass in
// fyne.io/systray) made on thread, or 0.
func trayWindow(thread uint32) uintptr {
	class, _ := windows.UTF16PtrFromString("SystrayClass")
	var h uintptr
	for {
		h, _, _ = procFindWindowExW.Call(0, h, uintptr(unsafe.Pointer(class)), 0)
		if h == 0 {
			return 0
		}
		if tid, err := windows.GetWindowThreadProcessId(windows.HWND(h), nil); err == nil && tid == thread {
			return h
		}
	}
}

// allowTaskbarCreated lets Explorer's TaskbarCreated through to this
// elevated process (UIPI drops it otherwise): systray adds the icon again
// with it after Explorer restarts. Only once the icon is up: before, it
// would add an empty one.
func allowTaskbarCreated() {
	const msgfltAdd = 1
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	if msg, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(name))); msg != 0 {
		procChangeWindowMessageFilter.Call(msg, msgfltAdd)
	}
}

// checkTray: the icon did not come up (Explorer refused it). A window
// hidden to the tray could not be opened again: it is shown minimized,
// and the close button minimizes it until the icon comes up.
func (g *GUI) checkTray() {
	g.tray.mu.Lock()
	ready := g.tray.ready
	if !ready {
		g.tray.missing.Store(true)
	}
	g.tray.mu.Unlock()
	if ready {
		return
	}
	g.ctl.Log.Warn("the tray icon did not appear: HyRoute stays in the taskbar")
	if ctx := g.context(); ctx != nil && g.tray.hidden.Swap(false) {
		runtime.WindowShow(ctx)
		runtime.WindowMinimise(ctx)
	}
}

// trayExit runs when the tray window goes: on HyRoute's exit, and when
// Windows ends the session (the tray gets WM_ENDSESSION and the process
// ends right after; the main window does not report it). Only the latter
// removes the kill switch block.
//
// systray reports WM_ENDSESSION also when the end was cancelled (another
// program refused it and the user chose Cancel) and removes the icon
// either way. A HyRoute still running a while later, once Windows no
// longer reports the session ending, takes the kill switch back and keeps
// the window in the taskbar until the icon is back.
//
// systray calls this once per run: after it, a real end of the session
// would not reach HyRoute until the next run. So the run is replaced at
// once (renewTray), before the block comes back; also when the cancelled
// end came once Windows no longer reported it (neither HyRoute's exit nor
// restartTray's).
func (g *GUI) trayExit() {
	if !killswitch.SessionEnding() {
		if !g.tray.restart.Load() && !g.tray.closed.Load() {
			go g.renewTray()
		}
		return
	}
	g.ctl.EndSession()
	go func() {
		time.Sleep(sessionEndWait)
		for killswitch.SessionEnding() {
			time.Sleep(5 * time.Second)
		}
		g.renewTray()
		g.ctl.SessionResumed()
		g.checkTray()
	}()
}

// renewTray starts a new run of systray now (see restartTray), not at
// watchTray's next look, and waits a while for it to begin. If it cannot,
// watchTray tries again.
func (g *GUI) renewTray() {
	g.tray.mu.Lock()
	g.tray.ready = false
	g.tray.rulesets = trayRulesets{} // rulesets: the new run brings its own items
	gen, thread := g.tray.gen, g.tray.thread
	g.tray.mu.Unlock()
	if !g.restartTray(thread) {
		return
	}
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		g.tray.mu.Lock()
		begun := g.tray.gen != gen
		g.tray.mu.Unlock()
		if begun {
			return
		}
	}
}

// quitTray removes the tray icon when HyRoute exits, and no run of
// systray begins after it. systray.Quit calls the exit function that the
// first systray.Run registers and panics before it, and the tray may wait
// for Explorer's taskbar that long (see startTray). A run that has not
// made its window yet quits in trayReady.
func (g *GUI) quitTray() {
	g.tray.mu.Lock()
	g.tray.closed.Store(true)
	started, thread := g.tray.started, g.tray.thread
	g.tray.mu.Unlock()
	// systray.Run registers first, then makes the window.
	if started && trayWindow(thread) != 0 {
		systray.Quit()
	}
}

// sessionEndWait: Windows ends a process soon after its WM_ENDSESSION;
// one alive this much later is not ending.
const sessionEndWait = 30 * time.Second

// trayReady builds the menu of run gen of systray (see startTray), once
// its icon is up.
func (g *GUI) trayReady(gen uint64) {
	if g.tray.closed.Load() {
		// quitTray came before this run's window: its icon must not stay.
		systray.Quit()
		return
	}
	g.tray.build.Lock()
	defer g.tray.build.Unlock()
	if !g.trayCurrent(gen) {
		return
	}
	if _, off := g.trayIconPaths(); off != "" {
		systray.SetIconFromFilePath(off)
	}
	systray.SetTooltip("HyRoute")
	open := systray.AddMenuItem("Открыть HyRoute", "")
	systray.AddSeparator()
	status := systray.AddMenuItem("Отключено", "")
	status.Disable()
	toggle := systray.AddMenuItem("Подключить", "")
	rs, rsSlots := trayRulesetsMenu() // rulesets: hidden until there are two profiles
	systray.AddSeparator()
	quit := systray.AddMenuItem("Выход", "")
	systray.SetOnTapped(g.showWindow) // left click opens, right click shows the menu

	if g.trayUp(status, toggle) {
		g.ctl.Log.Info("the tray icon appeared: the close button hides HyRoute to the tray again")
	}
	g.trayRulesetsUp(rs, rsSlots) // rulesets
	g.updateTray()
	allowTaskbarCreated()

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				g.showWindow()
			case <-toggle.ClickedCh:
				go g.trayToggle()
			case <-quit.ClickedCh:
				g.quit()
				return
			}
		}
	}()
}

// trayCurrent: gen is the run of systray going on, and restartTray has
// not closed it.
func (g *GUI) trayCurrent(gen uint64) bool {
	g.tray.mu.Lock()
	defer g.tray.mu.Unlock()
	return gen == g.tray.gen && !g.tray.restart.Load()
}

// trayUp records that the icon and its new menu are up, as trayReady drew
// them (updateTray draws the state over it). late: the window had already
// taken the icon's place in the taskbar (see checkTray).
func (g *GUI) trayUp(status, toggle *systray.MenuItem) (late bool) {
	g.tray.mu.Lock()
	defer g.tray.mu.Unlock()
	g.tray.ready, g.tray.status, g.tray.toggle = true, status, toggle
	g.tray.state, g.tray.on = "", false
	return g.tray.missing.Swap(false)
}

// trayToggle does what the clicked item said ("Подключить" or
// "Отключить"), even if the state has moved on since it was drawn.
func (g *GUI) trayToggle() {
	g.tray.mu.Lock()
	on := g.tray.on
	g.tray.mu.Unlock()
	if on {
		g.ctl.Disconnect()
		return
	}
	var err error
	if st := g.ctl.Status(); st.State == "error" && st.Stats != nil {
		// The engine failed but the session is still there: Connect would
		// do nothing.
		err = g.ctl.Reconnect()
	} else {
		err = g.ctl.Connect()
	}
	if err != nil {
		g.showWindow()
	}
}

// trayView is what the tray shows for a status: the text, and whether
// routing is on (colour icon, "Отключить").
func trayView(st app.Status) (text string, on bool) {
	on = st.State != "disconnected" && st.State != "error"
	text = map[string]string{
		"disconnected": "Отключено", "starting": "Запуск…", "connecting": "Подключение…",
		"connected": "Подключено", "tunnel-down": "Сервер недоступен", "error": "Ошибка",
	}[st.State]
	if st.State == "disconnected" && st.Net != nil && st.Net.Off {
		// netmodes: no names, the tray does not know Privacy mode.
		text = "Отключено правилом сети"
	}
	if st.KillSwitch == "blocking" {
		text = "Интернет закрыт kill switch"
	}
	return text, on
}

// updateTray follows the connection state (called on every status change;
// only a changed state touches the tray).
func (g *GUI) updateTray() {
	g.tray.mu.Lock()
	defer g.tray.mu.Unlock()
	if !g.tray.ready {
		return
	}
	g.trayRulesetsLocked() // rulesets: follows its own changes
	// Read under the lock: every change runs this in a goroutine of its
	// own, and an older reading must not be applied after a newer one.
	text, on := trayView(g.ctl.Status())
	if g.tray.state == text && g.tray.on == on {
		return
	}
	g.tray.state, g.tray.on = text, on
	iconOn, iconOff := g.trayIconPaths()
	if on && iconOn != "" {
		systray.SetIconFromFilePath(iconOn)
	} else if iconOff != "" {
		systray.SetIconFromFilePath(iconOff)
	}
	systray.SetTooltip("HyRoute — " + text)
	g.tray.status.SetTitle(text)
	if on {
		g.tray.toggle.SetTitle("Отключить")
	} else {
		g.tray.toggle.SetTitle("Подключить")
	}
}

// trayIconPaths returns the tray icons as files in the runtime folder
// ("" if they could not be written): systray loads an icon from a file.
// Not systray.SetIcon: it writes the file to %TEMP% under a name known in
// advance and loads whatever is there, and that folder is the user's, so
// any program could hand this elevated process a file of its own to parse,
// or a link that makes it create one anywhere. Only administrators can
// write to the runtime folder.
func (g *GUI) trayIconPaths() (on, off string) {
	g.tray.iconsOnce.Do(func() {
		iconOn, iconOff := trayIcons()
		var err error
		if g.tray.iconOn, err = writeIcon(g.runtimeDir, iconOn); err == nil {
			g.tray.iconOff, err = writeIcon(g.runtimeDir, iconOff)
		}
		if err != nil {
			g.tray.iconOn, g.tray.iconOff = "", ""
			g.ctl.Log.Warn("tray icon files not written: the tray icon stays blank", "err", err)
		}
	})
	return g.tray.iconOn, g.tray.iconOff
}

// showWindow brings the window up as it was: Wails restores it only if it
// is minimized (WindowUnminimise would also take a maximized one back to
// its normal size).
func (g *GUI) showWindow() {
	if ctx := g.context(); ctx != nil {
		g.tray.hidden.Store(false)
		runtime.WindowShow(ctx)
	}
}

// quit exits for real (tray "Выход", updates, moving to Program Files):
// the close button only hides the window when it goes to the tray.
func (g *GUI) quit() {
	g.quitting.Store(true)
	if ctx := g.context(); ctx != nil {
		runtime.Quit(ctx)
	}
}

// beforeClose: the close button hides the window to the tray (setting
// «Кнопка × сворачивает в трей», on by default), or minimizes it when the
// tray icon did not come up.
func (g *GUI) beforeClose(ctx context.Context) bool {
	if g.quitting.Load() || !g.ctl.Prefs().CloseToTrayOn() {
		return false
	}
	if g.tray.missing.Load() {
		runtime.WindowMinimise(ctx)
		return true
	}
	g.tray.hidden.Store(true)
	runtime.WindowHide(ctx)
	return true
}
