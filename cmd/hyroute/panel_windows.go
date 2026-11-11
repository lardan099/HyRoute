//go:build windows

package main

import (
	"context"
	"os"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

// The panel: a small window by the tray icon with what is changed most
// often (connect, the main server, the rule profile, the DPI bypass) and
// a way into the main window. It is the window process once more
// (HyRoute.exe --window … --window-panel) with the same page bundle, which
// mounts Panel.svelte for it (Bridge.Mode), and a winHost of its own in
// the main process, so the panel and the main window may be open
// together. A left click on the tray icon opens it and closes it; it also
// goes when the user turns to another window, as a menu does.

// panelTitle is the panel's window title: how its own process finds it.
const panelTitle = "HyRoute · панель"

// The panel's size (Wails scales it by the screen's DPI).
const (
	panelWidth  = 340
	panelHeight = 452
	panelMargin = 12 // from the edges of the work area, in pixels
)

// ---- the main process ----

// panelReopen: a click on the tray icon while the panel is open takes the
// foreground from it, and the panel closes by itself before the click
// arrives here: within this time of its going the click is the one that
// closed it, not one to open it again.
const panelReopen = 600 * time.Millisecond

// showPanel is the left click on the tray icon: the panel opens, or goes
// if it is open. Without a panel (it did not start) the main window opens
// instead, as it did before the panel.
func (g *GUI) showPanel() {
	h := g.panel
	if h == nil || h.exe == "" {
		g.showWindow()
		return
	}
	h.mu.Lock()
	if h.peer != nil {
		h.mu.Unlock()
		go h.close()
		return
	}
	if time.Since(h.goneAt) < panelReopen {
		h.mu.Unlock()
		return
	}
	err := h.startLocked("normal")
	h.mu.Unlock()
	if err != nil {
		g.ctl.Log.Error("the panel did not open: opening the window", "err", err)
		g.showWindow()
	}
}

// PanelOpenWindow is the panel's «Открыть HyRoute»: the main window comes
// up and the panel goes.
func (g *GUI) PanelOpenWindow() {
	g.showWindow()
	go g.panel.close()
}

// PanelQuit is the panel's «Выход».
func (g *GUI) PanelQuit() { g.quit() }

// ---- the panel's process ----

var (
	procFindWindow          = user32.NewProc("FindWindowW")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procMonitorFromPoint    = user32.NewProc("MonitorFromPoint")
	procGetMonitorInfo      = user32.NewProc("GetMonitorInfoW")
	procGetWindowRect       = user32.NewProc("GetWindowRect")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
	procGetWindowLongPtr    = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr    = user32.NewProc("SetWindowLongPtrW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
)

type winRect struct{ Left, Top, Right, Bottom int32 }

type winPoint struct{ X, Y int32 }

type monitorInfo struct {
	Size    uint32
	Monitor winRect
	Work    winRect
	Flags   uint32
}

// panelWindow is the panel's own top-level window (0: not made yet).
func panelWindow() windows.HWND {
	t, _ := windows.UTF16PtrFromString(panelTitle)
	h, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(t)))
	if h == 0 {
		return 0
	}
	var pid uint32
	windows.GetWindowThreadProcessId(windows.HWND(h), &pid)
	if pid != uint32(os.Getpid()) {
		return 0
	}
	return windows.HWND(h)
}

// panelCorner is where a window of size w×h goes in the work area: the
// corner nearest the pointer (the tray icon just clicked), a margin in.
// The taskbar may be at any edge of the screen: the work area is what is
// left of it.
func panelCorner(work winRect, pt winPoint, w, h int32) (x, y int32) {
	x, y = work.Right-w-panelMargin, work.Bottom-h-panelMargin
	if pt.X < (work.Left+work.Right)/2 {
		x = work.Left + panelMargin
	}
	if pt.Y < (work.Top+work.Bottom)/2 {
		y = work.Top + panelMargin
	}
	// A work area smaller than the panel: its top left stays in sight.
	return max(x, work.Left), max(y, work.Top)
}

// placePanel puts the hidden panel by the tray icon, on top of other
// windows and out of the taskbar. false: the window was not found, and
// stays where Wails put it.
func placePanel() bool {
	hwnd := panelWindow()
	if hwnd == 0 {
		return false
	}
	const (
		gwlExStyle     = ^uintptr(19) // -20
		wsExToolWindow = 0x00000080
		wsExAppWindow  = 0x00040000
		swpNoSize      = 0x0001
		swpNoActivate  = 0x0010
		hwndTopmost    = ^uintptr(0) // -1
	)
	ex, _, _ := procGetWindowLongPtr.Call(uintptr(hwnd), gwlExStyle)
	procSetWindowLongPtr.Call(uintptr(hwnd), gwlExStyle, (ex|wsExToolWindow)&^wsExAppWindow)

	var pt winPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// MonitorFromPoint takes the POINT by value: both halves in one word.
	mon, _, _ := procMonitorFromPoint.Call(uintptr(uint32(pt.X))|uintptr(uint32(pt.Y))<<32, 2) // MONITOR_DEFAULTTONEAREST
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	var wr winRect
	if r, _, _ := procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return false
	}
	if r, _, _ := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&wr))); r == 0 {
		return false
	}
	x, y := panelCorner(mi.Work, pt, wr.Right-wr.Left, wr.Bottom-wr.Top)
	procSetWindowPos.Call(uintptr(hwnd), hwndTopmost, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoActivate)
	return true
}

// watchPanel closes the panel once the user turns to another window, as
// a menu closes. Until the panel has had the foreground it only asks for
// it: Windows may keep a window started by another process in the
// background, and a panel that never came forward must not vanish.
func (b *Bridge) watchPanel(ctx context.Context) {
	hwnd := panelWindow()
	me := uint32(os.Getpid())
	had := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.peer.Done():
			return
		case <-time.After(150 * time.Millisecond):
		}
		var pid uint32
		if fg := windows.GetForegroundWindow(); fg != 0 {
			windows.GetWindowThreadProcessId(fg, &pid)
		}
		switch {
		case pid == me:
			had = true
		case had:
			b.closing.Store(true)
			runtime.Quit(ctx)
			return
		case hwnd != 0:
			procSetForegroundWindow.Call(uintptr(hwnd))
		}
	}
}

// Mode tells the page what it is the page of: "panel" or "window".
func (b *Bridge) Mode() string {
	if b.panel {
		return "panel"
	}
	return "window"
}

// ClosePanel closes the panel (Esc, or after an action that ends it).
func (b *Bridge) ClosePanel() {
	if ctx := b.context(); ctx != nil && b.panel {
		b.closing.Store(true)
		runtime.Quit(ctx)
	}
}
