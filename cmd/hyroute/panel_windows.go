//go:build windows

package main

import (
	"context"
	"fmt"
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
// goes when the user turns to another window, as a menu does. It stands
// against the taskbar above the icon and is as tall as its content.

// panelTitle is the panel's window title: how its own process finds it.
const panelTitle = "HyRoute · панель"

// The panel's size (Wails scales it by the screen's DPI). Its height is
// the page's to say (Bridge.PanelFit); panelHeight is what the hidden
// window starts with.
const (
	panelWidth     = 340
	panelHeight    = 220
	panelMinHeight = 120
	panelMaxHeight = 640
	panelMargin    = 12 // from the taskbar and the edges of the work area, in pixels
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
	// Where the click was: the panel goes above the icon, wherever the
	// pointer is by the time its window is made.
	var pt winPoint
	if r, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt))); r != 0 {
		h.at = fmt.Sprintf("%d,%d", pt.X, pt.Y)
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
	procGetDpiForWindow     = user32.NewProc("GetDpiForWindow")
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

// panelPlace is where a panel of size w×h goes: against the taskbar,
// centred on at (the tray icon just clicked), a margin in from the edges
// of the work area. The taskbar is at the edge where the work area is
// smaller than the monitor; a hidden one leaves no such edge, and the
// panel goes to the corner of the work area nearest at.
func panelPlace(mon, work winRect, at winPoint, w, h int32) (x, y int32) {
	switch {
	case work.Bottom < mon.Bottom:
		x, y = at.X-w/2, work.Bottom-h-panelMargin
	case work.Top > mon.Top:
		x, y = at.X-w/2, work.Top+panelMargin
	case work.Left > mon.Left:
		x, y = work.Left+panelMargin, at.Y-h/2
	case work.Right < mon.Right:
		x, y = work.Right-w-panelMargin, at.Y-h/2
	default:
		x, y = work.Right-w-panelMargin, work.Bottom-h-panelMargin
		if at.X < (work.Left+work.Right)/2 {
			x = work.Left + panelMargin
		}
		if at.Y < (work.Top+work.Bottom)/2 {
			y = work.Top + panelMargin
		}
	}
	// Inside the work area; one smaller than the panel keeps its top left
	// in sight.
	x = max(min(x, work.Right-w-panelMargin), work.Left+panelMargin)
	y = max(min(y, work.Bottom-h-panelMargin), work.Top+panelMargin)
	return x, y
}

// placePanel puts the panel by the tray icon at at, h pixels tall (0: as
// tall as it is), on top of other windows and out of the taskbar. false:
// the window was not found, and stays where Wails put it.
func placePanel(at winPoint, h int32) bool {
	hwnd := panelWindow()
	if hwnd == 0 {
		return false
	}
	const (
		gwlExStyle     = ^uintptr(19) // -20
		wsExToolWindow = 0x00000080
		wsExAppWindow  = 0x00040000
		swpNoActivate  = 0x0010
		hwndTopmost    = ^uintptr(0) // -1
	)
	ex, _, _ := procGetWindowLongPtr.Call(uintptr(hwnd), gwlExStyle)
	if want := (ex | wsExToolWindow) &^ wsExAppWindow; want != ex {
		procSetWindowLongPtr.Call(uintptr(hwnd), gwlExStyle, want)
	}
	// MonitorFromPoint takes the POINT by value: both halves in one word.
	mon, _, _ := procMonitorFromPoint.Call(uintptr(uint32(at.X))|uintptr(uint32(at.Y))<<32, 2) // MONITOR_DEFAULTTONEAREST
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	var wr winRect
	if r, _, _ := procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return false
	}
	if r, _, _ := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&wr))); r == 0 {
		return false
	}
	w := wr.Right - wr.Left
	if h <= 0 {
		h = wr.Bottom - wr.Top
	}
	h = min(h, mi.Work.Bottom-mi.Work.Top-2*panelMargin)
	x, y := panelPlace(mi.Monitor, mi.Work, at, w, h)
	procSetWindowPos.Call(uintptr(hwnd), hwndTopmost, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpNoActivate)
	return true
}

// parsePanelAt reads "x,y" (--window-panel-at); without it the panel goes
// by where the pointer is now.
func parsePanelAt(s string) winPoint {
	var pt winPoint
	if n, err := fmt.Sscanf(s, "%d,%d", &pt.X, &pt.Y); err != nil || n != 2 {
		procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	}
	return pt
}

// PanelFit is the page saying how tall its content is, in CSS pixels: the
// panel becomes that tall, against the taskbar still, and with the first
// call it is shown (never empty, never with a blank strip under two rows).
func (b *Bridge) PanelFit(height int) {
	ctx := b.context()
	if !b.panel || ctx == nil {
		return
	}
	scale := 1.0
	if hwnd := panelWindow(); hwnd != 0 && procGetDpiForWindow.Find() == nil {
		if dpi, _, _ := procGetDpiForWindow.Call(uintptr(hwnd)); dpi > 0 {
			scale = float64(dpi) / 96
		}
	}
	height = max(panelMinHeight, min(height, panelMaxHeight))
	placePanel(b.panelAt, int32(float64(height)*scale+0.5))
	b.showPanelWindow(ctx)
}

// showPanelWindow shows the panel once and starts watching for the user
// turning away from it.
func (b *Bridge) showPanelWindow(ctx context.Context) {
	if b.panelShown.CompareAndSwap(false, true) {
		runtime.WindowShow(ctx)
		go b.watchPanel(ctx)
	}
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
