//go:build windows

package main

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// The window out of sight. Wails only hides the window (tray) or lets
// Windows minimize it; WebView2 still takes the page for a visible one, so
// its timers run at full rate and an open «Соединения» keeps redrawing
// thousands of rows all day. Two things follow the window:
//
//   - the page: the "window" event (true: in sight) pauses its polling while
//     the window is hidden or minimized (frontend/src/poll.ts);
//   - WebView2, for a window hidden to the tray: IsVisible off (Chromium
//     treats the page as hidden: no drawing, throttled timers). A minimized
//     window keeps
//     IsVisible: HyRoute sees a restore only up to a second later, and a
//     WebView2 still invisible then shows an empty window.
//
// Not the memory target «low» (ICoreWebView2_19): go-webview2's webview2
// package panics in its init under Go 1.27 (NewCallback of a method with
// arguments wider than uintptr), and its vtables of the later interfaces
// leave out the inherited methods, so the call would hit another method.
//
// Wails v2 does not give out its WebView2: it is reached through the
// unexported fields of its Windows frontend (Wails is pinned in go.mod).
// When they are not found the page still pauses, WebView2 is left as is.
type webviewState struct {
	once     sync.Once
	chromium *edge.Chromium
	invoke   func(func())

	mu     sync.Mutex
	seen   int8 // the page: 0 not told yet, 1 in sight, -1 out of sight
	shown  int8 // WebView2 IsVisible: 0 not set yet, 1 on, -1 off
	ticker bool
	down   atomic.Bool // the window is closing: nothing more to tell
}

// webviewOf finds the WebView2 of the window behind ctx (Wails' runtime
// keeps its frontend there).
func webviewOf(ctx context.Context) (*edge.Chromium, func(func())) {
	fe := reflect.ValueOf(ctx.Value("frontend"))
	if fe.Kind() != reflect.Pointer || fe.IsNil() || fe.Elem().Kind() != reflect.Struct {
		return nil, nil
	}
	s := fe.Elem()
	ch := s.FieldByName("chromium")
	if !ch.IsValid() || ch.Type() != reflect.TypeFor[*edge.Chromium]() {
		return nil, nil
	}
	chromium := *(**edge.Chromium)(unsafe.Pointer(ch.UnsafeAddr()))
	mw := s.FieldByName("mainWindow")
	if chromium == nil || !mw.IsValid() || mw.Kind() != reflect.Pointer {
		return nil, nil
	}
	w := reflect.NewAt(mw.Type(), unsafe.Pointer(mw.UnsafeAddr())).Elem()
	if w.IsNil() {
		return nil, nil
	}
	// Invoke runs a function on the window's thread: WebView2 is a COM
	// object of that thread.
	inv, ok := w.MethodByName("Invoke").Interface().(func(func()))
	if !ok {
		return nil, nil
	}
	return chromium, inv
}

// syncWindow tells the page and WebView2 whether the window is in sight.
// It runs when HyRoute hides or shows the window and every second for a
// minimize or restore, which Wails does not report.
func (g *GUI) syncWindow() {
	ctx := g.context()
	if ctx == nil || !g.uiUp.Load() || g.web.down.Load() {
		return // before domReady: no page to tell yet, domReady syncs
	}
	w := &g.web
	w.once.Do(func() {
		w.chromium, w.invoke = webviewOf(ctx)
		if w.chromium == nil {
			g.ctl.Log.Warn("WebView2 not found: a window hidden to the tray only pauses the page")
		}
	})
	hidden := g.tray.hidden.Load()
	seen := !hidden && !runtime.WindowIsMinimised(ctx)

	w.mu.Lock()
	defer w.mu.Unlock()
	if v := sign(seen); w.seen != v {
		w.seen = v
		runtime.EventsEmit(ctx, "window", seen)
	}
	if w.chromium == nil {
		return
	}
	if v := sign(!hidden); w.shown != v {
		w.shown = v
		chromium := w.chromium
		w.invoke(func() { setWebviewShown(chromium, !hidden) })
	}
}

func sign(b bool) int8 {
	if b {
		return 1
	}
	return -1
}

// setWebviewShown runs on the window's thread.
func setWebviewShown(c *edge.Chromium, on bool) {
	defer func() { recover() }() // a WebView2 going away with the window
	if c.GetController() == nil {
		return
	}
	if on {
		c.Show()
	} else {
		c.Hide()
	}
}

// watchWindow follows minimize and restore once the page is up.
func (g *GUI) watchWindow() {
	g.web.mu.Lock()
	started := g.web.ticker
	g.web.ticker = true
	g.web.mu.Unlock()
	if started {
		return
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			if g.web.down.Load() {
				return
			}
			g.syncWindow()
		}
	}()
}
