//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailswin "github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/frontend"
	"github.com/lardan099/hyroute/internal/uirpc"
)

// The window process: HyRoute.exe --window. The main process starts it
// when the window opens and it exits when the window closes, so WebView2
// and its processes are gone while HyRoute sits in the tray (they held
// some 200 MB). It holds nothing but the window: every call of the page
// goes to the main process (Bridge.Call), which answers with the methods
// of GUI as Wails bound them before; the main process in turn asks this
// one for what needs the window (file dialogs, the clipboard, showing it)
// and sends the events of the page.

// Bridge is bound to the page: window.go.main.Bridge (frontend/src/api.ts).
type Bridge struct {
	peer    *uirpc.Peer
	ctx     atomic.Pointer[context.Context]
	unsaved atomic.Int32
	closing atomic.Bool // the close is decided: OnBeforeClose lets it through
}

// Call runs a method of GUI in the main process for the page.
func (b *Bridge) Call(method string, args []json.RawMessage) (json.RawMessage, error) {
	r, err := b.peer.CallRaw(context.Background(), method, args)
	if errors.Is(err, uirpc.ErrClosed) {
		return nil, errors.New("нет связи с HyRoute: он закрылся")
	}
	return r, err
}

// SetUnsaved is the page's number of unsaved edits: closing the window
// asks about them first.
func (b *Bridge) SetUnsaved(n int) { b.unsaved.Store(int32(n)) }

func (b *Bridge) context() context.Context {
	if p := b.ctx.Load(); p != nil {
		return *p
	}
	return nil
}

// windowGeom is the window's place and size, kept by the main process
// from one window to the next.
type windowGeom struct {
	X, Y, W, H int
	Max        bool
}

func (g windowGeom) String() string {
	return fmt.Sprintf("%d,%d,%d,%d,%t", g.X, g.Y, g.W, g.H, g.Max)
}

func parseGeom(s string) (windowGeom, bool) {
	p := strings.Split(s, ",")
	if len(p) != 5 {
		return windowGeom{}, false
	}
	var g windowGeom
	var err error
	for i, dst := range []*int{&g.X, &g.Y, &g.W, &g.H} {
		if *dst, err = strconv.Atoi(p[i]); err != nil {
			return windowGeom{}, false
		}
	}
	g.Max = p[4] == "true"
	// A window smaller than the minimum or larger than any screen is not
	// one HyRoute saved.
	if g.W < 900 || g.H < 560 || g.W > 16384 || g.H > 16384 {
		return windowGeom{}, false
	}
	return g, true
}

// runWindow is the window process. pipes is "<read handle>,<write handle>":
// the ends of the two pipes the main process made for it.
func runWindow(pipes, state, geom string) {
	var rh, wh uintptr
	if _, err := fmt.Sscanf(pipes, "%d,%d", &rh, &wh); err != nil || rh == 0 || wh == 0 {
		messageBox("HyRoute", "Окно HyRoute запускает сам HyRoute.")
		os.Exit(2)
	}
	in, out := os.NewFile(rh, "from-hyroute"), os.NewFile(wh, "to-hyroute")
	peer := uirpc.New(in, out)
	b := &Bridge{peer: peer}
	peer.OnCall = b.answer
	peer.OnEvent = func(name string, args []json.RawMessage) {
		ctx := b.context()
		if ctx == nil {
			return
		}
		data := make([]any, len(args))
		for i, a := range args {
			json.Unmarshal(a, &data[i])
		}
		runtime.EventsEmit(ctx, name, data...)
	}
	go func() {
		peer.Run()
		// HyRoute is gone (it exited or crashed): the window goes with it.
		b.closing.Store(true)
		if ctx := b.context(); ctx != nil {
			runtime.Quit(ctx)
		}
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}()

	g, haveGeom := parseGeom(geom)
	width, height := 1180, 760
	if haveGeom {
		width, height = g.W, g.H
	}
	startState := options.Normal
	if state == "minimised" {
		startState = options.Minimised
	}
	webviewDir, err := webviewDataDir()
	if err != nil {
		fatalBox(err)
	}
	err = wails.Run(&options.App{
		Title:            "HyRoute",
		WindowStartState: startState,
		// Placed first, then shown: no jump from the middle of the screen.
		StartHidden:      haveGeom && startState == options.Normal,
		Width:            width,
		Height:           height,
		MinWidth:         900,
		MinHeight:        560,
		BackgroundColour: &options.RGBA{R: 24, G: 26, B: 31, A: 255},
		AssetServer:      &assetserver.Options{Assets: frontend.Dist},
		LogLevel:         logger.ERROR,
		OnStartup: func(ctx context.Context) {
			b.ctx.Store(&ctx)
			if haveGeom && startState == options.Normal {
				runtime.WindowSetPosition(ctx, g.X, g.Y)
				if g.Max {
					runtime.WindowMaximise(ctx)
				}
				runtime.WindowShow(ctx)
			}
		},
		OnDomReady: func(ctx context.Context) {
			peer.Notify("window.ready")
			go b.watchMinimised(ctx)
		},
		OnBeforeClose: b.beforeClose,
		Bind:          []any{b},
		Windows: &wailswin.Options{
			Theme:               wailswin.SystemDefault,
			WebviewUserDataPath: webviewDir,
		},
	})
	if err != nil {
		fatalBox(err)
	}
	os.Exit(0)
}

// answer serves the main process's calls: what needs the window.
func (b *Bridge) answer(method string, args []json.RawMessage) (any, error) {
	ctx := b.context()
	if ctx == nil {
		return nil, errors.New("окно ещё открывается")
	}
	arg := func(i int, v any) error {
		if i >= len(args) {
			return fmt.Errorf("%s: нет аргумента %d", method, i+1)
		}
		return json.Unmarshal(args[i], v)
	}
	switch method {
	case "show":
		runtime.WindowShow(ctx)
		return nil, nil
	case "minimise":
		runtime.WindowMinimise(ctx)
		return nil, nil
	case "close":
		b.closing.Store(true)
		runtime.Quit(ctx)
		return nil, nil
	case "clipboard.get":
		return runtime.ClipboardGetText(ctx)
	case "clipboard.set":
		var s string
		if err := arg(0, &s); err != nil {
			return nil, err
		}
		return nil, runtime.ClipboardSetText(ctx, s)
	case "dialog.open":
		var o runtime.OpenDialogOptions
		if err := arg(0, &o); err != nil {
			return nil, err
		}
		return runtime.OpenFileDialog(ctx, o)
	case "dialog.save":
		var o runtime.SaveDialogOptions
		if err := arg(0, &o); err != nil {
			return nil, err
		}
		return runtime.SaveFileDialog(ctx, o)
	}
	return nil, fmt.Errorf("окно не знает вызова %q", method)
}

// beforeClose: the close button. Unsaved edits are asked about; then the
// main process says what closing means now: the window goes (HyRoute
// stays in the tray), HyRoute exits («Кнопка × сворачивает в трей» off),
// or, while the tray icon is not up, the window is only minimized.
func (b *Bridge) beforeClose(ctx context.Context) bool {
	if b.closing.Load() {
		return false
	}
	if n := b.unsaved.Load(); n > 0 && !confirmBox("HyRoute", "Есть несохранённые изменения. Закрыть окно и потерять их?") {
		return true
	}
	what := "close"
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r, err := b.peer.Call(c, "window.beforeClose"); err == nil {
		json.Unmarshal(r, &what)
	}
	if what == "minimise" {
		runtime.WindowMinimise(ctx)
		return true
	}
	if !runtime.WindowIsMinimised(ctx) {
		x, y := runtime.WindowGetPosition(ctx)
		max := runtime.WindowIsMaximised(ctx)
		w, h := runtime.WindowGetSize(ctx)
		b.peer.Notify("window.geometry", windowGeom{X: x, Y: y, W: w, H: h, Max: max}.String())
	}
	b.closing.Store(true)
	return false
}

// watchMinimised tells the page when the window is minimized or back:
// its polling stops meanwhile (frontend/src/poll.ts). Wails does not
// report it, so it is looked at every second.
func (b *Bridge) watchMinimised(ctx context.Context) {
	seen := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.peer.Done():
			return
		case <-time.After(time.Second):
		}
		if now := !runtime.WindowIsMinimised(ctx); now != seen {
			seen = now
			runtime.EventsEmit(ctx, "window", seen)
		}
	}
}

func confirmBox(title, text string) bool {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	r, _ := windows.MessageBox(0, m, t, windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_TOPMOST)
	return r == 6 // IDYES
}
