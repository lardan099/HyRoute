//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/uirpc"
)

// winHost is the main process's side of the window process
// (window_windows.go): it starts it when the window opens, passes calls
// both ways and hears when it is gone. At most one window process runs.
type winHost struct {
	g   *GUI
	exe string // HyRoute.exe; "" (tests): no window is ever started

	mu   sync.Mutex
	peer *uirpc.Peer
	pid  uint32
	geom string // where the last window was (windowGeom)
}

// errNoWindow: a call that needs the window came while it is closed.
var errNoWindow = errors.New("окно HyRoute закрыто")

// open shows the window, starting the window process if there is none.
// state: "normal" or "minimised" (only for a new window).
func (h *winHost) open(state string) {
	if h == nil || h.exe == "" {
		return
	}
	h.mu.Lock()
	if p := h.peer; p != nil {
		pid := h.pid
		h.mu.Unlock()
		// The tray click gave this process the foreground; the window's
		// process may take it.
		procAllowSetForegroundWindow.Call(uintptr(pid))
		go p.Call(context.Background(), "show")
		return
	}
	defer h.mu.Unlock()
	if err := h.startLocked(state); err != nil {
		h.g.ctl.Log.Error("the window did not open", "err", err)
		messageBox("HyRoute", "Окно HyRoute не открылось: "+err.Error())
	}
}

func (h *winHost) startLocked(state string) error {
	// Two pipes: HyRoute → window and window → HyRoute. The window's ends
	// are inherited by it alone (Go lists the handles a child inherits).
	toWinR, toWinW, err := os.Pipe()
	if err != nil {
		return err
	}
	fromWinR, fromWinW, err := os.Pipe()
	if err != nil {
		toWinR.Close()
		toWinW.Close()
		return err
	}
	closeAll := func() {
		for _, f := range []*os.File{toWinR, toWinW, fromWinR, fromWinW} {
			f.Close()
		}
	}
	for _, f := range []*os.File{toWinR, fromWinW} {
		if err := windows.SetHandleInformation(windows.Handle(f.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			closeAll()
			return err
		}
	}
	args := []string{"--window", fmt.Sprintf("%d,%d", toWinR.Fd(), fromWinW.Fd()), "--window-state", state}
	if h.geom != "" {
		args = append(args, "--window-geom", h.geom)
	}
	cmd := exec.Command(h.exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(toWinR.Fd()), syscall.Handle(fromWinW.Fd())},
	}
	// The click that opens the window gave this process the foreground:
	// the window it starts may take it.
	procAllowSetForegroundWindow.Call(asfwAny)
	if err := cmd.Start(); err != nil {
		closeAll()
		return err
	}
	// The window's ends are its own now: closed here, so that its exit
	// ends the connection.
	toWinR.Close()
	fromWinW.Close()
	peer := uirpc.New(fromWinR, toWinW)
	peer.OnCall = h.answer
	h.peer, h.pid = peer, uint32(cmd.Process.Pid)
	h.g.ctl.Log.Debug("window opened", "pid", h.pid)
	go func() {
		peer.Run()
		fromWinR.Close()
		toWinW.Close()
		cmd.Wait()
		h.mu.Lock()
		if h.peer == peer {
			h.peer, h.pid = nil, 0
		}
		h.mu.Unlock()
		h.g.ctl.Log.Debug("window closed")
	}()
	return nil
}

// isOpen: a window process runs.
func (h *winHost) isOpen() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peer != nil
}

func (h *winHost) current() *uirpc.Peer {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peer
}

// call asks the window for something only it can do.
func (h *winHost) call(method string, args ...any) (json.RawMessage, error) {
	p := h.current()
	if p == nil {
		return nil, errNoWindow
	}
	r, err := p.Call(context.Background(), method, args...)
	if errors.Is(err, uirpc.ErrClosed) {
		return nil, errNoWindow
	}
	return r, err
}

// notify sends the page an event (dropped while the window is closed: it
// reads everything anew when it opens).
func (h *winHost) notify(name string, args ...any) {
	if p := h.current(); p != nil {
		p.Notify(name, args...)
	}
}

// close closes the window and waits a little for it to go (HyRoute's
// exit).
func (h *winHost) close() {
	p := h.current()
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Call(ctx, "close")
	select {
	case <-p.Done():
	case <-ctx.Done():
	}
}

// answer serves the window's calls: the page's calls of GUI methods, and
// the window's own («window.» …).
func (h *winHost) answer(method string, args []json.RawMessage) (any, error) {
	if !strings.HasPrefix(method, "window.") {
		return h.g.dispatch(method, args)
	}
	switch method {
	case "window.ready":
		h.g.uiUp.Store(true)
		h.g.signalHealthy()
		return nil, nil
	case "window.beforeClose":
		return h.g.closeAction(), nil
	case "window.geometry":
		var s string
		if len(args) > 0 && json.Unmarshal(args[0], &s) == nil {
			h.mu.Lock()
			h.geom = nextGeom(h.geom, s)
			h.mu.Unlock()
		}
		return nil, nil
	}
	return nil, fmt.Errorf("HyRoute не знает вызова окна %q", method)
}

// nextGeom is the place of the next window after one closed at closed. A
// maximized window keeps the place it had before it was maximized: a
// window opened maximized and then restored goes back there, not to the
// size of the screen.
func nextGeom(prev, closed string) string {
	c, ok := parseGeom(closed)
	if !ok {
		return prev
	}
	if p, ok := parseGeom(prev); ok && c.Max {
		p.Max = true
		return p.String()
	}
	return c.String()
}

// ---- what GUI asks of the window ----

func (h *winHost) clipboardGet() (string, error) {
	r, err := h.call("clipboard.get")
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}

func (h *winHost) clipboardSet(text string) error {
	_, err := h.call("clipboard.set", text)
	return err
}

func (h *winHost) openFile(o runtime.OpenDialogOptions) (string, error) {
	r, err := h.call("dialog.open", o)
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}

func (h *winHost) saveFile(o runtime.SaveDialogOptions) (string, error) {
	r, err := h.call("dialog.save", o)
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}
