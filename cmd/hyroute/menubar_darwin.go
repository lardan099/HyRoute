//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// The icon's process has no Dock icon and no menu of its own.
static void hyrouteAccessory(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	});
}
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"fyne.io/systray"

	buildfiles "github.com/lardan099/hyroute/build"
	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/uirpc"
)

// The menu bar icon (HyRoute --menubar): a process of the signed-in user,
// started at login by a launch agent, with what the Windows tray has: the
// state, «Подключить»/«Отключить», the rule profiles, «Открыть HyRoute».
// It talks to the service over its socket, as the window does.
type menubar struct {
	mu     sync.Mutex
	peer   *uirpc.Peer
	on     bool
	shown  string // the state text shown
	status *systray.MenuItem
	toggle *systray.MenuItem
	rs     *systray.MenuItem
	slots  []*systray.MenuItem
	ids    []string // the profile of each slot
	rsSig  string
	// The «Сервер» submenu (trayservers.go), as the profiles' one.
	srv      *systray.MenuItem
	srvSlots []*systray.MenuItem
	srvIDs   []string // the server or group of each slot
	srvSig   string
	wake     chan struct{}
}

func runMenubar() {
	m := &menubar{wake: make(chan struct{}, 1)}
	systray.Run(m.ready, nil)
}

var menubarIcons = sync.OnceValues(func() (template, on []byte) {
	src, err := png.Decode(bytes.NewReader(buildfiles.Icon))
	if err != nil {
		return nil, nil
	}
	on = scale(src, 36, false)
	// A template icon is black with the icon's alpha: macOS draws it in
	// the menu bar's colour.
	b := src.Bounds()
	t := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA()
			t.SetNRGBA(x, y, color.NRGBA{A: uint8(a >> 8)})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, t)
	tsrc, _ := png.Decode(bytes.NewReader(buf.Bytes()))
	return scale(tsrc, 36, false), on
})

func (m *menubar) ready() {
	C.hyrouteAccessory()
	tmpl, _ := menubarIcons()
	systray.SetTemplateIcon(tmpl, tmpl)
	systray.SetTooltip("HyRoute")
	open := systray.AddMenuItem("Открыть HyRoute", "")
	systray.AddSeparator()
	m.status = systray.AddMenuItem("Подключение к службе…", "")
	m.status.Disable()
	m.toggle = systray.AddMenuItem("Подключить", "")
	m.toggle.Disable()
	m.srv = systray.AddMenuItem("Сервер", "")
	for range trayServersMax {
		it := m.srv.AddSubMenuItemCheckbox("", "", false)
		it.Hide()
		m.srvSlots = append(m.srvSlots, it)
	}
	m.srvIDs = make([]string, len(m.srvSlots))
	m.srv.Hide()
	m.rs = systray.AddMenuItem("Профиль правил", "")
	for range trayRulesetsMax {
		it := m.rs.AddSubMenuItemCheckbox("", "", false)
		it.Hide()
		m.slots = append(m.slots, it)
	}
	m.ids = make([]string, len(m.slots))
	m.rs.Hide()
	systray.AddSeparator()
	quit := systray.AddMenuItem("Скрыть значок", "")
	go func() {
		for {
			select {
			case <-open.ClickedCh:
				openWindow()
			case <-m.toggle.ClickedCh:
				go m.doToggle()
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
	for i, it := range m.slots {
		go func() {
			for range it.ClickedCh {
				m.mu.Lock()
				id := m.ids[i]
				m.mu.Unlock()
				if id != "" {
					go m.call("SwitchRulesetFromTray", id)
				}
			}
		}()
	}
	for i, it := range m.srvSlots {
		go func() {
			for range it.ClickedCh {
				m.mu.Lock()
				id := m.srvIDs[i]
				m.mu.Unlock()
				if id != "" {
					go m.setMain(id)
				}
			}
		}()
	}
	go m.connectLoop()
	go m.refreshLoop()
}

// openWindow starts HyRoute.app (or brings its window up).
func openWindow() {
	exec.Command("/usr/bin/open", "-b", "com.hyroute.app").Run()
}

func (m *menubar) connectLoop() {
	for {
		c, err := net.Dial("unix", sockPath)
		if err != nil {
			m.setText("Служба HyRoute не запущена", false, false)
			time.Sleep(3 * time.Second)
			continue
		}
		p := uirpc.New(c, c)
		var refused atomic.Bool
		p.OnEvent = func(name string, args []json.RawMessage) {
			switch name {
			case "status", "settings":
				m.kick()
			case "menubar.openWindow":
				openWindow()
			case "service.updated":
				// The service restarts with a new version: so does the icon,
				// from the service's (new) copy.
				go func() {
					time.Sleep(5 * time.Second)
					exe := serviceDir + "/HyRoute"
					syscall.Exec(exe, []string{exe, "--menubar"}, os.Environ())
				}()
			case "refused":
				refused.Store(true)
			}
		}
		go p.Run()
		p.Notify("client.menubar")
		m.mu.Lock()
		m.peer = p
		m.mu.Unlock()
		m.kick()
		<-p.Done()
		m.mu.Lock()
		m.peer = nil
		m.mu.Unlock()
		if refused.Load() {
			m.setText("Нет прав: HyRoute управляют администраторы", false, false)
			return
		}
		m.setText("Служба HyRoute не отвечает", false, false)
		time.Sleep(2 * time.Second)
	}
}

func (m *menubar) kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// refreshLoop redraws on every event, and every 5 seconds in case one was
// missed.
func (m *menubar) refreshLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.wake:
		case <-t.C:
		}
		m.refresh()
	}
}

func (m *menubar) call(method string, args ...any) (json.RawMessage, error) {
	m.mu.Lock()
	p := m.peer
	m.mu.Unlock()
	if p == nil {
		return nil, errNoService
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return p.Call(ctx, method, args...)
}

var errNoService = errors.New("нет связи со службой HyRoute")

func (m *menubar) refresh() {
	r, err := m.call("Status")
	if err != nil {
		return
	}
	var st app.Status
	if json.Unmarshal(r, &st) != nil {
		return
	}
	text, on := trayView(st)
	m.setText(text, on, true)
	if r, err := m.call("RulesetsBrief"); err == nil {
		var b app.RulesetsBrief
		if json.Unmarshal(r, &b) == nil {
			m.showRulesets(b)
		}
	}
	if r, err := m.call("ServersBrief"); err == nil {
		var b app.ServersBrief
		if json.Unmarshal(r, &b) == nil {
			m.showServers(b)
		}
	}
}

// setMain makes the clicked server the main one; the window says why when
// it cannot be.
func (m *menubar) setMain(id string) {
	if _, err := m.call("SetMainFromTray", id); err != nil {
		openWindow()
		return
	}
	m.refresh()
}

func (m *menubar) showServers(b app.ServersBrief) {
	visible, title, items, sig := trayServersView(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if sig == m.srvSig {
		return
	}
	m.srvSig = sig
	if !visible {
		m.srv.Hide()
		return
	}
	m.srv.SetTitle(strings.ReplaceAll(title, "&&", "&"))
	m.srv.Show()
	for i, it := range m.srvSlots {
		if i >= len(items) {
			m.srvIDs[i] = ""
			it.Hide()
			continue
		}
		m.srvIDs[i] = items[i].ID
		it.SetTitle(strings.ReplaceAll(items[i].Title, "&&", "&")) // trayMenuText doubles it for Windows
		if items[i].Checked {
			it.Check()
		} else {
			it.Uncheck()
		}
		if items[i].Disabled {
			it.Disable()
		} else {
			it.Enable()
		}
		it.Show()
	}
}

func (m *menubar) setText(text string, on, usable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == nil {
		return
	}
	if m.shown != text {
		m.status.SetTitle(text)
		systray.SetTooltip("HyRoute — " + text)
		m.shown = text
	}
	if on != m.on || !usable {
		_, iconOn := menubarIcons()
		tmpl, _ := menubarIcons()
		if on && usable {
			systray.SetIcon(iconOn)
		} else {
			systray.SetTemplateIcon(tmpl, tmpl)
		}
	}
	m.on = on && usable
	if !usable {
		m.toggle.Disable()
		return
	}
	m.toggle.Enable()
	if on {
		m.toggle.SetTitle("Отключить")
	} else {
		m.toggle.SetTitle("Подключить")
	}
}

func (m *menubar) showRulesets(b app.RulesetsBrief) {
	visible, title, items, sig := trayRulesetsView(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if sig == m.rsSig {
		return
	}
	m.rsSig = sig
	if !visible {
		m.rs.Hide()
		return
	}
	m.rs.SetTitle(title)
	m.rs.Show()
	for i, it := range m.slots {
		if i >= len(items) {
			m.ids[i] = ""
			it.Hide()
			continue
		}
		m.ids[i] = items[i].ID
		it.SetTitle(strings.ReplaceAll(items[i].Title, "&&", "&")) // trayMenuText doubles it for Windows
		if items[i].Checked {
			it.Check()
		} else {
			it.Uncheck()
		}
		if items[i].Disabled {
			it.Disable()
		} else {
			it.Enable()
		}
		it.Show()
	}
}

// doToggle does what the item says now.
func (m *menubar) doToggle() {
	m.mu.Lock()
	on := m.on
	m.mu.Unlock()
	if on {
		m.call("Disconnect")
		return
	}
	if _, err := m.call("ConnectOrResume"); err != nil {
		openWindow()
	}
}
