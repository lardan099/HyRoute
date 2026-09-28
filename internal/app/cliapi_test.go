package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

func TestConnectOrResume(t *testing.T) {
	c, started := newCtl(t)
	c.ImportURIs(link)
	already, err := c.ConnectOrResume()
	if err != nil || already || len(*started) != 1 {
		t.Fatal(already, err, len(*started))
	}
	if already, err := c.ConnectOrResume(); err != nil || !already || len(*started) != 1 {
		t.Fatal("a running session must be left alone", already, err)
	}
	// An engine that failed: reconnected, not left alone.
	(*started)[0].failed.Store(true)
	if already, err := c.ConnectOrResume(); err != nil || already || len(*started) != 2 {
		t.Fatal(already, err, len(*started))
	}
	c.Disconnect()
}

func TestShutdownRefusesConnect(t *testing.T) {
	c, started := newCtl(t)
	c.Shutdown()
	for name, f := range map[string]func() error{
		"Connect": c.Connect, "Reconnect": c.Reconnect,
		"ConnectOrResume": func() error { _, err := c.ConnectOrResume(); return err },
	} {
		if err := f(); !errors.Is(err, errClosing) || err.Error() != "HyRoute завершает работу" {
			t.Errorf("%s after Shutdown: %v", name, err)
		}
	}
	if len(*started) != 0 {
		t.Fatal("a session started after Shutdown")
	}

	// A Connect waiting for lifeMu while Shutdown runs gets the same error.
	c2, started2 := newCtl(t)
	c2.lifeMu.Lock()
	done := make(chan error)
	go func() { done <- c2.Connect() }()
	time.Sleep(20 * time.Millisecond)
	shut := make(chan struct{})
	go func() { c2.Shutdown(); close(shut) }()
	time.Sleep(20 * time.Millisecond)
	c2.lifeMu.Unlock()
	err := <-done
	<-shut
	if !errors.Is(err, errClosing) {
		// The Connect may have taken lifeMu first: then Shutdown stopped it.
		if err != nil || c2.Status().State != "disconnected" {
			t.Fatal(err, c2.Status().State)
		}
	}
	_ = started2
}

func TestBeginExit(t *testing.T) {
	c, started := newCtl(t)
	undo := c.BeginExit()
	if err := c.Connect(); !errors.Is(err, errClosing) {
		t.Fatal(err)
	}
	undo()
	if err := c.Connect(); err != nil || len(*started) != 1 {
		t.Fatal(err)
	}
	undo2 := c.BeginExit()
	c.Shutdown()
	undo2()
	if err := c.Connect(); !errors.Is(err, errClosing) {
		t.Fatal("undo after Shutdown must not let connects through:", err)
	}
}

// The network rules' connects (a rule, «Подключаться сразу после
// запуска», a restore) start nothing while HyRoute exits either.
func TestBeginExitStopsNetworkConnects(t *testing.T) {
	c, started := newCtl(t)
	c.ImportURIs(link)
	undo := c.BeginExit()
	if err := c.ConnectAtStart("test"); err != nil {
		t.Fatal(err)
	}
	c.lifeMu.Lock()
	done, err := c.netConnectLocked(false)
	c.lifeMu.Unlock()
	if done || err != nil || len(*started) != 0 {
		t.Fatal(done, err, len(*started))
	}
	undo()
	c.lifeMu.Lock()
	done, err = c.netConnectLocked(false)
	c.lifeMu.Unlock()
	if !done || err != nil || len(*started) != 1 {
		t.Fatal(done, err, len(*started))
	}
	c.Disconnect()
}

func TestLogsTail(t *testing.T) {
	c, _ := newCtl(t)
	if got := c.LogsTail("hysteria", 5); got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
	for i := 0; i < 20; i++ {
		c.HysteriaLog.Add(time.Now(), "info", fmt.Sprint(i))
	}
	got := c.LogsTail("hysteria", 3)
	if len(got) != 3 || got[0].Msg != "17" || got[2].Msg != "19" {
		t.Fatalf("%v", got)
	}
	if n := len(c.LogsTail("hysteria", 1<<20)); n != 20 {
		t.Fatal(n)
	}
	if n := len(c.LogsTail("hysteria", -1)); n != 0 {
		t.Fatal(n)
	}
	c.profileJournal("abc").Add(time.Now(), "warn", "x")
	if got := c.LogsTail("hysteria:abc", 10); len(got) != 1 || got[0].Msg != "x" {
		t.Fatalf("%v", got)
	}
}

func TestUpdatePrefs(t *testing.T) {
	c, _ := newCtl(t)
	var wg sync.WaitGroup
	const rounds = 100
	for i := 0; i < rounds; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); c.SkipAppVersion(fmt.Sprint("v", i)) }()
		go func() {
			defer wg.Done()
			c.SetGeoPrefs("custom", fmt.Sprintf("https://example.com/%d/geosite.dat", i), "", true, 12)
		}()
		go func() { defer wg.Done(); c.UpdatePrefs(func(p *store.Prefs) error { p.CLI = "full"; return nil }) }()
		go func() {
			// As GUI.SavePrefs: the page's fields over the current ones.
			defer wg.Done()
			c.UpdatePrefs(func(p *store.Prefs) error { p.AutoConnect = true; p.LogKeep = 7; return nil })
		}()
	}
	wg.Wait()
	p := c.Prefs()
	if p.SkipVersion == "" || p.GeoSource != "custom" || p.CLI != "full" || !p.AutoConnect || p.LogKeep != 7 {
		t.Fatalf("a field was lost: %+v", p)
	}
	disk, err := c.Store.LoadPrefs()
	if err != nil || disk.CLI != "full" || disk.GeoSource != "custom" || !disk.AutoConnect || disk.SkipVersion != p.SkipVersion {
		t.Fatalf("%+v %v", disk, err)
	}
	// Broken prefs.json: every write is refused.
	c.mu.Lock()
	c.prefsBroken = errors.New("prefs.json: bad")
	c.mu.Unlock()
	if err := c.UpdatePrefs(func(p *store.Prefs) error { p.CLI = "off"; return nil }); err == nil || !strings.Contains(err.Error(), "prefs.json не загружен") {
		t.Fatal(err)
	}
	if err := c.SkipAppVersion("v9"); err == nil {
		t.Fatal("saved while broken")
	}
}

func TestCLIModeBrokenPrefs(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	os.WriteFile(filepath.Join(dir, "prefs.json"), []byte("{"), 0o600)
	c, _ := newCtlAtLoadErr(t, st)
	if c.Prefs().CLI != "" {
		t.Fatal(c.Prefs())
	}
	if mode, err := c.CLIMode(); mode != "off" || err == nil {
		t.Fatal(mode, err)
	}
	os.WriteFile(filepath.Join(dir, "prefs.json"), []byte(`{"cli":"full"}`), 0o600)
	c.Load()
	if mode, err := c.CLIMode(); mode != "full" || err != nil {
		t.Fatal(mode, err)
	}
	os.WriteFile(filepath.Join(dir, "prefs.json"), []byte(`{}`), 0o600)
	c.Load()
	if mode, err := c.CLIMode(); mode != "read" || err != nil {
		t.Fatal("unset must be read-only:", mode, err)
	}
}

// newCtlAtLoadErr is newCtlAt for a data folder with a broken file.
func newCtlAtLoadErr(t *testing.T, st *store.Store) (*Controller, error) {
	t.Helper()
	c := New(st, nil, session.Config{}, slog.LevelInfo)
	noDNS(c, "")
	return c, c.Load()
}

func TestSanitizeFunc(t *testing.T) {
	c, _ := newCtl(t)
	c.ImportURIs(link)
	s := "connect to example.com 8.8.8.8 https://a.example.org/x"
	if got, want := c.SanitizeFunc()(s), c.Sanitize(s); got != want || got == s {
		t.Fatalf("%q %q", got, want)
	}
}

func TestResolveByName(t *testing.T) {
	names := []string{"Панель", "Панель 2", "Work"}
	for q, want := range map[string]int{"панель": 0, " WORK ": 2, "2": 1, "or": 2} {
		if i, err := resolveByName(names, q, "подписка"); err != nil || i != want {
			t.Errorf("%q: %d %v", q, i, err)
		}
	}
	if _, err := resolveByName(names, "нет", "подписка"); err == nil || err.Error() != "не найдено: подписка «нет»" {
		t.Error(err)
	}
	if _, err := resolveByName(names, "ан", "подписка"); err == nil || !strings.Contains(err.Error(), "«Панель», «Панель 2» — уточните") {
		t.Error(err)
	}
}
