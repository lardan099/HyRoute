package app

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

// brokenSettingsCtl has a settings.json that does not load; it counts
// session starts.
func brokenSettingsCtl(t *testing.T) (*Controller, *int) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"rules":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	started := 0
	c := New(st, func(cfg session.Config) (Session, error) {
		started++
		return &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}, nil
	}, session.Config{}, slog.LevelInfo)
	if err := c.Load(); err == nil {
		t.Fatal("broken settings.json loaded without an error")
	}
	return c, &started
}

// The rules in memory are the defaults (everything direct): connecting
// would ignore the user's rules.
func TestConnectRefusedWithUnloadedSettings(t *testing.T) {
	c, started := brokenSettingsCtl(t)
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	err := c.Connect()
	if err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
		t.Fatalf("connected with the default rules: %v", err)
	}
	if *started != 0 || c.Status().State != "disconnected" {
		t.Fatalf("%d starts, state %q", *started, c.Status().State)
	}
	if err := c.Reconnect(); err == nil || *started != 0 {
		t.Fatal("reconnected with the default rules")
	}
}

// gatedCtl starts sessions only when gate is closed or sent to.
func gatedCtl(t *testing.T) (c *Controller, gate chan struct{}, started func() []*fakeSession) {
	t.Helper()
	c, _ = newCtl(t)
	gate = make(chan struct{})
	var mu sync.Mutex
	var list []*fakeSession
	c.Start = func(cfg session.Config) (Session, error) {
		<-gate
		f := &fakeSession{reg: flows.NewRegistry(1000), cfg: cfg, set: cfg.Rules, profiles: cfg.Profiles}
		mu.Lock()
		list = append(list, f)
		mu.Unlock()
		return f, nil
	}
	return c, gate, func() []*fakeSession {
		mu.Lock()
		defer mu.Unlock()
		return append([]*fakeSession(nil), list...)
	}
}

func waitStarting(t *testing.T, c *Controller) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); c.Status().State != "starting"; {
		if time.Now().After(end) {
			t.Fatal("not starting")
		}
		time.Sleep(time.Millisecond)
	}
}

// "Отключить" in the tray while the session starts: routing must end up
// off, and the kill switch not armed after it.
func TestDisconnectDuringStart(t *testing.T) {
	c, gate, started := gatedCtl(t)
	ks := &fakeKS{blocks: true} // a crashed run left the block
	c.KillSwitch = ks
	c.InitKillSwitch()
	setKillSwitch(t, c, true)
	connected := make(chan error, 1)
	go func() { connected <- c.Connect() }()
	waitStarting(t, c)
	disconnected := make(chan struct{})
	go func() {
		c.Disconnect()
		close(disconnected)
	}()
	// Give a Disconnect that does not wait for the start the time to
	// return before the session is up.
	select {
	case <-disconnected:
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	<-disconnected
	s := started()
	if st := c.Status(); st.State != "disconnected" || len(s) != 1 || !s[0].stopped {
		t.Fatalf("state %q, sessions %d", st.State, len(s))
	}
	if ks.blocks || ks.pass || c.Status().KillSwitch != "" {
		t.Fatalf("kill switch after Disconnect: %+v", ks)
	}
}

// Rules and servers saved while the session starts reach it once it runs;
// engine options ask for a reconnect.
func TestChangesDuringStartReachSession(t *testing.T) {
	c, gate, started := gatedCtl(t)
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() { connected <- c.Connect() }()
	waitStarting(t, c)
	st := c.Settings()
	off := false
	st.DefaultAction, st.BlockQUIC = rules.Tunnel, &off
	res, err := c.SaveSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsReconnect {
		t.Fatal("QUIC option changed while starting: no reconnect asked")
	}
	// A server added and made the main one meanwhile.
	imp, err := c.ImportURIs("hy2://x@h2.example:8443")
	if err != nil || len(imp.Added) != 1 {
		t.Fatalf("%+v %v", imp, err)
	}
	h2 := imp.Added[0].ID
	if err := c.SetMain(h2); err != nil {
		t.Fatal(err)
	}
	close(gate)
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	f := started()[0]
	if ids(f.cfg.Profiles) != "" {
		t.Fatalf("the start itself had %q", ids(f.cfg.Profiles))
	}
	got := f.set.EvaluateNoDomain(rules.Subject{Proto: 6})
	if ids(f.profiles) != "h2.example" || got.Action != rules.Tunnel || got.Profile != h2 {
		t.Fatalf("session runs %q, default %v via %q", ids(f.profiles), got.Action, got.Profile)
	}
	// The next save compares with what the session started with.
	if res, _ := c.SaveSettings(st); !res.NeedsReconnect {
		t.Fatal("engine options of the session forgotten")
	}
}

func TestConnectionsAcrossSession(t *testing.T) {
	c, started := newCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	// Nothing closed yet: [] rather than null.
	var bad []string
	nilSlices(reflect.ValueOf(c.Connections(100)), "Connections", &bad)
	if len(bad) > 0 {
		t.Fatalf("nil slices: %v", bad)
	}
	b, _ := json.Marshal(c.Connections(100))
	if !strings.Contains(string(b), `"closed":[]`) {
		t.Fatal(string(b))
	}
	reg := (*started)[0].reg
	reg.Open(&flows.Record{}) // a direct flow the engine never closes
	reg.Close(reg.Open(&flows.Record{}), time.Now())
	if got := c.Connections(100); len(got.Active) != 1 || len(got.Closed) != 1 {
		t.Fatalf("%+v", got)
	}
	c.Disconnect()
	if got := c.Connections(100); len(got.Active) != 0 || len(got.Closed) != 1 {
		t.Fatalf("after disconnect: %+v", got)
	}
}

// A flow closing while the list is built must not be in both halves: the
// UI keys the rows by ID.
func TestConnectionsNoDuplicates(t *testing.T) {
	c, gate, started := gatedCtl(t)
	close(gate)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	reg := started()[0].reg
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var open []*flows.Record
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			open = append(open, reg.Open(&flows.Record{}))
			if len(open) > 50 {
				reg.Close(open[0], time.Now())
				open = open[1:]
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 3000; i++ {
		got := c.Connections(0)
		seen := map[uint64]bool{}
		for _, v := range got.Active {
			seen[v.ID] = true
		}
		for _, v := range got.Closed {
			if seen[v.ID] {
				t.Fatalf("flow %d both active and closed", v.ID)
			}
		}
	}
}

// Saves at the same time: settings.json and the rules in use agree.
func TestConcurrentSaves(t *testing.T) {
	c, _ := newCtl(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				st := c.Settings()
				st.Rules = []rules.Rule{{Name: fmt.Sprintf("r%d-%d", g, i), App: &rules.AppMatch{Pattern: "a.exe"}, Action: rules.Direct}}
				if _, err := c.SaveSettings(st); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	disk, _, err := c.Store.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if mem := c.Settings(); disk.Rules[0].Name != mem.Rules[0].Name {
		t.Fatalf("settings.json has %s, HyRoute uses %s", disk.Rules[0].Name, mem.Rules[0].Name)
	}
}
