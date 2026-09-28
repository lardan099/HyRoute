package app

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

const link = "hysteria2://user:pass@example.com:443,20000-50000/?obfs-password=ob&sni=s.example#DE%20one"

type fakeSession struct {
	NopSession
	stopped  bool
	set      *rules.Set
	profiles []hysteria.Profile
	reg      *flows.Registry
	tunnels  []tunnels.Status
	stats    session.Stats
	cfg      session.Config
	failed   atomic.Bool
	// onReset runs in ResetConnections; resets counts the calls.
	onReset func()
	resets  int
}

// fail is an engine failure as the engine reports it: marked first, then
// the callback.
func (f *fakeSession) fail() {
	f.failed.Store(true)
	f.cfg.OnEngineFail()
}

func (f *fakeSession) Stop() { f.stopped = true }
func (f *fakeSession) ResetConnections() {
	f.resets++
	if f.onReset != nil {
		f.onReset()
	}
}
func (f *fakeSession) SetRules(s *rules.Set, p []hysteria.Profile) {
	f.set, f.profiles = s, p
}
func (f *fakeSession) Flows() *flows.Registry    { return f.reg }
func (f *fakeSession) EngineFailed() bool        { return f.failed.Load() }
func (f *fakeSession) Tunnels() []tunnels.Status { return f.tunnels }
func (f *fakeSession) Stats() session.Stats      { return f.stats }

func newCtl(t *testing.T) (*Controller, *[]*fakeSession) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return newCtlAt(t, st)
}

func newCtlAt(t *testing.T, st *store.Store) (*Controller, *[]*fakeSession) {
	t.Helper()
	var started []*fakeSession
	c := New(st, func(cfg session.Config) (Session, error) {
		f := &fakeSession{reg: flows.NewRegistry(10), cfg: cfg, set: cfg.Rules, profiles: cfg.Profiles}
		started = append(started, f)
		return f, nil
	}, session.Config{}, slog.LevelInfo)
	// Tests that fail an engine reconnect by hand; recover_test.go sets
	// its own delay.
	c.recoverDelay = time.Hour
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	return c, &started
}

func ids(ps []hysteria.Profile) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Name)
	}
	return strings.Join(s, ",")
}

func TestImportConnectStatus(t *testing.T) {
	c, started := newCtl(t)
	res, err := c.ImportURIs("garbage\n" + link + "\n hy2://x@h2.example:8443 vless://abc@h:1")
	if err != nil || len(res.Added) != 2 || len(res.Errors) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if !res.Added[0].Main || res.Added[0].Name != "DE one" || res.Added[1].Name != "h2.example" {
		t.Fatalf("%+v", res.Added)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("obfs-password without obfs must warn")
	}
	de, h2 := res.Added[0].ID, res.Added[1].ID

	// Nothing is tunneled yet: routing starts without any Hysteria.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	if len(f.cfg.Profiles) != 0 || f.cfg.Settings == nil || f.cfg.Rules == nil || f.cfg.Log == nil {
		t.Fatalf("%+v", f.cfg)
	}
	if s := c.Status(); s.State != "connected" || s.Main != "DE one" {
		t.Fatalf("%+v", s)
	}

	// Rules pick profiles; only the used ones run.
	st := c.Settings()
	st.Rules = []rules.Rule{
		{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel},
		{Name: "yt", Domain: &rules.DomainMatch{Pattern: ".youtube.com"}, Action: rules.Tunnel, Profile: h2},
	}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if ids(f.profiles) != "DE one,h2.example" || f.set.Main != de {
		t.Fatalf("running %s main %s", ids(f.profiles), f.set.Main)
	}
	f.tunnels = []tunnels.Status{{ID: de, Name: "DE one", State: "connected"}, {ID: h2, Name: "h2.example", State: "connecting"}}
	if s := c.Status(); s.State != "connecting" || len(s.Tunnels) != 2 {
		t.Fatalf("%+v", s)
	}
	f.tunnels[1] = tunnels.Status{ID: h2, Name: "h2.example", State: "failed", Message: "Неверный пароль", Rejected: 3}
	if s := c.Status(); s.State != "tunnel-down" || !strings.Contains(s.Message, "h2.example недоступен, 3 соединений отклонено: Неверный пароль") {
		t.Fatalf("%+v", s)
	}

	// Switching the main profile applies live to rules without a profile.
	if err := c.SetMain(h2); err != nil {
		t.Fatal(err)
	}
	if ids(f.profiles) != "h2.example" || f.set.Main != h2 {
		t.Fatalf("after SetMain: %s", ids(f.profiles))
	}
	// A profile named by a rule cannot be deleted.
	if err := c.DeleteProfile(h2); err == nil || !strings.Contains(err.Error(), "yt") {
		t.Fatalf("delete used profile: %v", err)
	}
	if err := c.DeleteProfile(de); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	if s := c.Status(); s.State != "disconnected" || !f.stopped {
		t.Fatalf("%+v", s)
	}
}

func TestRuleWarnings(t *testing.T) {
	c, _ := newCtl(t)
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "a", App: &rules.AppMatch{Pattern: "a.exe"}, Action: rules.Tunnel}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Kind != "no-main" {
		t.Fatalf("%+v", w)
	}
	res, _ := c.ImportURIs(link)
	st.Rules = append(st.Rules, rules.Rule{Name: "b", App: &rules.AppMatch{Pattern: "b.exe"}, Action: rules.Tunnel, Profile: "gone"})
	c.SaveSettings(st)
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Kind != "deleted" || w[0].Rule != "b" {
		t.Fatalf("%+v", w)
	}
	if ps := c.Profiles(); len(ps[0].UsedBy) != 1 || ps[0].UsedBy[0] != "a" || ps[0].ID != res.Added[0].ID {
		t.Fatalf("%+v", ps)
	}
}

func TestProfilesPersistAndSecretsSurviveReload(t *testing.T) {
	c, _ := newCtl(t)
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	c2 := New(c.Store, c.Start, session.Config{}, slog.LevelInfo)
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	ps := c2.Profiles()
	if len(ps) != 1 || !ps[0].Main {
		t.Fatalf("%+v", ps)
	}
	p, err := c2.Profile(ps[0].ID)
	if err != nil || p.Auth != "user:pass" || p.Obfs.Password != "ob" || p.Obfs.Type != "salamander" {
		t.Fatalf("%+v %v", p, err)
	}
	uri, _ := c2.ExportURI(p.ID)
	if !strings.Contains(uri, "obfs=salamander") {
		t.Fatal(uri)
	}
	// Edit and reorder.
	p.Name = "renamed"
	if _, err := c2.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.SaveProfile(hysteria.Profile{Host: "b.example"}); err != nil {
		t.Fatal(err)
	}
	if err := c2.MoveProfile(c2.Profiles()[1].ID, 0); err != nil {
		t.Fatal(err)
	}
	if ps := c2.Profiles(); ps[0].Name != "b.example" || ps[1].Name != "renamed" || !ps[1].Main {
		t.Fatalf("%+v", ps)
	}
	if _, err := c2.SaveProfile(hysteria.Profile{Host: "c", Obfs: hysteria.Obfs{Type: "salamander"}}); err == nil {
		t.Fatal("invalid profile saved")
	}
}

func TestSettingsApplyLiveAndFlagReconnect(t *testing.T) {
	c, started := newCtl(t)
	c.Base.Stub = true
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel}}
	res, err := c.SaveSettings(st)
	if err != nil || res.NeedsReconnect {
		t.Fatalf("%+v %v", res, err)
	}
	if f := (*started)[0]; f.set == nil || ids(f.profiles) != "stub" {
		t.Fatal("rules not applied to the running session")
	}
	off := false
	st.BlockQUIC = &off
	if res, _ := c.SaveSettings(st); !res.NeedsReconnect {
		t.Fatal("engine option change must ask for reconnect")
	}
	st.Rules = append(st.Rules, rules.Rule{Name: "bad", Domain: &rules.DomainMatch{Pattern: "a b"}})
	if _, err := c.SaveSettings(st); err == nil {
		t.Fatal("invalid rules saved")
	}
	if got := c.Settings(); len(got.Rules) != 1 {
		t.Fatal("invalid save must not replace settings")
	}
}

func TestHysteriaLogRedactedPerProfile(t *testing.T) {
	c, _ := newCtl(t)
	c.Redactor.Set("topsecret")
	c.hysteriaLine("p1", hysteria.LogLine{Level: "error", Msg: "auth failed", Fields: map[string]any{"auth": "topsecret", "addr": "1.2.3.4:443"}})
	c.hysteriaLine("p2", hysteria.LogLine{Level: "info", Msg: "other"})
	e := c.Logs("hysteria:p1", 0)
	if len(e) != 1 || e[0].Level != "error" || strings.Contains(e[0].Msg, "topsecret") || !strings.Contains(e[0].Msg, "addr=1.2.3.4:443") {
		t.Fatalf("%+v", e)
	}
	if all := c.Logs("hysteria", 0); len(all) != 2 || !strings.HasPrefix(all[1].Msg, "[p2] ") {
		t.Fatalf("%+v", all)
	}
}

func TestParseLinksBase64AndIgnored(t *testing.T) {
	body := "hy2://a@h1.example:443#one\nvless://x@h:1\nvmess://abc\nhysteria2://b@h2.example:443#two\nss://y@z:1"
	enc := "aHkyOi8vYUBoMS5leGFtcGxlOjQ0MyNvbmUKdmxlc3M6Ly94QGg6MQp2bWVzczovL2FiYwpoeXN0ZXJpYTI6Ly9iQGgyLmV4YW1wbGU6NDQzI3R3bwpzczovL3lAejox"
	for _, in := range []string{body, enc, enc + "\n"} {
		l := ParseLinks(in)
		if len(l.Profiles) != 2 || l.IgnoredTotal() != 3 || l.Ignored["vless"] != 1 {
			t.Fatalf("%q: %+v", in, l)
		}
	}
	if !ParseLinks(enc).Base64 || ParseLinks(body).Base64 {
		t.Fatal("base64 flag")
	}
}

// Stopping an unused profile waits for its Hysteria, whose last status
// and log lines arrive through the controller's callbacks while
// SaveSettings holds the controller lock. They must not need that lock.
type callbackSession struct{ fakeSession }

func (f *callbackSession) SetRules(s *rules.Set, p []hysteria.Profile) {
	f.fakeSession.SetRules(s, p)
	f.cfg.OnStatus("x", hysteria.Status{State: hysteria.Stopped})
	f.cfg.HysteriaLog("x", hysteria.LogLine{Level: "info", Msg: "bye"})
}

func TestCallbacksDoNotDeadlock(t *testing.T) {
	c, _ := newCtl(t)
	c.Start = func(cfg session.Config) (Session, error) {
		return &callbackSession{fakeSession{reg: flows.NewRegistry(10), cfg: cfg}}, nil
	}
	c.ImportURIs(link)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		st := c.Settings()
		st.DefaultAction = rules.Tunnel
		c.SaveSettings(st)
		c.SetMain(c.Profiles()[0].ID)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: callbacks wait for the controller lock")
	}
}

func TestCleanTarget(t *testing.T) {
	type hp struct {
		host string
		port uint16
	}
	for in, want := range map[string]hp{
		".2ip.io": {"2ip.io", 0}, "*.2ip.io": {"2ip.io", 0}, "https://www.2ip.io/path?x": {"www.2ip.io", 443},
		"http://2ip.io:8080/": {"2ip.io", 8080}, "2ip.io:443": {"2ip.io", 443}, "[2001:db8::1]:22": {"2001:db8::1", 22},
		" 1.2.3.4 ": {"1.2.3.4", 0},
	} {
		if h, p := cleanTarget(in); h != want.host || p != want.port {
			t.Errorf("%q: %q %d", in, h, p)
		}
	}
}

// Rules saved in an earlier run start their profiles on Connect.
func TestConnectAfterReloadStartsProfiles(t *testing.T) {
	c, _ := newCtl(t)
	c.ImportURIs(link)
	st := c.Settings()
	st.DefaultAction = rules.Tunnel
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	var started []*fakeSession
	c2 := New(c.Store, func(cfg session.Config) (Session, error) {
		f := &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}
		started = append(started, f)
		return f, nil
	}, session.Config{}, nil)
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	if err := c2.Connect(); err != nil {
		t.Fatal(err)
	}
	if ids(started[0].cfg.Profiles) != "DE one" || started[0].cfg.Rules.Main == "" {
		t.Fatalf("profiles %q main %q", ids(started[0].cfg.Profiles), started[0].cfg.Rules.Main)
	}
}
