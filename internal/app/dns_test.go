package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/dnsproxy"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// dnsSession records the DNS calls of the controller.
type dnsSession struct {
	fakeSession
	mu     sync.Mutex
	calls  []string // "SetDNS on|off", "SetRules"
	pols   []*dnspolicy.Policy
	pause  time.Time
	health []dnsproxy.Health
	setErr error
}

func (f *dnsSession) SetDNS(p *dnspolicy.Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p == nil {
		f.calls = append(f.calls, "SetDNS off")
	} else {
		f.calls = append(f.calls, "SetDNS on")
	}
	f.pols = append(f.pols, p)
	return f.setErr
}

func (f *dnsSession) SetRules(s *rules.Set, p []hysteria.Profile) {
	f.mu.Lock()
	f.calls = append(f.calls, "SetRules")
	f.mu.Unlock()
	f.fakeSession.SetRules(s, p)
}

func (f *dnsSession) DNSHealth() []dnsproxy.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health
}

func (f *dnsSession) PauseDNS(until time.Time) {
	f.mu.Lock()
	f.pause = until
	f.mu.Unlock()
}

func (f *dnsSession) lastPol() *dnspolicy.Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pols) == 0 {
		return nil
	}
	return f.pols[len(f.pols)-1]
}

type dnsCtl struct {
	*Controller
	sessions []*dnsSession
	flushes  atomic.Int32
}

func newDNSCtl(t *testing.T, st *store.Store) *dnsCtl {
	t.Helper()
	old := flushGap
	flushGap = 20 * time.Millisecond
	t.Cleanup(func() { flushGap = old })
	if st == nil {
		var err error
		if st, err = store.Open(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	d := &dnsCtl{}
	c := New(st, func(cfg session.Config) (Session, error) {
		f := &dnsSession{fakeSession: fakeSession{reg: flows.NewRegistry(10), cfg: cfg, set: cfg.Rules, profiles: cfg.Profiles}}
		d.sessions = append(d.sessions, f)
		return f, nil
	}, session.Config{}, slog.LevelInfo)
	c.recoverDelay = time.Hour
	noDNS(c, "")
	c.FlushDNS = func() error { d.flushes.Add(1); return nil } // as main: before Load
	d.Controller = c
	if err := c.Load(); err != nil && !strings.Contains(err.Error(), "dns.json") {
		t.Fatal(err)
	}
	return d
}

func (d *dnsCtl) sess() *dnsSession { return d.sessions[len(d.sessions)-1] }

// waitFlushes waits for n flushes in all (and a little longer: no more).
func (d *dnsCtl) waitFlushes(t *testing.T, n int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for d.flushes.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * flushGap)
	if got := d.flushes.Load(); got != n {
		t.Fatalf("%d flushes, want %d", got, n)
	}
}

func TestSaveDNS(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := newDNSCtl(t, st)
	if err := d.SaveDNS(dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "tcp://9.9.9.9"}}); err == nil ||
		err.Error() != "Для прямых запросов нужен зашифрованный сервер: https://… или tls://…" {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(st.Dir, "dns.json")); !os.IsNotExist(err) {
		t.Fatal("dns.json written for a refused config")
	}
	// Disconnected: saved, nothing pushed, no flush.
	const secret = "https://dns.nextdns.io/abcdef123456"
	cfg := dnspolicy.Config{ByRules: true, IgnoreAddrRules: true, Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: secret}}
	if err := d.SaveDNS(cfg); err != nil {
		t.Fatal(err)
	}
	if v := d.DNS(); !v.Config.ByRules || !v.Config.IgnoreAddrRules || v.Config.Tunnel.Preset != "cloudflare" || len(v.Presets) != len(dnspolicy.Presets) {
		t.Fatalf("%+v", v)
	}
	d.waitFlushes(t, 0)
	// Connect: the session starts with the policy; the cache is flushed.
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if p := d.sess().cfg.DNS; p == nil || !p.Cfg.ByRules || p.DirectSpec == nil || p.DirectSpec.Name != dnspolicy.CustomName {
		t.Fatalf("session policy %+v", p)
	}
	d.waitFlushes(t, 1)
	// A change while connected: pushed and flushed.
	cfg.BlockBrowserDoH = true
	if err := d.SaveDNS(cfg); err != nil {
		t.Fatal(err)
	}
	if p := d.sess().lastPol(); p == nil || !p.Cfg.BlockBrowserDoH {
		t.Fatalf("not pushed: %+v", p)
	}
	d.waitFlushes(t, 2)
	// Rules saved while resolving by the rules: flushed.
	if _, err := d.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{{Name: "x", Domains: []string{"x.example"}, Action: rules.Direct}}}); err != nil {
		t.Fatal(err)
	}
	d.waitFlushes(t, 3)
	// Rate limit: requests in a burst give one flush.
	for range 5 {
		d.flushDNSAsync("test")
	}
	d.waitFlushes(t, 4)
	// A refused push is reported, the file is saved.
	d.sess().setErr = errors.New("filter swap failed")
	cfg.StripECH = true
	if err := d.SaveDNS(cfg); err == nil || !strings.Contains(err.Error(), "сохранены, но не применены") {
		t.Fatal(err)
	}
	d.sess().setErr = nil
	d.waitFlushes(t, 5)
	// Disconnect: flushed.
	d.Disconnect()
	d.waitFlushes(t, 6)
	// Secrets: not in logs, not in the diagnostics.
	d.Log.Info("test", "url", secret)
	for _, e := range d.EngineLog.Since(0, 0) {
		if strings.Contains(e.Msg, "abcdef123456") {
			t.Fatalf("secret in the log: %s", e.Msg)
		}
	}
	diag := d.Diagnostics(nil, false)
	if strings.Contains(diag, "abcdef123456") || strings.Contains(diag, "nextdns") || !strings.Contains(diag, "direct=custom") {
		t.Fatalf("diagnostics: %s", diag)
	}
	// Reloaded: the same settings.
	d2 := newDNSCtl(t, st)
	if v := d2.DNS(); !v.Config.IgnoreAddrRules || v.Config.Direct.URL != secret || v.Error != "" {
		t.Fatalf("reloaded %+v", v)
	}
	d2.waitFlushes(t, 1) // a start with an option on flushes
	// A broken file: every option off, saving refused, the file kept.
	os.WriteFile(filepath.Join(st.Dir, "dns.json"), []byte("{broken"), 0o600)
	d3 := newDNSCtl(t, st)
	if v := d3.DNS(); v.Error == "" || v.Config.ByRules || strings.Contains(v.Error, "dns.json") {
		t.Fatalf("broken %+v", v) // the card names the file itself
	}
	if err := d3.SaveDNS(dnspolicy.Config{}); err == nil || !strings.Contains(err.Error(), "dns.json не загружен") || strings.Count(err.Error(), "dns.json") != 1 {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir, "dns.json")); string(b) != "{broken" {
		t.Fatal("broken file overwritten")
	}
	if _, err := d3.DNSConfig(); err == nil {
		t.Fatal("DNSConfig of a broken file")
	}
	if err := d3.Connect(); err != nil || d3.sess().cfg.DNS != nil {
		t.Fatal("a broken dns.json must leave DNS off")
	}
}

// Unused: no dns.json is created and the session gets no policy.
func TestDNSUnused(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	d := newDNSCtl(t, st)
	d.DNS()
	d.Status()
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if d.sess().cfg.DNS != nil || d.Status().DNS != nil {
		t.Fatal("policy without settings")
	}
	d.Disconnect()
	if _, err := os.Stat(filepath.Join(st.Dir, "dns.json")); !os.IsNotExist(err) {
		t.Fatal("dns.json created")
	}
	d.waitFlushes(t, 0)
}

func TestStatusDNS(t *testing.T) {
	d := newDNSCtl(t, nil)
	if d.Status().DNS != nil {
		t.Fatal("disconnected")
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if d.Status().DNS != nil {
		t.Fatal("all off")
	}
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true, Tunnel: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "https://secret.example/abcdefgh"},
		Direct: dnspolicy.Upstream{Preset: "quad9"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d.sess().mu.Lock()
	d.sess().health = []dnsproxy.Health{
		{Via: dnspolicy.ViaDirect, Key: "direct", Kind: "tls", RetryAt: now.Add(-time.Second)},
		{Via: dnspolicy.ViaTunnel, Key: "tunnel:p1", Profile: "p1", Kind: "http", Code: 503, RetryAt: now.Add(10 * time.Second)},
	}
	d.sess().mu.Unlock()
	s := d.Status().DNS
	if s == nil || !s.ByRules || !s.Direct || len(s.Health) != 2 {
		t.Fatalf("%+v", s)
	}
	if h := s.Health[0]; h.Via != "direct" || h.Upstream != "Quad9" || h.RetryIn != 0 || h.Kind != "tls" {
		t.Fatalf("%+v", h)
	}
	if h := s.Health[1]; h.Via != "tunnel" || h.Upstream != dnspolicy.CustomName || h.Profile != "p1" || h.Code != 503 || h.RetryIn < 8 {
		t.Fatalf("%+v", h)
	}
}

// A session that did not take the settings (a failed filter swap) is not
// reported as resolving by them; the next successful apply or a reconnect
// ends that.
func TestStatusDNSNotApplied(t *testing.T) {
	d := newDNSCtl(t, nil)
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	d.sess().mu.Lock()
	d.sess().setErr = errors.New("filter swap failed")
	d.sess().mu.Unlock()
	cfg := dnspolicy.Config{ByRules: true, Tunnel: dnspolicy.Upstream{Preset: "cloudflare"}}
	if err := d.SaveDNS(cfg); err == nil || !strings.Contains(err.Error(), "сохранены, но не применены") {
		t.Fatal(err)
	}
	if s := d.Status().DNS; s == nil || !s.NotApplied || s.ByRules || s.PauseLeft != 0 || len(s.Health) != 0 {
		t.Fatalf("%+v", s)
	}
	d.sess().mu.Lock()
	d.sess().setErr = nil
	d.sess().mu.Unlock()
	if err := d.SaveDNS(cfg); err != nil {
		t.Fatal(err)
	}
	if s := d.Status().DNS; s == nil || s.NotApplied || !s.ByRules {
		t.Fatalf("%+v", s)
	}
	// A reconnect starts with the policy: the failure does not carry over.
	d.sess().mu.Lock()
	d.sess().setErr = errors.New("filter swap failed")
	d.sess().mu.Unlock()
	d.SaveDNS(dnspolicy.Config{ByRules: true, Tunnel: dnspolicy.Upstream{Preset: "quad9"}})
	if s := d.Status().DNS; s == nil || !s.NotApplied {
		t.Fatalf("%+v", s)
	}
	d.Disconnect()
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if s := d.Status().DNS; s == nil || s.NotApplied || !s.ByRules {
		t.Fatalf("after reconnect: %+v", s)
	}
}

func TestPauseDNSTunnel(t *testing.T) {
	d := newDNSCtl(t, nil)
	if err := d.PauseDNSTunnel(); err == nil || err.Error() != "HyRoute не подключён" {
		t.Fatal(err)
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := d.PauseDNSTunnel(); err == nil || err.Error() != "DNS по правилам не включён" {
		t.Fatal(err)
	}
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	d.waitFlushes(t, 1)
	if err := d.PauseDNSTunnel(); err != nil {
		t.Fatal(err)
	}
	if p := d.sess().pause; time.Until(p) < 4*time.Minute {
		t.Fatalf("session pause %v", p)
	}
	if s := d.Status().DNS; s == nil || s.PauseLeft < 290 || s.PauseLeft > 300 {
		t.Fatalf("%+v", s)
	}
	d.waitFlushes(t, 2)
	d.CancelDNSPause()
	if !d.sess().pause.IsZero() || d.Status().DNS.PauseLeft != 0 {
		t.Fatal("cancel")
	}
	d.PauseDNSTunnel()
	d.Disconnect()
	d.Connect()
	if s := d.Status().DNS; s == nil || s.PauseLeft != 0 {
		t.Fatalf("a new connect with the old pause: %+v", s)
	}
}

func TestDNSPolicyNames(t *testing.T) {
	d := newDNSCtl(t, nil)
	if _, err := d.ImportURIs("hysteria2://a@hy1.example:443#one\nhysteria2://b@203.0.113.5:443#two"); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true, Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "https://my-doh.example/dns-query"}}); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	pol := d.dnsPolicyLocked()
	d.mu.Unlock()
	classify := func(name string) dnspolicy.Decision {
		return pol.Classify(dnspolicy.Question{Name: name, Type: dnsmessage.TypeA}, dnspolicy.Requester{System: true}, dnspolicy.Env{})
	}
	if d := classify("hy1.example"); d.Local != "server" {
		t.Fatalf("server host: %+v", d)
	}
	if d := classify("my-doh.example"); d.Local != "service" {
		t.Fatalf("custom upstream host: %+v", d)
	}
	for _, n := range []string{"203.0.113.5", "raw.githubusercontent.com", "sub.example"} {
		if d := classify(n); d.Local == "server" || d.Local == "service" {
			t.Fatalf("%s is a permanent name: %+v", n, d)
		}
	}
}

// A server added while connected: its host is in the policy before its
// Hysteria starts.
func TestApplyRoutingDNSFirst(t *testing.T) {
	d := newDNSCtl(t, nil)
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	s := d.sess()
	s.mu.Lock()
	s.calls, s.pols = nil, nil
	s.mu.Unlock()
	if _, err := d.ImportURIs("hysteria2://a@new.example:443#new"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	calls := append([]string(nil), s.calls...)
	s.mu.Unlock()
	if len(calls) < 2 || calls[0] != "SetDNS on" || calls[1] != "SetRules" {
		t.Fatalf("order %v", calls)
	}
	p := s.lastPol()
	if dd := p.Classify(dnspolicy.Question{Name: "new.example", Type: dnsmessage.TypeA}, dnspolicy.Requester{System: true}, dnspolicy.Env{}); dd.Local != "server" {
		t.Fatalf("new host not in the policy: %+v", dd)
	}
}

func TestExplainDNS(t *testing.T) {
	d := newDNSCtl(t, nil)
	if _, err := d.ImportURIs("hysteria2://a@hy1.example:443#one"); err != nil {
		t.Fatal(err)
	}
	st := d.Settings()
	st.Config = rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "ads", Domains: []string{"ads.example"}, Action: rules.Block},
		{Name: "chrome site", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{"app.example"}, Action: rules.Direct},
		{Name: "tcp site", Domains: []string{"proto.example"}, Protocol: "tcp", Action: rules.Block},
		{Name: "direct", Domains: []string{".direct.example"}, Action: rules.Direct},
		{Name: "addr", Domains: []string{"8.8.8.0/24"}, Action: rules.Direct},
	}}
	ex := func(target, app string) *DNSExplain {
		t.Helper()
		return d.Explain(ExplainQuery{Target: target, App: app}, &st).DNS
	}
	if ex("example.org", "") != nil {
		t.Fatal("DNS off")
	}
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	check := func(label string, got *DNSExplain, want DNSExplain) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s: nil, want %+v", label, want)
		}
		if !sameDNSExplain(got, &want) {
			t.Fatalf("%s: %+v (system %+v), want %+v (system %+v)", label, got, got.System, want, want.System)
		}
	}
	check("addr", ex("example.org", ""), DNSExplain{Route: "addr", Rule: "addr"})
	check("block", ex("ads.example", ""), DNSExplain{Route: "block", Rule: "ads"})
	check("server", ex("hy1.example", ""), DNSExplain{Route: "server"})
	check("local", ex("nas", ""), DNSExplain{Route: "local"})
	check("service", ex("www.msftconnecttest.com", ""), DNSExplain{Route: "service"})
	check("direct", ex("x.direct.example", ""), DNSExplain{Route: "direct"})
	check("app cond", ex("app.example", ""), DNSExplain{Route: "addr", Rule: "addr"})
	// A program: as it asks itself, and through the Windows DNS client
	// (most programs) where its rule counts only conditionally.
	check("app known", ex("app.example", "chrome"), DNSExplain{Route: "direct", System: &DNSExplain{Route: "addr", Rule: "addr"}})
	check("app, same both ways", ex("x.direct.example", "chrome"), DNSExplain{Route: "direct"})
	check("proto", ex("proto.example", ""), DNSExplain{Route: "addr", Rule: "addr"})
	// Without the address check: the tunnel, conditions shown.
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true, IgnoreAddrRules: true}); err != nil {
		t.Fatal(err)
	}
	main := d.Status().MainID
	check("tunnel", ex("example.org", ""), DNSExplain{Route: "tunnel", Profile: main, Upstream: "Cloudflare", Rule: "default", NoIPv6: true})
	st.Config.Rules[2].Action = rules.Tunnel
	check("proto cond", ex("proto.example", ""), DNSExplain{Route: "tunnel", Profile: main, Upstream: "Cloudflare", Rule: "tcp site", Cond: "proto", Proto: "tcp", NoIPv6: true})
	// "any" with ports: no protocol named («некоторых портов»).
	st.Config.Rules[2].Protocol, st.Config.Rules[2].Ports = "any", rules.PortList{"443"}
	check("ports cond", ex("proto.example", ""), DNSExplain{Route: "tunnel", Profile: main, Upstream: "Cloudflare", Rule: "tcp site", Cond: "proto", NoIPv6: true})
	st.Config.Rules[2].Protocol, st.Config.Rules[2].Ports = "tcp", nil
	check("app direct, system tunnel", ex("app.example", "chrome.exe"), DNSExplain{Route: "direct",
		System: &DNSExplain{Route: "tunnel", Profile: main, Upstream: "Cloudflare", Rule: "default", NoIPv6: true}})
	st.Config.Rules[1].Action = rules.Tunnel
	check("app cond tunnel", ex("app.example", ""), DNSExplain{Route: "tunnel", Profile: main, Upstream: "Cloudflare", Rule: "chrome site", Cond: "app", NoIPv6: true})
	// The direct upstream.
	if err := d.SaveDNS(dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: "google"}}); err != nil {
		t.Fatal(err)
	}
	check("upstream", ex("example.org", ""), DNSExplain{Route: "upstream", Upstream: "Google"})
	// The saved rules when no editor copy is given.
	if got := d.Explain(ExplainQuery{Target: "1.2.3.4"}, nil).DNS; got != nil {
		t.Fatalf("an IP has no DNS line: %+v", got)
	}
	_ = settings.Settings{}
}

// sameDNSExplain compares two Explain lines and their System lines.
func sameDNSExplain(a, b *DNSExplain) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, y := *a, *b
	x.System, y.System = nil, nil
	return x == y && sameDNSExplain(a.System, b.System)
}

// Shutdown: the process ends right after it, so the flush of the session
// just stopped runs before it returns, even inside the rate limit.
func TestDNSExitFlush(t *testing.T) {
	d := newDNSCtl(t, nil)
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	d.waitFlushes(t, 1)
	flushGap = time.Hour // the connect flush was just now: an async one would wait
	d.Shutdown()
	if got := d.flushes.Load(); got != 2 {
		t.Fatalf("%d flushes when Shutdown returned, want 2", got)
	}
	// Nothing due: none.
	d2 := newDNSCtl(t, nil)
	d2.Shutdown()
	if got := d2.flushes.Load(); got != 0 {
		t.Fatalf("%d flushes without DNS", got)
	}
}

// DNS turned on while the session starts: the session keeps the record
// applyRoutingLocked made (HyRoute's own names pass, the flushes happen).
func TestDNSOnWhileStarting(t *testing.T) {
	d := newDNSCtl(t, nil)
	start := d.Start
	d.Start = func(cfg session.Config) (Session, error) {
		if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
			t.Error(err)
		}
		return start(cfg)
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if d.sess().cfg.DNS != nil {
		t.Fatal("started with the policy")
	}
	if ref := d.dnsSess.Load(); ref == nil || !ref.dns {
		t.Fatalf("record lost: %+v", ref)
	}
	d.waitFlushes(t, 1)
	d.Disconnect()
	d.waitFlushes(t, 2)
}

// A custom server's account ID in its host or a short path segment never
// reaches a log or the diagnostics; a dns.json that quotes a bad host
// loads as an error without the host.
func TestDNSSecretsHost(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	d := newDNSCtl(t, st)
	cfg := dnspolicy.Config{ByRules: true, Tunnel: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "tls://abcdef123456.dns.nextdns.io"},
		Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "https://dns.nextdns.io/zx81yq"}}
	if err := d.SaveDNS(cfg); err != nil {
		t.Fatal(err)
	}
	d.Log.Info("socks error", "reqAddr", "abcdef123456.dns.nextdns.io:853", "url", "https://dns.nextdns.io/zx81yq")
	d.hysteriaLine("p1", hysteria.LogLine{Level: "error", Msg: "TCP error", Fields: map[string]any{"reqAddr": "abcdef123456.dns.nextdns.io:853"}})
	for _, e := range d.EngineLog.Since(0, 0) {
		if strings.Contains(e.Msg, "abcdef123456") || strings.Contains(e.Msg, "zx81yq") {
			t.Fatalf("secret in the log: %s", e.Msg)
		}
	}
	if diag := d.Diagnostics(nil, false); strings.Contains(diag, "abcdef123456") || strings.Contains(diag, "zx81yq") {
		t.Fatalf("diagnostics: %s", diag)
	}
	if !slices.Contains(dnsSecrets(cfg), "zx81yq") || slices.Contains(dnsSecrets(dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom,
		URL: "https://dns.quad9.net/dns-query"}}), "dns.quad9.net") {
		t.Fatal("secrets")
	}
	_, herr := dnspolicy.ParseUpstream("tls://bad_id!.dns.nextdns.io", false)
	err := dnsLoadError(fmt.Errorf("dns.json: %w", herr))
	if herr == nil || strings.Contains(err.Error(), "bad_id") || !strings.HasPrefix(err.Error(), "dns.json: ") {
		t.Fatal(herr, err)
	}
	// Other messages quote nothing secret and keep their reason.
	other := fmt.Errorf("dns.json: %w", dnspolicy.InputError("DNS-сервер «Яндекс» здесь выбрать нельзя"))
	if err := dnsLoadError(other); err != other {
		t.Fatal(err)
	}
}
