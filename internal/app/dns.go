package app

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/sysdns"
)

// DNS policies («Настройки» → «DNS», dns.json; ARCHITECTURE §6.1). The
// settings are global (not per rule profile). They apply at once to a
// running session; the Windows DNS cache is flushed whenever what HyRoute
// answers may have changed, so programs ask again.

// dnsState is the controller's DNS part (embedded in Controller).
type dnsState struct {
	// FlushDNS empties the Windows DNS cache (main: sysdns.FlushCache; nil
	// in tests = nothing to do).
	FlushDNS func() error
	// LocalSuffixes are the local DNS namespaces of the machine, for
	// Explain (main: from sysdns.Snapshot; nil = none).
	LocalSuffixes func() []string

	// Guarded by mu: the settings, dns.json's load error (the options are
	// off and the file is never overwritten), and the captive-portal pause
	// (zero = none).
	dns       dnspolicy.Config
	dnsBroken error
	dnsPause  time.Time

	// dnsSess is the running session and whether it ever had a policy
	// (lock-free: OwnDial, the status callback and the disconnect flush
	// read it).
	dnsSess   atomic.Pointer[dnsSessRef]
	dnsFlush  flushState
	dnsWarned atomic.Bool // "DNS policy not applied" logged
	// ownNames are the hosts HyRoute contacts itself (OwnDial writes them,
	// session or not; every session's policy reads them).
	ownNames dnspolicy.OwnNames
}

type dnsSessRef struct {
	sess Session
	dns  bool
}

// flushState rate-limits the Windows DNS cache flushes (its mutex is a
// leaf): at most one per flushGap, a request inside the gap is served at
// its end.
type flushState struct {
	mu        sync.Mutex
	last      time.Time
	scheduled bool
	pending   int   // flush goroutines not yet done (Shutdown flushes at once while any is)
	failed    int64 // the session's SERVFAIL and portal-pause counters at the last flush
}

// flushGap is the least time between two flushes (a variable for tests).
var flushGap = 2 * time.Second

// exitFlushWait bounds the flush on exit (one local dnsapi call).
const exitFlushWait = 3 * time.Second

// dnsPauseFor is how long «Разрешить имена напрямую на 5 минут» lasts.
const dnsPauseFor = 5 * time.Minute

// ownNameTTL is how long a host HyRoute contacts itself stays its own name.
const ownNameTTL = 2 * time.Minute

// loadDNS reads dns.json for Load; a broken file keeps every option off.
func (c *Controller) loadDNS(errs *[]string) (dnspolicy.Config, error) {
	cfg, err := c.Store.LoadDNS()
	if err != nil {
		err = dnsLoadError(err)
		*errs = append(*errs, err.Error())
		return dnspolicy.Config{}, err
	}
	c.Redactor.SetGroup("dns", dnsSecrets(cfg)...)
	return cfg, nil
}

// installLoadedDNSLocked installs what loadDNS read (c.mu held).
func (c *Controller) installLoadedDNSLocked(cfg dnspolicy.Config, err error) {
	c.dns, c.dnsBroken = cfg, err
}

// dnsLoadError keeps what a load error of dns.json may quote of a custom
// server (its host, which can carry an account ID) out of the log and the
// diagnostics: that validation message is replaced by its class. Nothing
// is registered with the redactor yet when the file does not load.
func dnsLoadError(err error) error {
	var he dnspolicy.HostError
	if errors.As(err, &he) {
		return errors.New("dns.json: неверное имя или IP своего DNS-сервера")
	}
	return err
}

// dnsLoadReason is a load error of dns.json for text that names the file
// already (the card, SaveDNS's refusal).
func dnsLoadReason(err error) string {
	return strings.TrimPrefix(err.Error(), "dns.json: ")
}

// dnsSecrets are the parts of the custom servers' URLs that must not reach
// a log: an account ID in the path (NextDNS's has 6 characters), in the
// host (tls://<id>.dns.nextdns.io; a tunnel server's host reaches
// Hysteria's log through SOCKS), a token in the query.
func dnsSecrets(cfg dnspolicy.Config) []string {
	var out []string
	for _, u := range []dnspolicy.Upstream{cfg.Tunnel, cfg.Direct} {
		if u.Preset != dnspolicy.Custom || u.URL == "" {
			continue
		}
		out = append(out, urlSecrets(u.URL)...)
		pu, err := url.Parse(strings.TrimSpace(u.URL))
		if err != nil {
			continue
		}
		if h := strings.ToLower(pu.Hostname()); h != "" && !presetHost(h) {
			if _, err := netip.ParseAddr(h); err != nil {
				out = append(out, h)
			}
		}
		for _, seg := range strings.Split(pu.Path, "/") {
			if len(seg) >= 4 && seg != "dns-query" && !slices.Contains(out, seg) {
				out = append(out, seg)
			}
		}
	}
	return out
}

// presetHost reports the host of a preset (public, never a secret).
func presetHost(h string) bool {
	for _, p := range dnspolicy.Presets {
		if u, err := url.Parse(p.URL); err == nil && strings.EqualFold(u.Hostname(), h) {
			return true
		}
	}
	return false
}

// dnsNamesLocked are the names the policy always passes: the servers'
// hosts and the custom direct server's host (c.mu held).
func (c *Controller) dnsNamesLocked() dnspolicy.Names {
	var n dnspolicy.Names
	for _, p := range c.profiles.List {
		if _, err := netip.ParseAddr(p.Host); err != nil && p.Host != "" {
			n.Servers = append(n.Servers, p.Host)
		}
	}
	if c.dns.Direct.Preset == dnspolicy.Custom {
		if s, err := dnspolicy.ParseUpstream(c.dns.Direct.URL, false); err == nil {
			if _, ok := s.IP(); !ok {
				n.Service = append(n.Service, s.Host)
			}
		}
	}
	return n
}

// dnsPolicyLocked compiles the DNS policy for the current servers (c.mu
// held); nil when off or broken.
func (c *Controller) dnsPolicyLocked() *dnspolicy.Policy {
	if c.dnsBroken != nil || !c.dns.Active() {
		return nil
	}
	pol, err := dnspolicy.Compile(c.dns, c.dnsNamesLocked())
	if err != nil {
		if !c.dnsWarned.Swap(true) {
			c.Log.Warn("DNS policy not applied", "err", err)
		}
		return nil
	}
	return pol
}

// dnsSession gives a starting session its policy and resolver log names.
func (c *Controller) dnsSessionLocked(cfg *session.Config) {
	cfg.DNS = c.dnsPolicyLocked()
	cfg.ProfileName = c.profileName
	cfg.OwnName = c.ownNames.Has
}

// dnsStarted records a started session; a policy flushes the cache. DNS
// turned on while it started was applied by applyRoutingLocked, which has
// recorded the session already: that record is kept.
func (c *Controller) dnsStarted(sess Session, cfg session.Config) {
	for {
		old := c.dnsSess.Load()
		on := cfg.DNS != nil || old != nil && old.sess == sess && old.dns
		if c.dnsSess.CompareAndSwap(old, &dnsSessRef{sess: sess, dns: on}) {
			if on {
				c.flushDNSAsync("connect")
			}
			return
		}
	}
}

// dnsStopped forgets a stopped session; one that had a policy flushes the
// cache (its answers go with it).
func (c *Controller) dnsStopped() {
	if ref := c.dnsSess.Swap(nil); ref != nil && ref.dns {
		c.flushDNSAsync("disconnect")
	}
}

// applyDNSLocked pushes the policy to the running session before its rules
// (c.mu held): a server added now starts its Hysteria in SetRules, and its
// host must already pass.
func (c *Controller) applyDNSLocked() {
	if c.sess == nil {
		return
	}
	pol := c.dnsPolicyLocked()
	if err := c.sess.SetDNS(pol); err != nil {
		c.Log.Warn("DNS settings not applied to the running session", "err", err)
		return
	}
	if pol != nil {
		c.dnsSess.Store(&dnsSessRef{sess: c.sess, dns: true})
	}
}

// dnsRulesChanged: saved rules (or a rule profile switch) change what
// HyRoute answers while it resolves by the rules.
func (c *Controller) dnsRulesChangedLocked() bool {
	return c.sess != nil && c.dns.ByRules && c.dnsBroken == nil
}

// dnsTunnelUp flushes the cache when a server's tunnel came up after names
// were refused (SERVFAIL) or passed during the portal pause since the last
// flush. Called by the Hysteria status callback: no lock of c's.
func (c *Controller) dnsTunnelUp(st hysteria.Status) {
	if st.State != hysteria.Connected {
		return
	}
	ref := c.dnsSess.Load()
	if ref == nil || !ref.dns {
		return
	}
	s := ref.sess.Stats()
	n := s.DNSFailed + s.DNSPortalPassed
	c.dnsFlush.mu.Lock()
	grew := n > c.dnsFlush.failed
	c.dnsFlush.mu.Unlock()
	if grew {
		c.flushDNSAsync("tunnel up")
	}
}

// dnsExitFlush is Shutdown's DNS part, after the filters are gone: a flush
// still waiting (the one of the session just stopped, or of a Disconnect
// just before) runs now rather than after the rate limit's wait, since the
// process ends next. Bounded by exitFlushWait.
func (c *Controller) dnsExitFlush() {
	if c.FlushDNS == nil {
		return
	}
	f := &c.dnsFlush
	f.mu.Lock()
	due := f.pending > 0
	f.mu.Unlock()
	if !due {
		return
	}
	done := make(chan error, 1)
	go func() { done <- c.FlushDNS() }()
	select {
	case err := <-done:
		if err != nil {
			c.Log.Warn("windows DNS cache not flushed", "reason", "exit", "err", err)
		}
	case <-time.After(exitFlushWait):
		c.Log.Warn("windows DNS cache not flushed", "reason", "exit", "err", "timeout")
	}
}

// flushDNSAsync empties the Windows DNS cache on a goroutine, at most once
// per flushGap. A failure is logged.
func (c *Controller) flushDNSAsync(reason string) {
	if c.FlushDNS == nil {
		return
	}
	f := &c.dnsFlush
	f.mu.Lock()
	if f.scheduled {
		f.mu.Unlock()
		return // the flush waiting covers this one
	}
	wait := flushGap - time.Since(f.last)
	f.scheduled = true
	f.pending++
	f.mu.Unlock()
	go func() {
		if wait > 0 {
			time.Sleep(wait)
		}
		var failed int64
		if ref := c.dnsSess.Load(); ref != nil {
			s := ref.sess.Stats()
			failed = s.DNSFailed + s.DNSPortalPassed
		}
		f.mu.Lock()
		f.scheduled, f.last, f.failed = false, time.Now(), failed
		f.mu.Unlock()
		err := c.FlushDNS()
		f.mu.Lock()
		f.pending--
		f.mu.Unlock()
		if err != nil {
			c.Log.Warn("windows DNS cache not flushed", "reason", reason, "err", err)
		}
	}()
}

// ---- the card ----

// DNSView is the «DNS» card.
type DNSView struct {
	Config  dnspolicy.Config `json:"config"`          // Direct.Preset "" = off; Tunnel.Preset "" shown as "cloudflare"
	Presets []DNSPreset      `json:"presets"`         //
	Error   string           `json:"error,omitempty"` // dns.json not loaded
}

// DNSPreset is a server the card offers.
type DNSPreset struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Tunnel bool   `json:"tunnel"`
	Direct bool   `json:"direct"`
}

// DNS returns the card's settings.
func (c *Controller) DNS() DNSView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := DNSView{Config: c.dns}
	if v.Config.Tunnel.Preset == "" {
		v.Config.Tunnel.Preset = dnspolicy.DefaultTunnel
	}
	if c.dnsBroken != nil {
		v.Error = dnsLoadReason(c.dnsBroken)
	}
	for _, p := range dnspolicy.Presets {
		v.Presets = append(v.Presets, DNSPreset{ID: p.ID, Name: p.Name, URL: p.URL, Tunnel: p.Tunnel, Direct: p.Direct})
	}
	return v
}

// DNSConfig is the saved configuration (backup); an error while dns.json
// is broken.
func (c *Controller) DNSConfig() (dnspolicy.Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dnsBroken != nil {
		return dnspolicy.Config{}, c.dnsBroken
	}
	return c.dns, nil
}

// SaveDNS validates, stores dns.json and applies at once.
func (c *Controller) SaveDNS(cfg dnspolicy.Config) error {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	c.saveMu.Lock()
	c.mu.Lock()
	broken := c.dnsBroken
	c.mu.Unlock()
	if broken != nil {
		c.saveMu.Unlock()
		return fmt.Errorf("dns.json не загружен, изменения не сохраняются: %s", dnsLoadReason(broken))
	}
	if err := c.Store.SaveDNS(cfg); err != nil {
		c.saveMu.Unlock()
		return err
	}
	c.mu.Lock()
	err := c.dnsInstallLocked(cfg)
	connected := c.sess != nil
	c.mu.Unlock()
	c.saveMu.Unlock()
	if connected {
		c.flushDNSAsync("dns settings")
	}
	c.Log.Info("DNS settings saved", "byRules", cfg.ByRules, "tunnel", cfg.Tunnel.LogName(true), "direct", cfg.Direct.LogName(false),
		"blockBrowserDoH", cfg.BlockBrowserDoH, "stripECH", cfg.StripECH, "addrRules", !cfg.IgnoreAddrRules)
	c.changed()
	if err != nil {
		return fmt.Errorf("настройки DNS сохранены, но не применены: %v", err)
	}
	return nil
}

// dnsInstallLocked makes cfg the DNS settings in memory and applies them
// to the running session (c.mu held; no I/O). Backup's restore uses it too.
// A session that ever had a policy keeps its disconnect flush.
func (c *Controller) dnsInstallLocked(cfg dnspolicy.Config) error {
	c.dns, c.dnsBroken = cfg, nil
	c.dnsWarned.Store(false)
	c.Redactor.SetGroup("dns", dnsSecrets(cfg)...)
	if !cfg.ByRules {
		c.dnsPause = time.Time{}
	}
	if c.sess == nil {
		return nil
	}
	pol := c.dnsPolicyLocked()
	if err := c.sess.SetDNS(pol); err != nil {
		return err
	}
	if pol != nil {
		c.dnsSess.Store(&dnsSessRef{sess: c.sess, dns: true})
	}
	if pol == nil || !pol.Cfg.ByRules {
		c.sess.PauseDNS(time.Time{})
	}
	return nil
}

// PauseDNSTunnel lets tunnel names whose tunnel is unavailable pass as
// before for 5 minutes (a captive portal: hotel or airport Wi-Fi).
func (c *Controller) PauseDNSTunnel() error {
	c.mu.Lock()
	switch {
	case c.sess == nil:
		c.mu.Unlock()
		return errors.New("HyRoute не подключён")
	case !c.dns.ByRules || c.dnsBroken != nil:
		c.mu.Unlock()
		return errors.New("DNS по правилам не включён")
	}
	c.dnsPause = time.Now().Add(dnsPauseFor)
	c.sess.PauseDNS(c.dnsPause)
	c.mu.Unlock()
	c.flushDNSAsync("portal pause")
	c.Log.Info("DNS portal pause started", "minutes", int(dnsPauseFor/time.Minute))
	c.changed()
	return nil
}

// CancelDNSPause ends the pause early.
func (c *Controller) CancelDNSPause() {
	c.mu.Lock()
	had := !c.dnsPause.IsZero()
	c.dnsPause = time.Time{}
	if c.sess != nil {
		c.sess.PauseDNS(time.Time{})
	}
	c.mu.Unlock()
	if had {
		c.Log.Info("DNS portal pause ended")
		c.changed()
	}
}

// ---- status ----

// DNSStatus is Status.DNS: what Home and the card warn about.
type DNSStatus struct {
	ByRules   bool        `json:"byRules"`
	Direct    bool        `json:"direct"`
	Health    []DNSHealth `json:"health,omitempty"`    // down upstream clients
	PauseLeft int         `json:"pauseLeft,omitempty"` // captive-portal pause, seconds left
}

// DNSHealth is an upstream server that does not answer.
type DNSHealth struct {
	Via      string `json:"via"`               // "tunnel" | "direct"
	Profile  string `json:"profile,omitempty"` // tunnel: the server's ID (the UI shows its name)
	Upstream string `json:"upstream"`          // preset name or "свой сервер", never the URL
	Kind     string `json:"kind"`              // timeout | connect | tls | http | answer
	Code     int    `json:"code,omitempty"`
	RetryIn  int    `json:"retryIn"` // seconds, ≥ 0
}

// dnsStatusLocked is Status.DNS while a session runs (c.mu held).
func (c *Controller) dnsStatusLocked(s Session) *DNSStatus {
	if s == nil || c.dnsBroken != nil || !c.dns.Active() {
		return nil
	}
	st := &DNSStatus{ByRules: c.dns.ByRules, Direct: c.dns.Direct.Preset != ""}
	now := time.Now()
	if left := c.dnsPause.Sub(now); left > 0 && c.dns.ByRules {
		st.PauseLeft = int((left + time.Second - 1) / time.Second)
	}
	for _, h := range s.DNSHealth() {
		v := DNSHealth{Via: h.Via.String(), Profile: h.Profile, Kind: h.Kind, Code: h.Code, RetryIn: max(int(h.RetryAt.Sub(now)/time.Second), 0)}
		if h.Via == dnspolicy.ViaTunnel {
			v.Upstream = c.dns.Tunnel.UpstreamName(true)
		} else {
			v.Upstream = c.dns.Direct.UpstreamName(false)
		}
		st.Health = append(st.Health, v)
	}
	return st
}

// ---- Explain ----

// DNSExplain is the DNS line of «Проверить адрес».
type DNSExplain struct {
	Route    string `json:"route"`              // tunnel | block | upstream | direct | addr | server | local | service
	Profile  string `json:"profile,omitempty"`  // tunnel: rule target (server or group ID)
	Upstream string `json:"upstream,omitempty"` // preset name or "свой сервер"
	Rule     string `json:"rule,omitempty"`     // tunnel/block/addr: rule name ("default" = «Всё остальное»)
	Cond     string `json:"cond,omitempty"`     // tunnel/block from a conditional rule: "app" | "proto"
	Proto    string `json:"proto,omitempty"`    // cond "proto": "tcp" | "udp"
	NoIPv6   bool   `json:"noIPv6,omitempty"`
}

// explainDNS says how the name domain would resolve with the DNS settings
// and the rules cfg (the editor's unsaved ones when given). app "" is the
// Windows DNS client.
func (c *Controller) explainDNS(domain, app string, cfg rules.Config, main string, ipv6Blocked bool) *DNSExplain {
	if domain == "" {
		return nil
	}
	c.mu.Lock()
	pol := c.dnsPolicyLocked()
	dcfg := c.dns
	c.mu.Unlock()
	if pol == nil || !dcfg.ByRules && dcfg.Direct.Preset == "" {
		return nil
	}
	set, err := rules.Compile(cfg)
	if err != nil {
		return nil
	}
	set.Main = main
	env := dnspolicy.Env{Rules: set, IPv6Blocked: ipv6Blocked}
	if c.LocalSuffixes != nil {
		info := suffixInfo(c.LocalSuffixes())
		env.Local = info.Local
	}
	req := dnspolicy.Requester{System: true}
	if app = strings.TrimSpace(app); app != "" {
		name := strings.ToLower(filepath.Base(strings.ReplaceAll(app, `\`, "/")))
		if !strings.Contains(name, ".") {
			name += ".exe"
		}
		req = dnspolicy.Requester{Proc: &procinfo.Info{Name: name, Path: app}}
	}
	name := rules.NormalizeDomain(domain)
	d := pol.Classify(dnspolicy.Question{Name: name, Type: dnsmessage.TypeA}, req, env)
	ex := &DNSExplain{Rule: d.Rule}
	switch {
	case d.Kind == dnspolicy.Pass && d.Local != "":
		ex.Route = d.Local
		if d.Local != "addr" {
			ex.Rule = ""
		}
	case d.Kind == dnspolicy.Pass:
		ex.Route, ex.Rule = "direct", ""
	case d.Kind == dnspolicy.Answer:
		ex.Route = "block"
	case d.Via == dnspolicy.ViaDirect:
		ex.Route, ex.Rule, ex.Upstream = "upstream", "", pol.DirectSpec.Name
	default:
		ex.Route, ex.Profile, ex.Upstream = "tunnel", d.Route.Profile, pol.TunnelSpec.Name
		d6 := pol.Classify(dnspolicy.Question{Name: name, Type: dnsmessage.TypeAAAA}, req, env)
		ex.NoIPv6 = d6.Kind == dnspolicy.Answer && d6.Rule == dnspolicy.RuleNoIPv6
	}
	if ex.Route == "tunnel" || ex.Route == "block" {
		switch {
		case d.Cond&rules.CondApp != 0:
			ex.Cond = "app"
		case d.Cond&rules.CondProto != 0:
			ex.Cond = "proto"
			if r, ok := enabledRule(cfg, d.Pos); ok {
				// "any" (or empty) with ports: the card says «некоторых портов»
				if p := strings.ToLower(r.Protocol); p == "tcp" || p == "udp" {
					ex.Proto = p
				}
			}
		}
	}
	return ex
}

// enabledRule is the i-th enabled rule of cfg (the compiled set's index).
func enabledRule(cfg rules.Config, i int) (rules.Rule, bool) {
	n := 0
	for _, r := range cfg.Rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		if n == i {
			return r, true
		}
		n++
	}
	return rules.Rule{}, false
}

// ---- diagnostics ----

// dnsDiagLines are the DNS lines of the diagnostics: the settings (never a
// URL) and the session's counters.
func (c *Controller) dnsDiagLines(stats *session.Stats) []string {
	c.mu.Lock()
	cfg, broken := c.dns, c.dnsBroken
	c.mu.Unlock()
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	l := fmt.Sprintf("   DNS: byRules=%s tunnel=%s direct=%s blockBrowserDoH=%s stripECH=%s addrRules=%s", onOff(cfg.ByRules),
		cfg.Tunnel.LogName(true), cfg.Direct.LogName(false), onOff(cfg.BlockBrowserDoH), onOff(cfg.StripECH), onOff(!cfg.IgnoreAddrRules))
	if broken != nil {
		l += " loadError=" + broken.Error()
	}
	out := []string{l}
	if s := stats; s != nil && cfg.Active() {
		out = append(out, fmt.Sprintf("   DNS queries: tunnel=%d direct=%d passed=%d blocked=%d doh=%d failed=%d truncated=%d portalPassed=%d systemDoH=%d",
			s.DNSTunnel, s.DNSDirect, s.DNSPassed, s.DNSBlocked, s.DNSDoH, s.DNSFailed, s.DNSTruncated, s.DNSPortalPassed, s.SystemDoH))
	}
	return out
}

// suffixInfo is an Info with only local namespaces (Explain).
func suffixInfo(names []string) *sysdns.Info { return &sysdns.Info{Suffixes: sysdns.ParseNames(names)} }
