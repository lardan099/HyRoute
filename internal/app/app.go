// Package app is the controller behind the GUI and the tray: profiles,
// subscriptions, settings, routing on/off, status, connections and logs.
// It does not depend on Windows; the session starter is injected.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/dnsproxy"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Session is what the controller needs from a running session.
type Session interface {
	Stop()
	// ResetConnections resets the relayed connections while the filters
	// still reflect the resets (before a disconnect closes the kill
	// switch's pass; Stop resets any since).
	ResetConnections()
	SetRules(*rules.Set, []hysteria.Profile)
	Flows() *flows.Registry
	EngineFailed() bool
	Tunnels() []tunnels.Status
	Acquire(hysteria.Profile) (*tunnels.Endpoint, func())
	// DNSSites are the DNS cache names of an address grouped by site
	// (dnscache.Cache.Sites).
	DNSSites(netip.Addr) [][]string
	Stats() session.Stats
	// Endpoint is a running profile's tunnel (nil when not running).
	Endpoint(profile string) *tunnels.Endpoint
	// groups
	// ServerIPRoom is how many more server IPs the exclusions can take.
	ServerIPRoom() int
	// dns
	// SetDNS replaces the DNS policy (nil = off); DNSHealth lists the
	// resolver clients that are down; PauseDNS sets the captive-portal
	// pause (zero time: none).
	SetDNS(*dnspolicy.Policy) error
	DNSHealth() []dnsproxy.Health
	PauseDNS(until time.Time)
	// conn-rules
	// ECHPublicName reports whether name is an ECH public name as the
	// engine knows it (dnscache.Cache.PublicName).
	ECHPublicName(name string) bool
}

type Starter func(session.Config) (Session, error)

type Controller struct {
	Store *store.Store
	Start Starter
	// Base is copied into every session config (Dir, Exe, RunDir, Stub,
	// Hysteria, TCPOnly).
	Base session.Config

	Log       *slog.Logger // engine log (goes to EngineLog)
	EngineLog *logx.Journal
	// HysteriaLog merges every profile's Hysteria log ("[name] msg");
	// each profile also has its own journal (Logs("hysteria:<id>")).
	HysteriaLog *logx.Journal
	Redactor    *logx.Redactor
	// OnChange is called after the state changes (for UI events and the
	// tray icon). It must not block.
	OnChange func()
	// OnGiveUp is called, on a goroutine of its own, when HyRoute stops
	// reconnecting by itself after engine failures (see recover.go): the
	// user has to act, so the window shows.
	OnGiveUp func()
	// Version is sent as the subscription User-Agent.
	Version string
	// CoreVersion reports the Hysteria core in use (diagnostics).
	CoreVersion func() string
	// Updater checks and installs HyRoute and Hysteria updates (nil =
	// disabled).
	Updater *Updater
	// Runners starts Hysteria for profile checks outside a session (nil =
	// session.RunnerFactory(Base)).
	Runners tunnels.Factory
	// Fetch overrides the subscription download (tests).
	Fetch func(ctx context.Context, url string) (FetchResult, error)
	// KillSwitch closes the internet when routing stops without a
	// Disconnect (nil = not available).
	KillSwitch KillSwitch
	// ListRunning lists running programs (rule editor suggestions).
	ListRunning func() []procinfo.Running
	// ProxyFirewall allows exactly these local proxy ports from the local
	// network, TCP and UDP (an empty list removes that rule; nil = nothing
	// to do).
	ProxyFirewall func(tcp, udp []int) error
	// LegacyProxyUDP reports the UDP proxy rule of v1.2.0, which served UDP
	// on every LAN proxy (socks-udp keeps it on for them; nil = unknown).
	LegacyProxyUDP func() bool
	// foundation: OnSettings is called, holding no lock, after every
	// settings commit with the new revision (SettingsRev): pages holding a
	// copy of the settings reload. It must not block.
	OnSettings func(rev uint64)

	// lifeMu serializes Connect, disconnect, kill switch changes, the
	// automatic reconnect after an engine failure and the ports of local
	// proxies, so a Disconnect during a start is not lost. Taken before
	// mu, ksMu, proxyMu, recMu and netMu; after netActMu. stats: the
	// statistics' lock (internal/stats) is taken after all of these. Its I/O
	// lock (stats.ioMu) is never taken or waited for with any Controller lock
	// held, lifeMu included; the Disconnect path only samples in memory and
	// kicks RunStats.
	lifeMu sync.Mutex
	// saveMu keeps settings.json and c.settings in the same order. Taken
	// after netActMu; before mu and netMu.
	saveMu sync.Mutex
	// subMu guards subLocks (see lockSub). A subscription's own lock is
	// held across its download: taken before mu, never while holding it.
	subMu    sync.Mutex
	subLocks map[string]*subLock

	mu        sync.Mutex
	profiles  *store.Profiles
	settings  *settings.Settings
	set       *rules.Set // compiled settings; Main is filled per use
	loadErr   string
	sess      Session
	sessSet   *settings.Settings
	lastFlows *flows.Registry
	starting  bool
	startErr  string
	since     time.Time
	hyMu      sync.Mutex // guards hyLogs (not c.mu: see profileName)
	hyLogs    map[string]*logx.Journal
	names     atomic.Pointer[map[string]string] // profile ID -> name
	subs      []store.Subscription
	pending   map[string]pendingSub
	// A file that failed to load is never overwritten: its data would be
	// lost (e.g. DPAPI secrets from another Windows account, or rules a
	// newer HyRoute wrote). Only the defaults are in memory.
	profilesBroken, subsBroken error
	settingsBroken             error
	proxiesBroken              error
	prefsBroken                error
	prefs                      store.Prefs
	checkMgr                   *tunnels.Manager
	files                      logFiles
	geo                        geoState
	ksMu                       sync.Mutex // guards ks; never held with mu
	ks                         ksState
	runMu                      sync.Mutex
	runList                    []procinfo.Running
	runAt                      time.Time
	proxies                    []store.LocalProxy
	proxyMu                    sync.Mutex // guards proxyRuns, proxyFW; taken after mu, never before
	proxyRuns                  map[string]*proxyRun
	proxyFW                    *proxyPorts // nil: the rules are unknown
	// recoverDelay: how long after an engine failure the automatic
	// reconnect waits (tests change it).
	recoverDelay time.Duration
	recMu        sync.Mutex // guards rec; innermost: nothing is taken or called with it held
	rec          recoverState

	// failedStop: the last session stopped after its engine failed, and
	// routing did not come back since (see startLocked). Guarded by mu.
	failedStop bool

	// foundation: settingsRev is the settings revision: +1 by every
	// settings commit, at install under mu; 1 after Load (see SettingsRev).
	settingsRev atomic.Uint64
	// rulesAt is the settingsRev of the last commit that changed the
	// active rules part (guardRevLocked). Guarded by mu.
	rulesAt uint64

	// Feature state (one line per feature, landing order).
	groupsState
	portsState
	rulesetsState // rulesets: guarded by mu (rulesets.go)
	dnsState      // dns: DNS policies (dns.go)
	statsState    // stats: traffic statistics (stats.go)
	netmodesState // netmodes: «Сети», guarded by netMu (netmodes.go)
	proxyUDPState // socks-udp (proxies.go)
	cliState      // cli: prefsMu, the exit guard (cliapi.go)
	// conn-rules: undo entries under their own leaf lock (connrules.go)
	connRulesState
	backupState // backup: backupMu and importMu (backup.go)
}

// New builds a controller with journals and a logger.
func New(st *store.Store, start Starter, base session.Config, level slog.Leveler) *Controller {
	c := &Controller{
		Store:       st,
		Start:       start,
		Base:        base,
		EngineLog:   logx.NewJournal(10000),
		HysteriaLog: logx.NewJournal(10000),
		Redactor:    &logx.Redactor{},
		hyLogs:      map[string]*logx.Journal{},

		recoverDelay: engineRecoverDelay,
	}
	c.Log = slog.New(logx.NewHandler(c.EngineLog, c.Redactor, level, nil))
	c.initGroups()
	c.initStats()    // stats
	c.initNetModes() // netmodes
	return c
}

// Load reads profiles and settings. Errors are kept and shown in the UI;
// a broken file is never overwritten silently.
func (c *Controller) Load() error {
	var ls []loaded
	for _, name := range loadOrder[:5] { // profiles … dns.json
		ls = append(ls, c.loadFile(name, nil))
	}
	c.initGeo() // categories resolve while the settings compile
	ls = append(ls, c.loadFile("groups.json", ls[0].profiles), c.loadFile("settings.json", nil), c.loadFile("networks.json", nil))
	c.mu.Lock()
	c.installLoadedLocked(ls)
	loadErr := c.loadErr
	c.mu.Unlock()
	if note := loadedOf(ls, "settings.json").rules.Note; note != "" {
		c.Log.Info(note)
	}
	c.applyLogPrefs()
	if d := loadedOf(ls, "dns.json"); d.err == nil && d.dns.Active() {
		c.flushDNSAsync("start") // dns: answers of a run that crashed
	}
	c.loadStats() // stats: the collection mode (creates nothing)
	if c.Store != nil {
		// Files a killed run left half-written; an hour old: none is
		// being written now.
		if n := c.Store.SweepTemp(time.Now().Add(-time.Hour)); n > 0 {
			c.Log.Info("temporary files of an interrupted write removed", "count", n)
		}
	}
	c.groupsLog.Do(func() { c.groupsRT.Log = c.Log })
	if loadErr != "" {
		return errors.New(loadErr)
	}
	return nil
}

func (c *Controller) changed() {
	if c.OnChange != nil {
		c.OnChange()
	}
}

func (c *Controller) updateNamesLocked() {
	m := make(map[string]string, len(c.profiles.List))
	for _, p := range c.profiles.List {
		m[p.ID] = p.Name
	}
	c.groupNamesLocked(m)
	c.names.Store(&m)
	c.dropLogsOf(m)
}

// stubProfile stands for every profile in stub mode.
const stubProfile = "stub"

// routingLocked returns the rule set with the main target filled in, the
// profiles it sends traffic to and the groups it uses (their members run).
// c.mu must be held.
func (c *Controller) routingLocked() (*rules.Set, []hysteria.Profile, []string) {
	set := *c.set
	set.Main = c.mainTargetLocked()
	if c.Base.Stub && set.Main == "" {
		set.Main = stubProfile
	}
	used := map[string]bool{}
	for _, id := range set.Profiles() {
		used[id] = true
	}
	for _, p := range c.proxies {
		if p.Enabled {
			used[c.proxyProfileLocked(p)] = true
		}
	}
	usedGroups := c.expandGroupsLocked(used)
	var want []hysteria.Profile // in list order
	for _, p := range c.profiles.List {
		if used[p.ID] {
			want = append(want, p)
		}
	}
	if c.Base.Stub && used[stubProfile] {
		want = append(want, hysteria.Profile{ID: stubProfile, Name: "stub"})
	}
	return &set, want, usedGroups
}

// applyRoutingLocked pushes the current rules and profiles to the running
// session (c.mu must be held).
func (c *Controller) applyRoutingLocked() {
	if c.sess == nil {
		return
	}
	set, want, _ := c.routingLocked()
	c.applyDNSLocked() // dns: before SetRules starts a new server's Hysteria
	c.sess.SetRules(set, want)
}
