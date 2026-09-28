package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

const threeServers = "hy2://a@de1.example:443#DE1\nhy2://a@de2.example:443#DE2\nhy2://a@nl1.example:443#NL1"

// servers imports three manual servers and returns their IDs.
func servers(t *testing.T, c *Controller) (de1, de2, nl1 string) {
	t.Helper()
	res, err := c.ImportURIs(threeServers)
	if err != nil || len(res.Added) != 3 {
		t.Fatal(res, err)
	}
	return res.Added[0].ID, res.Added[1].ID, res.Added[2].ID
}

func saveGroup(t *testing.T, c *Controller, name string, s groups.Strategy, members ...string) string {
	t.Helper()
	v, err := c.SaveGroup(groups.Group{Name: name, Strategy: s, Members: members})
	if err != nil {
		t.Fatal(err)
	}
	if !groups.ValidID(v.ID) {
		t.Fatalf("group ID %q", v.ID)
	}
	return v.ID
}

func setRules(t *testing.T, c *Controller, def rules.Action, defProfile string, rs ...rules.Rule) {
	t.Helper()
	st := c.Settings()
	st.DefaultAction, st.DefaultProfile, st.Rules = def, defProfile, rs
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
}

func curlRule(target string, fallback ...string) rules.Rule {
	return rules.Rule{Name: "curl", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Tunnel, Profile: target, Fallback: fallback}
}

func fileBytes(t *testing.T, c *Controller, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- a session with endpoints ----

// ctlRunner is a Hysteria stand-in a test switches up and down.
type ctlRunner struct {
	h       tunnels.Hooks
	c       socks5.Client
	up      atomic.Bool
	retry   atomic.Bool // down and reconnecting after it worked
	noUDP   bool
	dialErr error
}

func (r *ctlRunner) Start() error { r.set(true); return nil }
func (r *ctlRunner) Stop()        { r.set(false) }
func (r *ctlRunner) set(up bool) {
	r.retry.Store(false)
	r.up.Store(up)
	if r.h.OnStatus != nil {
		r.h.OnStatus(r.Status())
	}
}

// reconnect is the supervisor's Connecting phase after a failure.
func (r *ctlRunner) reconnect() {
	r.up.Store(false)
	r.retry.Store(true)
	if r.h.OnStatus != nil {
		r.h.OnStatus(r.Status())
	}
}
func (r *ctlRunner) Status() hysteria.Status {
	if r.retry.Load() {
		return hysteria.Status{State: hysteria.Connecting, Restarts: 1}
	}
	if r.up.Load() {
		return hysteria.Status{State: hysteria.Connected, UDPEnabled: !r.noUDP}
	}
	return hysteria.Status{State: hysteria.Failed, Message: "down"}
}
func (r *ctlRunner) Available() bool    { return r.up.Load() }
func (r *ctlRunner) UDPAvailable() bool { return r.up.Load() && !r.noUDP }
func (r *ctlRunner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	if r.dialErr != nil {
		return nil, r.dialErr
	}
	return r.c.Connect(ctx, dst)
}
func (r *ctlRunner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	return r.c.UDPAssociate(ctx)
}
func (r *ctlRunner) SOCKS() socks5.Client { return r.c }

// liveSession runs its profiles as tunnels endpoints of ctlRunners.
type liveSession struct {
	*fakeSession
	mgr  *tunnels.Manager
	room int
}

func (s *liveSession) SetRules(set *rules.Set, p []hysteria.Profile) {
	s.fakeSession.SetRules(set, p)
	s.mgr.Sync(p)
}
func (s *liveSession) Stop()                                { s.fakeSession.Stop(); s.mgr.StopAll() }
func (s *liveSession) Endpoint(id string) *tunnels.Endpoint { return s.mgr.Get(id) }
func (s *liveSession) Tunnels() []tunnels.Status            { return s.mgr.Statuses() }
func (s *liveSession) ServerIPRoom() int                    { return s.room }
func (s *liveSession) Acquire(p hysteria.Profile) (*tunnels.Endpoint, func()) {
	return s.mgr.Acquire(p)
}

type liveRig struct {
	c    *Controller
	mu   sync.Mutex
	runs map[string]*ctlRunner // routing runners by profile ID
	temp atomic.Int32          // temporary (check) runners started
	sess *liveSession
	// socks is where runners' SOCKS5 goes (dials to web whatever the
	// destination); slow members use black.
	socks, black *socks5.Server
	slow         map[string]bool
	web          *httptest.Server
	room         int
}

func newLiveRig(t *testing.T) *liveRig {
	t.Helper()
	c, _ := newCtl(t)
	r := &liveRig{c: c, runs: map[string]*ctlRunner{}, slow: map[string]bool{}, room: 100}
	r.web = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(r.web.Close)
	r.socks = &socks5.Server{Dial: func(string, string) (net.Conn, error) { return net.Dial("tcp", r.web.Listener.Addr().String()) }}
	if err := r.socks.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.socks.Close() })
	// A server that accepts and never answers.
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hole.Close() })
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	r.black = &socks5.Server{Dial: func(string, string) (net.Conn, error) { return net.Dial("tcp", hole.Addr().String()) }}
	if err := r.black.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.black.Close() })
	factory := func(test bool) tunnels.Factory {
		return func(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
			srv := r.socks
			r.mu.Lock()
			if r.slow[p.ID] {
				srv = r.black
			}
			run := &ctlRunner{h: h, c: socks5.Client{Server: srv.Addr()}}
			if test {
				r.temp.Add(1)
			} else {
				r.runs[p.ID] = run
			}
			r.mu.Unlock()
			return run
		}
	}
	c.Runners = factory(true)
	c.Start = func(cfg session.Config) (Session, error) {
		m := &tunnels.Manager{Log: c.Log, OnStatus: cfg.OnStatus, OnDial: cfg.OnDial, OnHealth: cfg.OnHealth}
		base := factory(false)
		m.New = func(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
			if strings.HasPrefix(h.RedactGroup, "profile:test:") {
				return factory(true)(p, h)
			}
			return base(p, h)
		}
		s := &liveSession{fakeSession: &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}, mgr: m, room: r.room}
		s.SetRules(cfg.Rules, cfg.Profiles)
		r.sess = s
		return s, nil
	}
	return r
}

func (r *liveRig) runner(id string) *ctlRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs[id]
}

func (r *liveRig) running(t *testing.T) string {
	t.Helper()
	return ids(r.sess.fakeSession.profiles)
}

// ---- tests ----

// Only groups the routing uses run their members; a proxy's group too.
func TestGroupMembersRunWhenUsed(t *testing.T) {
	c, started := newCtl(t)
	de1, de2, nl1 := servers(t, c)
	auto := saveGroup(t, c, "Авто", groups.Latency, de1, de2)
	saveGroup(t, c, "Запас", groups.Failover, nl1)
	setRules(t, c, rules.Direct, "", curlRule(auto))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	if ids(f.cfg.Profiles) != "DE1,DE2" || f.cfg.Groups != c.groupsRT || f.cfg.OnDial == nil || f.cfg.OnHealth == nil {
		t.Fatalf("started %s", ids(f.cfg.Profiles))
	}
	// A disabled rule does not make a group run.
	off := false
	r := curlRule(auto)
	r.Enabled = &off
	setRules(t, c, rules.Direct, "", r)
	if ids(f.profiles) != "" {
		t.Fatalf("disabled rule runs %s", ids(f.profiles))
	}
	// A local proxy through a group runs its members.
	port := freePort(t)
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Enabled: true, Profile: auto, Port: port}}); err != nil {
		t.Fatal(err)
	}
	if ids(f.profiles) != "DE1,DE2" {
		t.Fatalf("proxy group runs %s", ids(f.profiles))
	}
	if v := c.Proxies()[0]; v.ProfileName != "Авто" {
		t.Fatalf("%+v", v)
	}
	c.Disconnect()
}

func TestGroupMain(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	auto := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	profilesBefore := fileBytes(t, c, "profiles.json")
	if err := c.SetMain(auto); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(profilesBefore, fileBytes(t, c, "profiles.json")) {
		t.Fatal("a group main rewrote profiles.json")
	}
	c.mu.Lock()
	set, _, used := c.routingLocked()
	c.mu.Unlock()
	if set.Main != auto || len(used) != 0 { // no rule uses the main yet
		t.Fatalf("main %q used %v", set.Main, used)
	}
	st := c.Status()
	if st.MainID != auto || st.Main != "Авто" || st.MainGroup == nil || st.MainGroup.Total != 2 || st.MainUnloaded {
		t.Fatalf("%+v", st)
	}
	for _, p := range c.Profiles() {
		if p.Main {
			t.Fatal("a server is main while a group is")
		}
	}
	// A server main clears the group main.
	if err := c.SetMain(de2); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.MainID != de2 || st.MainGroup != nil {
		t.Fatalf("%+v", st)
	}
	if f, _ := c.Store.LoadGroups(); f.Main != "" {
		t.Fatal("groups.json main not cleared")
	}
	// A group without existing servers cannot become the main.
	lone := saveGroup(t, c, "Один", groups.Failover, de1)
	if err := c.DeleteProfile(de1); err != nil {
		t.Fatal(err)
	}
	if err := c.SetMain(lone); err == nil || err.Error() != "В группе «Один» нет серверов — её нельзя сделать основной" {
		t.Fatal(err)
	}
}

// With no group main, choosing a server never creates groups.json.
func TestSetMainWithoutGroupsWritesNoFile(t *testing.T) {
	c, _ := newCtl(t)
	_, de2, _ := servers(t, c)
	if err := c.SetMain(de2); err != nil {
		t.Fatal(err)
	}
	c.Groups()
	c.Status()
	c.RuleWarnings()
	c.Diagnostics(nil, false)
	// «Сохранить» on the default probe settings changes nothing.
	if err := c.SetProbe(groups.Probe{URL: groups.DefaultProbeURL, IntervalSec: 60}); err != nil {
		t.Fatal(err)
	}
	if fileBytes(t, c, "groups.json") != nil {
		t.Fatal("groups.json created without groups")
	}
	if err := c.SetProbe(groups.Probe{IntervalSec: 90}); err != nil || fileBytes(t, c, "groups.json") == nil {
		t.Fatal("changed probe settings not saved", err)
	}
}

// A server main while a group is main: profiles.json first; a failed
// groups.json write leaves the group in charge and says so.
func TestSetMainServerGroupWriteFails(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	auto := saveGroup(t, c, "Авто", groups.Failover, de1)
	if err := c.SetMain(auto); err != nil {
		t.Fatal(err)
	}
	// A folder in its place: the write of groups.json fails.
	path := filepath.Join(c.Store.Dir, "groups.json")
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := c.SetMain(de2)
	if err == nil || !strings.HasPrefix(err.Error(), "Основной осталась группа «Авто»: не удалось записать groups.json") {
		t.Fatal(err)
	}
	c.mu.Lock()
	main, active := c.mainTargetLocked(), c.profiles.Active
	c.mu.Unlock()
	if main != auto || active != de2 {
		t.Fatalf("main %s active %s", main, active)
	}
}

// Editing one group never fails because of another one's empty or
// dangling member list; the dangling IDs go on the next write.
func TestOneBrokenGroupDoesNotBlockOthers(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	f := &groups.File{Version: 1, Groups: []groups.Group{
		{ID: "grp-00000000000b", Name: "B", Strategy: groups.Failover, Members: []string{}},
		{ID: "grp-00000000000c", Name: "C", Strategy: groups.Failover, Members: []string{de1, "deadbeef0000"}},
		{ID: "grp-0000000000a2", Name: "A2", Strategy: groups.Random, Members: []string{de2}},
	}}
	if err := c.Store.SaveGroups(f); err != nil {
		t.Fatal(err)
	}
	c, _ = newCtlAt(t, c.Store)
	a := saveGroup(t, c, "A", groups.RoundRobin, de1, de2)
	if err := c.SetProbe(groups.Probe{IntervalSec: 120}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetMain(a); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup("grp-0000000000a2"); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Store.LoadGroups()
	if b := got.Find("grp-00000000000b"); b == nil || len(b.Members) != 0 {
		t.Fatalf("%+v", got)
	}
	if cg := got.Find("grp-00000000000c"); !slices.Equal(cg.Members, []string{de1}) {
		t.Fatalf("dangling member kept: %v", cg.Members)
	}
	if _, err := c.SaveGroup(groups.Group{ID: "grp-00000000000b", Name: "B", Strategy: groups.Failover}); err == nil {
		t.Fatal("empty group saved")
	}
	// B is empty: rules through it warn.
	setRules(t, c, rules.Direct, "", curlRule("grp-00000000000b"))
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Kind != "empty" || w[0].Text != "в группе «B» нет серверов: соединения будут отклоняться" {
		t.Fatalf("%+v", w)
	}
}

func TestSaveGroupValidation(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	for g, want := range map[*groups.Group]string{
		{Name: " ", Strategy: groups.Failover, Members: []string{de1}}:                          "Укажите название группы",
		{Name: "A", Strategy: groups.Failover}:                                                  "Добавьте в группу хотя бы один сервер",
		{Name: "A", Strategy: "best", Members: []string{de1}}:                                   `Неизвестный способ выбора сервера "best"`,
		{Name: "A", Strategy: groups.Failover, SwitchAfterErrors: 1, Members: []string{de1}}:    "Число ошибок — от 2 до 20",
		{Name: "A", Strategy: groups.Latency, ToleranceMs: 5, Members: []string{de1}}:           "Порог переключения — от 10 до 1000 мс",
		{Name: strings.Repeat("я", 65), Strategy: groups.Failover, Members: []string{de1}}:      "Название группы — не длиннее 64 символов",
		{ID: "grp-00000000000f", Name: "A", Strategy: groups.Failover, Members: []string{de1}}:  "Группа не найдена",
		{Name: "A", Strategy: groups.Failover, Members: []string{de1, "grp-000000000001"}}:      "Сервер grp-000000000001 не найден",
		{Name: "A", Strategy: groups.Failover, Members: []string{"gone0000000", "gone1111111"}}: "Добавьте в группу хотя бы один сервер",
	} {
		if _, err := c.SaveGroup(*g); err == nil || err.Error() != want {
			t.Errorf("%+v: %v, want %q", *g, err, want)
		}
	}
	// A dangling member is dropped silently; options that do not apply go.
	v, err := c.SaveGroup(groups.Group{Name: " Авто ", Strategy: groups.RoundRobin, Revert: true, ToleranceMs: 70, Members: []string{de1, "deadbeef0000", de2}})
	if err != nil || v.Name != "Авто" || !slices.Equal(v.Members, []string{de1, de2}) || v.Revert || v.ToleranceMs != 0 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := c.SaveGroup(groups.Group{Name: "авто", Strategy: groups.Failover, Members: []string{de1}}); err == nil || err.Error() != "Группа «авто» уже есть" {
		t.Fatal(err)
	}
}

// A used group is never emptied by its subscription: an update or a
// deletion that would leave it without servers keeps them.
func TestSubscriptionNeverEmptiesUsedGroup(t *testing.T) {
	body := "hy2://a@s1.example:443#S1\nhy2://a@s2.example:443#S2\nhy2://a@s3.example:443#S3\n"
	setup := func(t *testing.T, used bool, manual bool) (*Controller, SubView, string) {
		c, _ := newCtl(t)
		b := body
		v := addSub(t, c, &b)
		var members []string
		for _, p := range c.Profiles() {
			members = append(members, p.ID)
		}
		// The main server is a manual one: the main is kept anyway.
		res, _ := c.ImportURIs("hy2://a@m.example:443#M")
		if err := c.SetMain(res.Added[0].ID); err != nil {
			t.Fatal(err)
		}
		if manual {
			members = append(members, res.Added[0].ID)
		}
		g := saveGroup(t, c, "Авто", groups.Latency, members...)
		if used {
			off := false
			r := curlRule(g)
			r.Enabled = &off // a disabled rule pins too
			setRules(t, c, rules.Direct, "", r)
		}
		return c, v, g
	}
	existing := func(c *Controller, g string) int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.existingLocked(c.groupsFile.Find(g).Members))
	}

	t.Run("update drops all", func(t *testing.T) {
		c, v, g := setup(t, true, false)
		c.Fetch = func(context.Context, string) (FetchResult, error) {
			return FetchResult{Body: []byte("hy2://a@other.example:443#X\n")}, nil
		}
		ms, err := c.UpdateSubscription(v.ID)
		if err != nil || ms.MissingKept != 3 || existing(c, g) != 3 {
			t.Fatalf("%+v %v", ms, err)
		}
		gv, _ := c.groupView(g, nil)
		if !gv.Views[0].NotInSub {
			t.Fatalf("%+v", gv.Views[0])
		}
		if w := c.RuleWarnings(); len(w) != 0 { // the rule is disabled
			t.Fatalf("%+v", w)
		}
	})
	t.Run("update drops some", func(t *testing.T) {
		c, v, g := setup(t, true, false)
		c.Fetch = func(context.Context, string) (FetchResult, error) {
			return FetchResult{Body: []byte("hy2://a@s1.example:443#S1\n")}, nil
		}
		ms, err := c.UpdateSubscription(v.ID)
		if err != nil || ms.Removed != 2 || ms.MissingKept != 0 || existing(c, g) != 1 {
			t.Fatalf("%+v %v", ms, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		c, v, g := setup(t, true, false)
		if err := c.DeleteSubscription(v.ID); err != nil {
			t.Fatal(err)
		}
		if existing(c, g) != 3 || c.Profiles()[0].Source != "" {
			t.Fatalf("%+v", c.Profiles())
		}
	})
	t.Run("unused", func(t *testing.T) {
		c, v, g := setup(t, false, false)
		if err := c.DeleteSubscription(v.ID); err != nil {
			t.Fatal(err)
		}
		if existing(c, g) != 0 || len(c.Profiles()) != 1 {
			t.Fatalf("%+v", c.Profiles())
		}
	})
	t.Run("manual member", func(t *testing.T) {
		c, v, g := setup(t, true, true)
		if err := c.DeleteSubscription(v.ID); err != nil {
			t.Fatal(err)
		}
		if existing(c, g) != 1 || len(c.Profiles()) != 1 {
			t.Fatalf("%+v", c.Profiles())
		}
	})
}

func TestDeleteGroupRefs(t *testing.T) {
	c, _ := newCtl(t)
	de1, _, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1)
	off := false
	r := curlRule(g)
	r.Enabled = &off
	setRules(t, c, rules.Direct, "", r)
	if err := c.DeleteGroup(g); err == nil || err.Error() != "Группа используется: curl. Выберите в них другой сервер или группу" {
		t.Fatal(err)
	}
	setRules(t, c, rules.Tunnel, "", rules.Rule{Name: "x", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: de1, Fallback: []string{g}})
	if err := c.DeleteGroup(g); err == nil || !strings.Contains(err.Error(), "x (запасной сервер)") {
		t.Fatal(err)
	}
	setRules(t, c, rules.Tunnel, g)
	if err := c.DeleteGroup(g); err == nil || !strings.Contains(err.Error(), "маршрут по умолчанию") {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "")
	port := freePort(t)
	pv, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "Биржа", Profile: g, Port: port}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(g); err == nil || !strings.Contains(err.Error(), "прокси «Биржа»") {
		t.Fatal(err)
	}
	c.DeleteProxy(pv.ID)
	// The main alone does not refuse: the active server is the main again.
	if err := c.SetMain(g); err != nil {
		t.Fatal(err)
	}
	// Settings broken: refused outright.
	c.mu.Lock()
	c.settingsBroken = errors.New("broken")
	c.mu.Unlock()
	if err := c.DeleteGroup(g); err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.settingsBroken = nil
	c.mu.Unlock()
	if err := c.DeleteGroup(g); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.MainID != de1 {
		t.Fatalf("main %s", st.MainID)
	}
}

func TestDeleteServerOfGroups(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, nl1 := servers(t, c)
	// A server no group holds: no groups.json at all.
	if err := c.DeleteProfile(nl1); err != nil || fileBytes(t, c, "groups.json") != nil {
		t.Fatal(err)
	}
	used := saveGroup(t, c, "Used", groups.Failover, de1)
	saveGroup(t, c, "Both", groups.Failover, de1, de2)
	setRules(t, c, rules.Direct, "", curlRule(used))
	err := c.DeleteProfile(de1)
	if err == nil || err.Error() != "Сервер — последний в группе «Used», которую используют: curl. Добавьте в группу другой сервер или удалите группу" {
		t.Fatal(err)
	}
	// Not in the used group: the others lose it at once.
	before := fileBytes(t, c, "groups.json")
	if err := c.DeleteProfile(de2); err != nil {
		t.Fatal(err)
	}
	f, _ := c.Store.LoadGroups()
	if both := f.Groups[1]; !slices.Equal(both.Members, []string{de1}) || bytes.Equal(before, fileBytes(t, c, "groups.json")) {
		t.Fatalf("%+v", both)
	}
	// A server no group holds leaves an existing groups.json alone.
	res, _ := c.ImportURIs("hy2://a@x.example:443#X")
	info, _ := os.Stat(filepath.Join(c.Store.Dir, "groups.json"))
	before = fileBytes(t, c, "groups.json")
	if err := c.DeleteProfile(res.Added[0].ID); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(c.Store.Dir, "groups.json"))
	if !bytes.Equal(before, fileBytes(t, c, "groups.json")) || !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("groups.json rewritten")
	}
}

// While profiles.json is broken groups.json is never written: a prune
// against the empty server list would strip every member.
func TestGroupsWhileProfilesBroken(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	a := saveGroup(t, c, "A", groups.Failover, de1)
	saveGroup(t, c, "B", groups.Latency, de2)
	setRules(t, c, rules.Direct, "", curlRule(a))
	os.WriteFile(filepath.Join(c.Store.Dir, "profiles.json"), []byte("{broken"), 0o600)
	c, started := newCtlAt2(t, c.Store)
	before := fileBytes(t, c, "groups.json")
	for name, err := range map[string]error{
		"SetProbe":    c.SetProbe(groups.Probe{IntervalSec: 30}),
		"DeleteGroup": c.DeleteGroup(a),
		"SetMain":     c.SetMain(a),
		"SaveGroup": func() error {
			_, err := c.SaveGroup(groups.Group{Name: "C", Strategy: groups.Failover, Members: []string{de1}})
			return err
		}(),
	} {
		if err == nil || !strings.HasPrefix(err.Error(), "profiles.json не загружен, группы не сохраняются") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !bytes.Equal(before, fileBytes(t, c, "groups.json")) {
		t.Fatal("groups.json changed")
	}
	// The groups have no member in memory: their traffic is refused.
	c.Connect()
	if f := (*started)[0]; len(f.cfg.Profiles) != 0 || c.groupsRT.Members(a) == nil || len(c.groupsRT.Members(a)) != 0 {
		t.Fatalf("%v", f.cfg.Profiles)
	}
	c.Disconnect()
}

// newCtlAt2 is newCtlAt for a store whose files may not load.
func newCtlAt2(t *testing.T, st *store.Store) (*Controller, *[]*fakeSession) {
	t.Helper()
	var started []*fakeSession
	c := New(st, func(cfg session.Config) (Session, error) {
		f := &fakeSession{reg: flows.NewRegistry(10), cfg: cfg, set: cfg.Rules, profiles: cfg.Profiles}
		started = append(started, f)
		return f, nil
	}, session.Config{}, nil)
	c.recoverDelay = time.Hour
	c.Load()
	return c, &started
}

// A hand-edited server ID with the group prefix is reported at load: it
// would be taken for a group and never run.
func TestServerWithGroupPrefix(t *testing.T) {
	c, _ := newCtl(t)
	servers(t, c)
	p, err := c.Store.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	p.List[1].ID = "grp-0000000000ab"
	if err := c.Store.SaveProfiles(p); err != nil {
		t.Fatal(err)
	}
	c2, _ := newCtlAt2(t, c.Store)
	if st := c2.Status(); !strings.Contains(st.LoadError, "у сервера «DE2» id начинается с grp- (grp-0000000000ab)") {
		t.Fatalf("%q", st.LoadError)
	}
}

// While groups.json is broken every server is protected, like while
// settings.json or proxies.json are.
func TestGroupsJSONBroken(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@s1.example:443#S1\nhy2://a@s2.example:443#S2\n"
	v := addSub(t, c, &body)
	ps := c.Profiles()
	g := saveGroup(t, c, "Авто", groups.Failover, ps[0].ID, ps[1].ID)
	if err := c.SetMain(g); err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "", rules.Rule{Name: "all", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Tunnel})
	good := fileBytes(t, c, "groups.json")
	broken := bytes.Replace(good, []byte(`"strategy": "failover"`), []byte(`"strategy": "best"`), 1)
	os.WriteFile(filepath.Join(c.Store.Dir, "groups.json"), broken, 0o600)
	c, _ = newCtlAt2(t, c.Store)
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://a@s1.example:443#S1\n")}, nil
	}
	st := c.Status()
	if st.MainID != g || !st.MainUnloaded || !strings.Contains(st.GroupsNote, "Основная группа не загружена") || !strings.Contains(st.LoadError, "groups.json") {
		t.Fatalf("%+v", st)
	}
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Text != "группы не загружены (groups.json): соединения будут отклоняться" {
		t.Fatalf("%+v", w)
	}
	if err := c.DeleteProfile(ps[0].ID); err == nil || !strings.HasPrefix(err.Error(), "groups.json не загружен: сервер не удаляется") {
		t.Fatal(err)
	}
	if err := c.SetMain(ps[0].ID); err == nil {
		t.Fatal("server main while a broken file names a group main")
	}
	if ms, err := c.UpdateSubscription(v.ID); err != nil || ms.MissingKept != 1 {
		t.Fatalf("%+v %v", ms, err)
	}
	if err := c.DeleteSubscription(v.ID); err != nil || len(c.Profiles()) != 2 {
		t.Fatalf("%v %+v", err, c.Profiles())
	}
	if !bytes.Equal(broken, fileBytes(t, c, "groups.json")) {
		t.Fatal("broken groups.json rewritten")
	}
	// Repaired: the group has all its members.
	os.WriteFile(filepath.Join(c.Store.Dir, "groups.json"), good, 0o600)
	c, _ = newCtlAt2(t, c.Store)
	gv, err := c.groupView(g, nil)
	if err != nil || gv.Missing != 0 || len(gv.Views) != 2 {
		t.Fatalf("%+v %v", gv, err)
	}
	// Unreadable: the main falls back to the server, and Status says so.
	os.WriteFile(filepath.Join(c.Store.Dir, "groups.json"), []byte("garbage"), 0o600)
	c, _ = newCtlAt2(t, c.Store)
	if st := c.Status(); st.MainID != ps[0].ID || !strings.Contains(st.GroupsNote, "сейчас вместо неё используется сервер «S1»") {
		t.Fatalf("%+v", st)
	}
}

// A group named only by a disabled rule does not run and is never
// reported down, but it cannot be deleted.
func TestGroupUsedOnlyByDisabledRule(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	off := false
	rule := curlRule(g)
	rule.Enabled = &off
	setRules(t, c, rules.Direct, "", rule)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	if r.running(t) != "" || r.runner(de1) != nil {
		t.Fatalf("members started: %s", r.running(t))
	}
	if st := c.Status(); st.State == "tunnel-down" || strings.Contains(st.Message, "Группа") {
		t.Fatalf("%+v", st)
	}
	if err := c.DeleteGroup(g); err == nil {
		t.Fatal("deleted")
	}
}

// A member down alone is not "tunnel-down" while its group has another
// usable member; every member down is, with the group's refusals.
func TestGroupStatusDown(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	setRules(t, c, rules.Direct, "", curlRule(g))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	if st := c.Status(); st.State != "connected" {
		t.Fatalf("%+v", st)
	}
	r.runner(de1).set(false)
	if st := c.Status(); st.State != "connected" {
		t.Fatalf("one member down: %+v", st)
	}
	// Reconnecting after a failure is not «connecting» either.
	r.runner(de1).reconnect()
	if st := c.Status(); st.State != "connected" {
		t.Fatalf("one member reconnecting: %+v", st)
	}
	r.runner(de1).set(false)
	r.runner(de2).set(false)
	c.groupsRT.NoteRejected(g)
	st := c.Status()
	if st.State != "tunnel-down" || !strings.Contains(st.Message, "Группа «Авто»: все серверы недоступны, отклонено соединений: 1") {
		t.Fatalf("%+v", st)
	}
	// A check of the group sends nothing through members that are down:
	// no probe failure, so the probe address is not blamed.
	for range 3 {
		v, err := c.ProbeGroup(g)
		if err != nil || v.Views[0].ProbeError != "не проверен: сервер не подключён" || v.ProbeBroken {
			t.Fatalf("%+v %v", v, err)
		}
	}
	if targets, _ := c.probeTargets(); len(targets) != 0 {
		t.Fatalf("members down probed: %v", targets)
	}
	info := c.Groups()
	if gv := info.Groups[0]; !gv.Running || gv.Up != 0 || gv.Rejected != 1 || gv.Views[0].State != "failed" || gv.ProbeBroken {
		t.Fatalf("%+v", gv)
	}
}

func TestExplainGroup(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	setRules(t, c, rules.Direct, "", curlRule(g))
	q := ExplainQuery{App: "curl.exe", Target: "1.2.3.4"}
	if ex := c.Explain(q, nil); !ex.Group || ex.ProfileName != "Авто" || ex.Via != "" || !slices.Contains(ex.Notes, "HyRoute не подключён: сервер группы выберется при подключении.") {
		t.Fatalf("%+v", ex)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	r.runner(de1).set(false)
	if ex := c.Explain(q, nil); ex.Via != "DE2" || !slices.Contains(ex.Notes, "Группа «Авто» (по порядку): сейчас соединение пошло бы через «DE2».") {
		t.Fatalf("%+v", ex)
	}
}

// A local proxy through a group dials the member the group chooses; with
// none usable it answers reply 1 and counts the refusal for the group.
func TestProxyThroughGroup(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.RoundRobin, de1, de2)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	p := store.LocalProxy{ID: "p1", Name: "Биржа", Enabled: true, Profile: g}
	c.mu.Lock()
	c.proxies = []store.LocalProxy{p}
	c.applyRoutingLocked()
	c.mu.Unlock()
	dial := c.proxyDialer(p)
	conn, err := dial(t.Context(), socks5.Addr{Host: "example.com", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	r.runner(de1).set(false)
	r.runner(de2).set(false)
	if _, err := dial(t.Context(), socks5.Addr{Host: "example.com", Port: 80}); !errors.Is(err, socks5.ReplyError(1)) {
		t.Fatal(err)
	}
	if h := c.groupsRT.Snapshot(g, func(string) bool { return false }); h.Rejected != 1 {
		t.Fatalf("%+v", h)
	}
}

// A local proxy's UDP association through a group goes through a member
// whose UDP works; with none it answers reply 1 and counts the refusal.
func TestProxyUDPThroughGroup(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	p := store.LocalProxy{ID: "p1", Name: "Биржа", Enabled: true, Profile: g}
	c.mu.Lock()
	c.proxies = []store.LocalProxy{p}
	c.applyRoutingLocked()
	s := c.sess
	c.mu.Unlock()
	assoc := c.proxyUDPDialer(p)
	via := func() *tunnels.Endpoint {
		t.Helper()
		u, err := assoc(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		return u.(*tunnelUDP).ep
	}
	if ep := via(); ep != s.Endpoint(de1) {
		t.Fatal("not through the first member")
	}
	r.runner(de1).set(false)
	if ep := via(); ep != s.Endpoint(de2) {
		t.Fatal("not through the second member")
	}
	r.runner(de2).set(false)
	if _, err := assoc(t.Context()); !errors.Is(err, socks5.ReplyError(1)) {
		t.Fatal(err)
	}
	if h := c.groupsRT.Snapshot(g, func(string) bool { return false }); h.Rejected != 1 {
		t.Fatalf("%+v", h)
	}
	// Statistics: each association under the member it went through, the
	// refusal under the group.
	recs := proxyUDPViews(c, "p1", true)
	if len(recs) != 3 || recs[0].Profile != de1 || recs[1].Profile != de2 || recs[1].Failover != true {
		t.Fatalf("%+v", recs)
	}
	for _, v := range recs[:2] {
		if v.Group != g || v.Outcome != "proxied" || v.Failed() {
			t.Fatalf("%+v", v)
		}
	}
	if v := recs[2]; v.Group != g || v.Profile != g || v.Outcome != "dropped: tunnel unavailable" || !v.Failed() {
		t.Fatalf("%+v", v)
	}
}

// A member whose endpoint disappears between the choice and the dial
// releases the trial it was chosen for.
func TestProxyGroupAbandonsTrial(t *testing.T) {
	c, _ := newCtl(t)
	de1, _, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1)
	c.mu.Lock()
	gf := c.groupsFile.Clone()
	gf.Groups[0].SwitchAfterErrors = 2
	c.mu.Unlock()
	c.groupsRT.SetGroups([]groups.Group{gf.Groups[0]})
	now := time.Unix(1_000_000, 0)
	c.groupsRT.SetClock(func() time.Time { return now })
	c.groupsRT.NoteDial(de1, "x:1", errors.New("fail"))
	c.groupsRT.NoteDial(de1, "y:1", errors.New("fail"))
	now = now.Add(groups.PenaltyFor)
	ep := (&tunnels.Manager{New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return &stubRunner{} }})
	ep.Sync([]hysteria.Profile{{ID: de1, Name: "DE1"}})
	defer ep.StopAll()
	s := &vanishingSession{fakeSession: &fakeSession{}, ep: ep.Get(de1)}
	_, err := c.proxyGroupDial(t.Context(), s, store.LocalProxy{ID: "p"}, g, socks5.Addr{Host: "a.example", Port: 443})
	if !errors.Is(err, socks5.ReplyError(1)) {
		t.Fatal(err)
	}
	if h := c.groupsRT.Snapshot(g, func(string) bool { return true }); h.Members[0].Reason == "trial" || h.Rejected != 1 {
		t.Fatalf("trial kept: %+v", h)
	}
}

// vanishingSession has the endpoint for the choice only.
type vanishingSession struct {
	*fakeSession
	ep    *tunnels.Endpoint
	calls atomic.Int32
}

func (s *vanishingSession) Endpoint(string) *tunnels.Endpoint {
	if s.calls.Add(1) > 1 {
		return nil
	}
	return s.ep
}

// A check through a reused routing endpoint never feeds its streak.
func TestCheckDoesNotFeedGroupHealth(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	c.mu.Lock()
	gf := c.groupsFile.Clone()
	gf.Groups[0].SwitchAfterErrors = 2
	c.mu.Unlock()
	if _, err := c.SaveGroup(gf.Groups[0]); err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "", curlRule(g))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	r.runner(de1).dialErr = errors.New("socks5: host unreachable")
	oldLat := latencyTarget
	latencyTarget = socks5.Addr{Host: "a.example", Port: 1}
	defer func() { latencyTarget = oldLat }()
	if res, _ := c.CheckProfile(de1); res.OK {
		t.Fatal("check passed")
	}
	if h := c.groupsRT.Snapshot(g, func(string) bool { return true }); h.Members[0].Errors != 0 {
		t.Fatalf("check fed the streak: %+v", h.Members[0])
	}
	// A routing dial does.
	ep := r.sess.Endpoint(de1)
	ep.Dial(t.Context(), socks5.Addr{Host: "b.example", Port: 1})
	if h := c.groupsRT.Snapshot(g, func(string) bool { return true }); h.Members[0].Errors != 1 {
		t.Fatalf("routing dial not noted: %+v", h.Members[0])
	}
}

// «Проверить» on a group: routing members in place, the others through a
// temporary Hysteria (not with too little address room), one run shared
// by concurrent calls, bounded by the budget.
func TestProbeGroup(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, nl1 := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Latency, de1, de2, nl1)
	// Disconnected: every member through a temporary Hysteria; two calls
	// share one run.
	var wg sync.WaitGroup
	views := make([]GroupView, 2)
	for i := range views {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.ProbeGroup(g)
			if err != nil {
				t.Error(err)
			}
			views[i] = v
		}()
	}
	wg.Wait()
	if n := r.temp.Load(); n != 3 {
		t.Fatalf("%d temporary Hysterias for one check", n)
	}
	for _, v := range views {
		for _, m := range v.Views {
			if m.ProbeAt == 0 || m.ProbeError != "" {
				t.Fatalf("%+v", m)
			}
		}
	}
	// Connected, de1 routing (a rule names it), nl1 never answers, a
	// short budget.
	setRules(t, c, rules.Direct, "", curlRule(de1))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	r.mu.Lock()
	r.slow[nl1] = true
	r.mu.Unlock()
	oldBudget := probeGroupBudget
	probeGroupBudget = 500 * time.Millisecond
	defer func() { probeGroupBudget = oldBudget }()
	r.temp.Store(0)
	v, err := c.ProbeGroup(g)
	if err != nil {
		t.Fatal(err)
	}
	if n := r.temp.Load(); n != 2 {
		t.Fatalf("%d temporary Hysterias, want 2 (de1 runs)", n)
	}
	if m := v.Views[2]; m.ProbeError != "нет результата за 60 с" {
		t.Fatalf("%+v", m)
	}
	// Too little room for temporary servers.
	r.sess.room = 3
	v, _ = c.ProbeGroup(g)
	if v.Views[1].ProbeError != "не проверен: запущено слишком много серверов" || v.Views[0].ProbeError != "" {
		t.Fatalf("%+v", v.Views)
	}
}

// Stub-like runners report their status: members get their uptime, and a
// failover group with revert returns to its first member after
// RevertAfter.
func TestGroupRevertThroughSession(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g, err := c.SaveGroup(groups.Group{Name: "Авто", Strategy: groups.Failover, Revert: true, Members: []string{de1, de2}})
	if err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "", curlRule(g.ID))
	now := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	c.groupsRT.SetClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	usable := endpointUsable(r.sess)
	if p, _ := c.groupsRT.Choose(g.ID, groups.Hint{}, usable); p.Member != de1 {
		t.Fatalf("%+v", p)
	}
	advance(time.Minute)
	r.runner(de1).set(false)
	if p, _ := c.groupsRT.Choose(g.ID, groups.Hint{}, usable); p.Member != de2 {
		t.Fatalf("%+v", p)
	}
	r.runner(de1).set(true)
	advance(groups.RevertAfter - time.Second)
	if p, _ := c.groupsRT.Choose(g.ID, groups.Hint{}, usable); p.Member != de2 {
		t.Fatalf("reverted early: %+v", p)
	}
	// «Проверить группу» meanwhile neither restarts de1's uptime nor
	// penalises it: the revert timer runs on.
	if v, err := c.ProbeGroup(g.ID); err != nil || v.Views[0].ProbeError != "" || v.Views[0].ProbeAt == 0 {
		t.Fatalf("%+v %v", v, err)
	}
	advance(time.Second)
	if p, _ := c.groupsRT.Choose(g.ID, groups.Hint{}, usable); p.Member != de1 {
		t.Fatalf("not reverted: %+v", p)
	}
}

// The main group as geodata's VPN route commits a member only when the
// download dials.
func TestGeoThroughMainGroup(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.RoundRobin, de1, de2)
	if err := c.SetMain(g); err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Tunnel, "")
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	usable := endpointUsable(r.sess)
	before, _ := c.groupsRT.Peek(g, groups.Hint{}, usable)
	tun := c.mainEndpoint()
	if tun == nil {
		t.Fatal("no VPN route")
	}
	if p, _ := c.groupsRT.Peek(g, groups.Hint{}, usable); p.Member != before.Member {
		t.Fatal("asking for the route committed a choice")
	}
	conn, err := tun.Dial(t.Context(), socks5.Addr{Host: "github.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if p, _ := c.groupsRT.Peek(g, groups.Hint{}, usable); p.Member == before.Member {
		t.Fatal("the dial did not choose")
	}
}

// Rule warnings of group targets.
func TestGroupRuleWarnings(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@s1.example:443#S1\n"
	v := addSub(t, c, &body)
	s1 := c.Profiles()[0].ID
	de1, _, _ := servers(t, c)
	subOnly := saveGroup(t, c, "Подписка", groups.Failover, s1)
	mixed := saveGroup(t, c, "Смесь", groups.Failover, s1, de1)
	setRules(t, c, rules.Tunnel, "", curlRule(subOnly, mixed, "grp-00000000000f"),
		rules.Rule{Name: "gone", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: "grp-00000000000f"})
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://a@other.example:443#X\n")}, nil
	}
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range c.RuleWarnings() {
		got = append(got, w.Rule+"|"+w.Kind+"|"+w.Text)
	}
	want := []string{
		"curl|missing|в группе «Подписка» остались только серверы, которых нет в подписке: выберите замену",
		"curl|deleted|запасная группа удалена: уберите её из правила",
		"gone|deleted|группа удалена: соединения будут отклоняться, выберите другую",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	// The main group, empty: a rule without a server says so.
	if err := c.SetMain(mixed); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.profiles.List = slices.DeleteFunc(c.profiles.List, func(p hysteria.Profile) bool { return true })
	c.syncGroupsLocked()
	w := c.ruleWarningsLocked()
	c.mu.Unlock()
	if len(w) == 0 || w[len(w)-1].Rule != "по умолчанию" || w[len(w)-1].Text != "в основной группе «Смесь» нет серверов: соединения будут отклоняться" {
		t.Fatalf("%+v", w)
	}
}

// Rules naming a group load without groups.json: they warn and fail
// closed (what v1.0.0 does with them too). No groups: routing and merges
// are what they were.
func TestGroupsCompatibility(t *testing.T) {
	c, _ := newCtl(t)
	de1, _, _ := servers(t, c)
	raw := []byte(`{"defaultAction":"direct","rules":[{"name":"g","apps":[{"pattern":"curl.exe"}],"action":"tunnel","profile":"grp-0123456789ab"}]}`)
	if _, _, err := settings.Parse(raw); err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "", curlRule("grp-0123456789ab"), curlRule(de1))
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Kind != "deleted" {
		t.Fatalf("%+v", w)
	}
	c.mu.Lock()
	set, want, used := c.routingLocked()
	c.mu.Unlock()
	if set.Main != c.profiles.Active || ids(want) != "DE1" || len(used) != 0 {
		t.Fatalf("%s %v", ids(want), used)
	}
	if ps := c.Profiles(); !ps[0].Main || ps[0].FastOpen {
		t.Fatalf("%+v", ps[0])
	}
	if fileBytes(t, c, "groups.json") != nil {
		t.Fatal("groups.json created")
	}
}

func TestResolveTarget(t *testing.T) {
	c, _ := newCtl(t)
	de1, _, nl1 := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1)
	for in, want := range map[string]string{"vpn": "", "основной": "", "NL": nl1, "группа:Авто": g, "авто": g, "id:" + g: g} {
		if id, err := c.ResolveTarget(in); err != nil || id != want {
			t.Errorf("%s: %q %v", in, id, err)
		}
	}
	if _, err := c.ResolveTarget("напрямую"); err == nil {
		t.Fatal("direct is no target")
	}
	if c.TargetName(g) != "Авто" || c.TargetName(nl1) != "NL1" || c.TargetName("") != "" {
		t.Fatal("TargetName")
	}
}

func TestGroupsDiagnostics(t *testing.T) {
	c, _ := newCtl(t)
	de1, _, _ := servers(t, c)
	saveGroup(t, c, "Авто", groups.Latency, de1)
	if err := c.SetProbe(groups.Probe{URL: "https://probe.example/SECRETTOKEN42/ping", IntervalSec: 120}); err != nil {
		t.Fatal(err)
	}
	d := c.Diagnostics(nil, false)
	if !strings.Contains(d, "== Группы") || !strings.Contains(d, `"Авто" самый быстрый, серверов 1`) ||
		!strings.Contains(d, "адрес проверки: https://probe.example/…, каждые 120 с") || strings.Contains(d, "SECRETTOKEN42") {
		t.Fatal(d)
	}
	for _, e := range c.Logs("engine", 0) {
		if strings.Contains(e.Msg, "SECRETTOKEN42") {
			t.Fatal("probe URL logged")
		}
	}
	if err := c.SetProbe(groups.Probe{URL: "http://192.168.1.1/"}); err == nil {
		t.Fatal("local probe URL accepted")
	}
	info := c.Groups()
	if info.Probe.IntervalSec != 120 || info.DefaultProbeURL != groups.DefaultProbeURL {
		t.Fatalf("%+v", info)
	}
}

// The v1.2.0 backup carries no groups: restoring its rules on the same
// computer keeps the rules that name a group of this computer, and only
// the unknown ones go to the main server.
func TestBackupRestoreKeepsGroupRefs(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	setRules(t, c, rules.Tunnel, g, curlRule(g, de2), curlRule("grp-00000000000f"))
	b, err := c.Backup(false, "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.RestoreBackup(b, "")
	if err != nil || r.Remapped != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	st := c.Settings()
	if st.DefaultProfile != g || st.Rules[0].Profile != g || !slices.Equal(st.Rules[0].Fallback, []string{de2}) || st.Rules[1].Profile != "" {
		t.Fatalf("%+v", st.Config)
	}
}
