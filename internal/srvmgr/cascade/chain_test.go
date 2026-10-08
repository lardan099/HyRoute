package cascade

// Chains of more than two servers (P4-08): one job deploys every link,
// from the exit towards the entry, and rolls all of it back on a failure;
// the unlink goes from the entry towards the exit.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const relayUP = `listen: :9443
acme:
  domains:
    - relay.example.com
auth:
  type: userpass
  userpass:
    bob: fake-bob-pass
`

const relay2PW = `listen: :7443
acme:
  domains:
    - relay2.example.com
auth:
  type: password
  password: fake-relay2-pass
`

// node is a server of a test chain.
type node struct {
	name, addr, cfg string
}

// chainWorld is a chain of several simulated servers, entry first.
type chainWorld struct {
	*world
	hosts []*host
	ids   []int64
}

// newChain makes a chain of the nodes on simulated hosts; each host
// pings the next.
func newChain(t *testing.T, nodes ...node) *chainWorld {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	w := &chainWorld{world: &world{t: t, db: db, keys: keys}}
	for _, n := range nodes {
		s := model.Server{Name: n.name, Host: n.addr, SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: binPath, Config: cfgPath, Unit: unitName, User: "hysteria", Version: "v2.12.3", Managed: true, At: time.Now()})
		c := model.ServerConfig{ServerID: s.ID, SHA256: sha([]byte(n.cfg)), Meta: model.ConfigMeta{TLS: "acme", Auth: "x"}, Source: model.ConfigDeploy, At: time.Now()}
		cfg := n.cfg
		db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) })
		w.ids = append(w.ids, s.ID)
		w.hosts = append(w.hosts, newHost(strings.ToLower(n.name), n.cfg))
	}
	for i := 0; i+1 < len(w.hosts); i++ {
		w.hosts[i].exit = w.hosts[i+1]
	}
	w.entry, w.exit = w.hosts[0], w.hosts[len(w.hosts)-1]
	w.in, w.out = w.ids[0], w.ids[len(w.ids)-1]
	now := time.Now()
	ch := model.Chain{Name: "Через три", Nodes: w.ids, Links: make([]model.ChainLink, len(w.ids)-1), CreatedAt: now, UpdatedAt: now}
	if err := db.CreateChain(ctx, &ch, nil); err != nil {
		t.Fatal(err)
	}
	w.chain = ch.ID
	w.linker, w.stop = w.controller()
	return w
}

// three is the chain entry → relay → exit (userpass on both the relay
// and the exit).
func three(t *testing.T) *chainWorld {
	return newChain(t, node{"Entry", "198.51.100.1", entryYAML}, node{"Relay", "198.51.100.2", relayUP}, node{"Exit", "203.0.113.2", exitUP})
}

// controller is world.controller with every host of the chain.
func (w *chainWorld) controller() (*Linker, func()) {
	hs := hosts{}
	for i, id := range w.ids {
		hs[id] = w.hosts[i]
	}
	eng := jobs.New(w.db, w.keys, redact.New(), hs, nil)
	eng.Poll = 10 * time.Millisecond
	l := New(Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 300 * time.Millisecond, Poll: 10 * time.Millisecond})
	eng.Register(l.Kind())
	eng.Register(l.UnlinkKind())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-done }) }
	w.t.Cleanup(stop)
	return l, stop
}

func (w *chainWorld) deploy() (model.Job, string) {
	w.t.Helper()
	j, err := w.linker.Deploy(context.Background(), w.chain, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.wait(j)
}

func (w *chainWorld) unlinkAll(del bool) (model.Job, string) {
	w.t.Helper()
	j, err := w.linker.UnlinkChain(context.Background(), w.chain, del, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.wait(j)
}

func (w *chainWorld) links() []model.ChainLink {
	w.t.Helper()
	c, err := w.db.ChainByID(context.Background(), w.chain)
	if err != nil {
		w.t.Fatal(err)
	}
	return c.Links
}

func (w *chainWorld) secretsOf(idx int) Secrets {
	sealed, _ := w.db.LinkSecrets(context.Background(), w.chain, idx)
	s, err := OpenSecrets(w.keys, w.chain, idx, sealed)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *chainWorld) linkCfgOf(idx int) string {
	return "/etc/hysteria/link-" + ID(w.chain, idx) + ".yaml"
}

// snapshot is every file and unit state of the hosts.
func (w *chainWorld) snapshot() []string {
	var out []string
	for _, h := range w.hosts {
		h.mu.Lock()
		var b strings.Builder
		for _, p := range slices.Sorted(maps.Keys(h.files)) {
			fmt.Fprintf(&b, "%s %s\n", p, sha(h.files[p]))
		}
		for _, u := range slices.Sorted(maps.Keys(h.units)) {
			if h.units[u] == "active" {
				fmt.Fprintf(&b, "unit %s\n", u)
			}
		}
		h.mu.Unlock()
		out = append(out, b.String())
	}
	return out
}

// before reports whether a comes before b in the log, both there.
func before(log, a, b string) bool {
	i, j := strings.Index(log, a), strings.Index(log, b)
	return i >= 0 && j >= 0 && i < j
}

// One job deploys both links, the exit's first: the relay gets the
// outbound into the next link (and the credentials of the link before)
// only once that link works, the entry its outbound last.
func TestChainDeploy(t *testing.T) {
	w := three(t)
	a, r, x := w.hosts[0], w.hosts[1], w.hosts[2]
	j, log := w.deploy()
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	if j.ServerID != w.ids[0] || len(j.Servers) != 2 || j.Servers[0] != w.ids[1] || j.Servers[1] != w.ids[2] {
		t.Fatalf("servers %d %v", j.ServerID, j.Servers)
	}
	s0, s1 := w.secretsOf(0), w.secretsOf(1)
	for _, s := range []string{s0.ExitPassword, s0.SOCKSPassword, s1.ExitPassword, s1.SOCKSPassword} {
		if strings.Contains(log, s) || strings.Contains(string(j.Params), s) {
			t.Fatalf("a secret of a link in the log or params:\n%s", log)
		}
	}
	if !strings.Contains(string(j.Params), `"hops"`) {
		t.Fatalf("params %s", j.Params)
	}
	steps, _ := w.db.JobSteps(context.Background(), j.ID)
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	if got := strings.Join(names, " "); !strings.HasPrefix(got, "connect check exit-config:1 exit-restart:1 exit-verify:1 link-config:1 link-service:1 link-check:1 entry-config:1 entry-restart:1 entry-verify:1 exit-config:0 ") || !strings.HasSuffix(got, " entry-verify:0 commit cleanup") {
		t.Fatalf("steps %s", got)
	}

	// Exit to entry: each server sends into a link only once it works.
	for _, pair := range [][2]string{
		{"Связь «Relay» → «Exit» работает", "На сервер «Relay» добавлен outbound"},
		{"На сервер «Relay» добавлен outbound", "Связь «Entry» → «Relay» работает"},
		{"Связь «Entry» → «Relay» работает", "На сервер «Entry» добавлен outbound"},
	} {
		if !before(log, pair[0], pair[1]) {
			t.Fatalf("%q not before %q:\n%s", pair[0], pair[1], log)
		}
	}

	// The exit has the user of link 1; the relay the user of link 0 and
	// the outbound into link 1; the entry the outbound into link 0.
	ls := w.links()
	p0, _ := ParseParams(ls[0].Params)
	p1, _ := ParseParams(ls[1].Params)
	xc, _ := x.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(xc)); c.Auth.UserPass[User(w.chain, 1)] != s1.ExitPassword || HasUser(c, User(w.chain, 0)) || len(c.Outbounds) != 0 {
		t.Fatalf("exit:\n%s", xc)
	}
	rc, _ := r.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(rc)); c.Auth.UserPass[User(w.chain, 0)] != s0.ExitPassword || c.Auth.UserPass["bob"] != "fake-bob-pass" ||
		len(c.Outbounds) != 1 || c.Outbounds[0].Name != OutboundName || c.Outbounds[0].SOCKS5.Addr != fmt.Sprintf("127.0.0.1:%d", p1.LocalPort) {
		t.Fatalf("relay:\n%s", rc)
	}
	ac, _ := a.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(ac)); len(c.Outbounds) != 1 || c.Outbounds[0].SOCKS5.Addr != fmt.Sprintf("127.0.0.1:%d", p0.LocalPort) {
		t.Fatalf("entry:\n%s", ac)
	}
	// Link clients: on the entry to the relay, on the relay to the exit.
	for i, h := range []*host{a, r} {
		b, found := h.file(w.linkCfgOf(i))
		c, _ := hyconfig.ParseClient([]byte(b))
		want := []string{"198.51.100.2:9443", "203.0.113.2:8443"}[i]
		if !found || c.Server != want || h.unit(UnitName(w.chain, i)) != "active" {
			t.Fatalf("link client %d on %s: %q", i, h.name, b)
		}
	}
	if _, found := a.file(w.linkCfgOf(1)); found {
		t.Fatal("the entry has the relay's link client")
	}
	// One restart per server: the relay got both changes at once.
	for _, h := range w.hosts {
		if n := h.restarts(unitName); n != 1 {
			t.Fatalf("%s restarted %d times", h.name, n)
		}
	}
	for i, id := range w.ids {
		rs := w.revs(id)
		if len(rs) != 2 || rs[0].Source != model.ConfigCascade {
			t.Fatalf("server %d: %d revisions", i, len(rs))
		}
	}
	for i, l := range ls {
		if l.State != model.LinkActive || l.FromRevision != w.revs(l.From)[0].Revision || l.ToRevision != w.revs(l.To)[0].Revision {
			t.Fatalf("link %d %+v", i, l)
		}
	}
	for _, h := range w.hosts {
		if _, found := h.file(cfgPath + Backup); found {
			t.Fatalf("copy left on %s", h.name)
		}
	}
	c, _ := w.db.ChainByID(context.Background(), w.chain)
	if c, _ = w.linker.Sync(context.Background(), c); c.Links[0].State != model.LinkActive || c.Links[1].State != model.LinkActive {
		t.Fatalf("after sync: %s %s", c.Links[0].State, c.Links[1].State)
	}

	// Again: both links deployed over themselves, nothing restarted.
	if j, log = w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("again: %s\n%s", j.ErrorMessage, log)
	}
	for _, h := range w.hosts {
		if n := h.restarts(unitName); n != 1 {
			t.Fatalf("again: %s restarted %d times", h.name, n)
		}
	}
	if len(w.revs(w.ids[1])) != 2 {
		t.Fatal("a revision stored again")
	}
}

// The relay does not start with its new config: the job rolls back the
// relay and the exit, and the entry is never touched.
func TestChainDeployRelayFails(t *testing.T) {
	w := three(t)
	snap := w.snapshot()
	w.hosts[1].bad = "link-"
	j, log := w.deploy()
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "Hysteria на сервере «Relay» не заработала") || j.CurrentStep != "entry-verify:1" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	w.hosts[1].bad = ""
	if got := w.snapshot(); fmt.Sprint(got) != fmt.Sprint(snap) {
		t.Fatalf("not as before:\n%v\n%v\n%s", snap, got, log)
	}
	if n := w.hosts[0].ncmds(); n == 0 || w.hosts[0].restarts(unitName) != 0 {
		t.Fatal("the entry was changed")
	}
	for i, l := range w.links() {
		if l.State != model.LinkFailed {
			t.Fatalf("link %d %s", i, l.State)
		}
	}
	for i, id := range w.ids {
		if len(w.revs(id)) != 1 {
			t.Fatalf("server %d has a new revision", i)
		}
	}
}

// Four nodes, the middle link does not come up: what the job put on the
// relays and the exit goes, every server is as it was. A retry once the
// link works deploys all of it.
func TestChainDeployMiddleHopFails(t *testing.T) {
	w := newChain(t, node{"Entry", "198.51.100.1", entryYAML}, node{"Relay", "198.51.100.2", relayUP}, node{"Relay2", "198.51.100.3", relay2PW}, node{"Exit", "203.0.113.2", exitUP})
	snap := w.snapshot()
	r2 := w.hosts[2]
	r2.mu.Lock()
	r2.down = true // the relay's link client does not reach Relay2
	r2.mu.Unlock()
	j, log := w.deploy()
	if j.State != model.JobFailed || j.CurrentStep != "link-check:1" || !strings.Contains(j.ErrorMessage, "Связь «Relay» → «Relay2» не заработала") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if !strings.Contains(log, "Связь «Relay2» → «Exit» работает") {
		t.Fatalf("the last link was not up first:\n%s", log)
	}
	if got := w.snapshot(); fmt.Sprint(got) != fmt.Sprint(snap) {
		t.Fatalf("not as before:\n%v\n%v\n%s", snap, got, log)
	}
	// Relay2 and the exit were changed and restarted back.
	if w.hosts[3].restarts(unitName) != 2 || r2.restarts(unitName) != 2 || w.hosts[0].restarts(unitName) != 0 {
		t.Fatalf("restarts: exit %d, relay2 %d, entry %d", w.hosts[3].restarts(unitName), r2.restarts(unitName), w.hosts[0].restarts(unitName))
	}
	for i, l := range w.links() {
		if l.State != model.LinkFailed {
			t.Fatalf("link %d %s", i, l.State)
		}
	}

	r2.mu.Lock()
	r2.down = false
	r2.mu.Unlock()
	if j, err := w.linker.x.Jobs.Retry(context.Background(), j.ID, 1); err != nil {
		t.Fatal(err)
	} else if j, log = w.wait(j); j.State != model.JobCompleted {
		t.Fatalf("retry: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	for i, l := range w.links() {
		if l.State != model.LinkActive {
			t.Fatalf("after the retry link %d %s", i, l.State)
		}
	}
	// Relay2 has a password: the link before it uses that, and its config
	// gets only the outbound.
	rc, _ := r2.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(rc)); c.Auth.Type != "password" || len(c.Outbounds) != 1 || c.Outbounds[0].Name != OutboundName {
		t.Fatalf("relay2:\n%s", rc)
	}
	b, _ := w.hosts[1].file(w.linkCfgOf(1))
	if c, _ := hyconfig.ParseClient([]byte(b)); c.Auth != "fake-relay2-pass" {
		t.Fatalf("relay's client auth %q", c.Auth)
	}
}

// Only the stale link is deployed again: the exit rotated the link's
// password, the entry is not even contacted.
func TestChainRefreshTouchesStaleOnly(t *testing.T) {
	w := three(t)
	if j, log := w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	ctx := context.Background()
	xc, _ := w.exit.file(cfgPath)
	c, _ := hyconfig.ParseServer([]byte(xc))
	c.Auth.UserPass[User(w.chain, 1)] = "fake-rotated-pass"
	rotated, _ := c.Marshal()
	w.rev(w.out, w.exit, string(rotated))
	ch, _ := w.db.ChainByID(ctx, w.chain)
	if ch, _ = w.linker.Sync(ctx, ch); ch.Links[0].State != model.LinkActive || ch.Links[1].State != model.LinkStale {
		t.Fatalf("after rotation: %s %s", ch.Links[0].State, ch.Links[1].State)
	}
	entryCmds := w.entry.ncmds()
	j, log := w.deploy()
	if j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	if j.ServerID != w.ids[1] || len(j.Servers) != 1 || j.Servers[0] != w.out || strings.Contains(string(j.Params), `"hops"`) {
		t.Fatalf("job on %d %v: %s", j.ServerID, j.Servers, j.Params)
	}
	if w.entry.ncmds() != entryCmds {
		t.Fatal("the entry was contacted")
	}
	xc, _ = w.exit.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(xc)); c.Auth.UserPass[User(w.chain, 1)] != w.secretsOf(1).ExitPassword {
		t.Fatal("the link's password not back on the exit")
	}
	ch, _ = w.db.ChainByID(ctx, w.chain)
	if ch, _ = w.linker.Sync(ctx, ch); ch.Links[0].State != model.LinkActive || ch.Links[1].State != model.LinkActive {
		t.Fatalf("after refresh: %s %s", ch.Links[0].State, ch.Links[1].State)
	}
}

// The unlink goes from the entry towards the exit: no server sends into a
// link that is already gone. Every server ends as before the chain.
func TestChainUnlinkOrder(t *testing.T) {
	w := three(t)
	if j, log := w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	j, log := w.unlinkAll(true)
	if j.State != model.JobCompleted {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	order := []string{
		"С сервера «Entry» убран outbound",
		"Служба связи " + UnitName(w.chain, 0) + " остановлена",
		"С сервера «Relay» убран пользователь связи " + User(w.chain, 0),
		"Служба связи " + UnitName(w.chain, 1) + " остановлена",
		"С сервера «Exit» убран пользователь связи " + User(w.chain, 1),
	}
	for i := 1; i < len(order); i++ {
		if !before(log, order[i-1], order[i]) {
			t.Fatalf("%q not before %q:\n%s", order[i-1], order[i], log)
		}
	}
	for i, h := range w.hosts {
		cfg, _ := h.file(cfgPath)
		c, _ := hyconfig.ParseServer([]byte(cfg))
		if HasOutbound(c) || HasUser(c, User(w.chain, 0)) || HasUser(c, User(w.chain, 1)) || h.unit(unitName) != "active" {
			t.Fatalf("server %d:\n%s", i, cfg)
		}
		for idx := range 2 {
			if _, found := h.file(w.linkCfgOf(idx)); found || h.unit(UnitName(w.chain, idx)) == "active" {
				t.Fatalf("link %d left on %s", idx, h.name)
			}
		}
		if _, found := h.file(cfgPath + Backup); found {
			t.Fatalf("copy left on %s", h.name)
		}
		if srv, _ := w.db.ServerByID(context.Background(), w.ids[i]); srv.Role != model.RoleStandalone || len(w.revs(w.ids[i])) != 3 {
			t.Fatalf("server %d: %s, %d revisions", i, srv.Role, len(w.revs(w.ids[i])))
		}
	}
	// The relay was restarted once for both of its links.
	if n := w.hosts[1].restarts(unitName); n != 2 {
		t.Fatalf("relay restarted %d times in all", n)
	}
	if _, err := w.db.ChainByID(context.Background(), w.chain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chain: %v", err)
	}
}

// Without delete the chain stays with every link new and without secrets.
func TestChainUnlinkKeeps(t *testing.T) {
	w := three(t)
	if j, log := w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	if j, log := w.unlinkAll(false); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	for i, l := range w.links() {
		if l.State != model.LinkNew {
			t.Fatalf("link %d %s", i, l.State)
		}
		if sealed, _ := w.db.LinkSecrets(context.Background(), w.chain, i); sealed != nil {
			t.Fatalf("link %d keeps its secrets", i)
		}
	}
	if _, err := w.linker.UnlinkChain(context.Background(), w.chain, true, 0); !errors.Is(err, ErrNotDeployed) {
		t.Fatalf("again: %v", err)
	}
}

// The relay fails while the chain is taken off: what the job did goes
// back on every server, and the links stay as they were.
func TestChainUnlinkRollsBack(t *testing.T) {
	w := three(t)
	if j, log := w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	snap := w.snapshot()
	w.hosts[1].mu.Lock()
	w.hosts[1].need = User(w.chain, 0)
	w.hosts[1].mu.Unlock()
	j, log := w.unlinkAll(true)
	if j.State != model.JobFailed || j.CurrentStep != "exit-verify:0" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if got := w.snapshot(); fmt.Sprint(got) != fmt.Sprint(snap) {
		t.Fatalf("not as before:\n%v\n%v\n%s", snap, got, log)
	}
	for i, l := range w.links() {
		if l.State != model.LinkActive {
			t.Fatalf("link %d %s", i, l.State)
		}
	}
}

// The relay's VPS is gone: «Удалить каскад» fails, then the chain is
// deleted without it. The entry and the exit lose all the links put
// there; the relay is marked with everything both links left on it.
func TestChainForceDeleteWithoutRelay(t *testing.T) {
	w := three(t)
	ctx := context.Background()
	if j, log := w.deploy(); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	r := w.hosts[1]
	r.setGone(true)
	j, log := w.unlinkAll(true)
	if j.State != model.JobFailed || j.CurrentStep != "connect" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	c, _ := w.db.ChainByID(ctx, w.chain)
	for idx := range 2 {
		un, err := w.linker.Unreached(ctx, c, idx)
		if err != nil || len(un) != 1 || un[0].Server != w.ids[1] || !un[0].Entry || len(un[0].Left) != 4 {
			t.Fatalf("unreached by link %d: %+v %v", idx, un, err)
		}
	}
	j, un, err := w.linker.ForceDelete(ctx, w.chain, 1, 0)
	if err != nil || len(un) != 1 {
		t.Fatal(err)
	}
	if j, log = w.wait(j); j.State != model.JobCompleted {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	ac, _ := w.entry.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(ac)); HasOutbound(c) {
		t.Fatal("the entry keeps the outbound")
	}
	if _, found := w.entry.file(w.linkCfgOf(0)); found {
		t.Fatal("the entry keeps its link client")
	}
	xc, _ := w.exit.file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(xc)); HasUser(c, User(w.chain, 1)) {
		t.Fatal("the exit keeps the link's user")
	}
	if _, err := w.db.ChainByID(ctx, w.chain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chain: %v", err)
	}
	relay, _ := w.db.ServerByID(ctx, w.ids[1])
	for _, s := range []string{UnitName(w.chain, 1), w.linkCfgOf(1), "outbound «cascade»", User(w.chain, 0)} {
		if !strings.Contains(relay.Notes, s) {
			t.Fatalf("relay note without %q: %q", s, relay.Notes)
		}
	}
	if relay.State != model.StateNeedsAttention || len(w.revs(w.ids[1])) != 2 {
		t.Fatalf("relay %s, %d revisions", relay.State, len(w.revs(w.ids[1])))
	}
	for _, id := range []int64{w.in, w.out} {
		if s, _ := w.db.ServerByID(ctx, id); s.State == model.StateNeedsAttention || s.Notes != "" || len(w.revs(id)) != 3 {
			t.Fatalf("server %d %s %q", id, s.State, s.Notes)
		}
	}
	if !strings.Contains(log, "пропущены «Relay»") {
		t.Fatalf("log:\n%s", log)
	}
}
