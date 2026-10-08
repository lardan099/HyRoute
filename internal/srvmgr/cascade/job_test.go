package cascade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const (
	cfgPath  = "/etc/hysteria/config.yaml"
	unitName = "hysteria-server.service"
	binPath  = "/usr/local/bin/hysteria"
)

const entryYAML = `listen: :443
acme:
  domains:
    - entry.example.com
auth:
  type: password
  password: fake-entry-pass
`

const exitUP = `listen: :8443
acme:
  domains:
    - exit.example.com
auth:
  type: userpass
  userpass:
    alice: fake-alice-pass
`

const exitPW = `listen: :8443
acme:
  domains:
    - exit.example.com
auth:
  type: password
  password: fake-exit-pass
`

// host is a server with Hysteria and systemd. Its server unit runs the
// config on disk; the link unit runs when its config and unit are there.
// `hysteria ping` reaches the exit host when it runs and accepts the
// link client's auth.
type host struct {
	mu    sync.Mutex
	name  string
	files map[string][]byte
	modes map[string]string
	units map[string]string // unit → state
	cmds  []string
	exit  *host // the exit, for ping
	// down: ping cannot reach this exit; bad: a server config with it
	// fails.
	down bool
	bad  string
	// need: a server config without it fails.
	need string
	// pingHook runs at each ping, runHook before each other command (tests
	// block in them).
	pingHook func()
	runHook  func(line string)
	// failRead: reading this file fails as a broken connection does;
	// fail: so do commands starting with it.
	failRead, fail string
	// listen are more lines of ss: sockets of other programs.
	listen string
	// gone: SSH to the host does not connect (its VPS was deleted).
	gone bool
}

// linkPID is the process of a running link client.
const linkPID = 5151

// linkPort is the SOCKS5 port of link unit u's config (0: none).
func (h *host) linkPort(u string) int {
	b, found := h.files["/etc/hysteria/"+strings.TrimSuffix(strings.TrimPrefix(u, "hyroute-"), ".service")+".yaml"]
	if !found || u == unitName {
		return 0
	}
	c, err := hyconfig.ParseClient(b)
	if err != nil || c.SOCKS5 == nil {
		return 0
	}
	_, port, _ := strings.Cut(c.SOCKS5.Listen, "127.0.0.1:")
	n, _ := strconv.Atoi(port)
	return n
}

func newHost(name, cfg string) *host {
	h := &host{name: name, files: map[string][]byte{cfgPath: []byte(cfg)}, modes: map[string]string{cfgPath: "640 root hysteria"}, units: map[string]string{}}
	h.restart(unitName)
	return h
}

func (h *host) serverOK() (int, bool) {
	c, err := hyconfig.ParseServer(h.files[cfgPath])
	if err != nil || hyconfig.HasErrors(c.Validate()) || (h.bad != "" && strings.Contains(string(h.files[cfgPath]), h.bad)) || (h.need != "" && !strings.Contains(string(h.files[cfgPath]), h.need)) {
		return 0, false
	}
	l, _ := hyconfig.ParseListen(c.Listen)
	return l.First, true
}

// restart starts a unit again: the server with its config, a link unit
// when its unit file and config are there.
func (h *host) restart(unit string) {
	if unit == unitName {
		if _, ok := h.serverOK(); ok {
			h.units[unit] = "active"
		} else {
			h.units[unit] = "failed"
		}
		return
	}
	_, hasUnit := h.files["/etc/systemd/system/"+unit]
	_, hasCfg := h.files["/etc/hysteria/"+strings.TrimSuffix(strings.TrimPrefix(unit, "hyroute-"), ".service")+".yaml"]
	if hasUnit && hasCfg {
		h.units[unit] = "active"
	} else {
		h.units[unit] = "failed"
	}
}

func ok(out string) remote.Result { return remote.Result{Stdout: []byte(out)} }

func (h *host) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	a := cmd.Args
	if len(a) > 1 && a[0] == binPath && a[len(a)-2] == "ping" {
		return h.ping(a)
	}
	line := strings.Join(a, " ")
	h.mu.Lock()
	hook := h.runHook
	h.mu.Unlock()
	if hook != nil {
		hook(line)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail != "" && strings.HasPrefix(line, h.fail) {
		return remote.Result{}, errors.New("ssh: connection lost")
	}
	h.cmds = append(h.cmds, line)
	last := a[len(a)-1]
	switch {
	case line == "id -un":
		return ok("root\n"), nil
	case line == "id -u":
		return ok("0\n"), nil
	case line == "uname -n":
		return ok(h.name + "\n"), nil
	case line == "uname -sr":
		return ok("Linux 6.8.0\n"), nil
	case line == "uname -m":
		return ok("x86_64\n"), nil
	case a[0] == "sha256sum":
		b, found := h.files[last]
		if !found {
			return remote.Result{ExitCode: 1, Stderr: []byte("No such file")}, nil
		}
		s := sha256.Sum256(b)
		return ok(hex.EncodeToString(s[:]) + "  " + last + "\n"), nil
	case a[0] == "cp":
		h.files[last] = append([]byte(nil), h.files[a[len(a)-2]]...)
		h.modes[last] = h.modes[a[len(a)-2]]
		return ok(""), nil
	case a[0] == "mv":
		src := a[len(a)-2]
		b, found := h.files[src]
		if !found {
			return remote.Result{ExitCode: 1, Stderr: []byte("mv: cannot stat")}, nil
		}
		h.files[last] = b
		delete(h.files, src)
		return ok(""), nil
	case a[0] == "rm":
		delete(h.files, last)
		return ok(""), nil
	case a[0] == "readlink":
		return ok(last + "\n"), nil
	case a[0] == "stat" && a[3] == "%u %g %a":
		// The binary and its directories are root's.
		return ok(strings.Repeat("0 0 755\n", len(a)-5)), nil
	case a[0] == "stat":
		b, found := h.files[last]
		if !found {
			return remote.Result{ExitCode: 1, Stderr: []byte("No such file")}, nil
		}
		return ok(fmt.Sprintf("%s %d\n", h.modes[last], len(b))), nil
	case line == "systemctl daemon-reload":
		return ok(""), nil
	case len(a) == 4 && a[0] == "systemctl" && a[1] == "is-active":
		st := h.units[last]
		if st == "" {
			st = "inactive"
		}
		code := 0
		if st != "active" {
			code = 3
		}
		return remote.Result{Stdout: []byte(st + "\n"), ExitCode: code}, nil
	case len(a) == 4 && a[0] == "systemctl" && (a[1] == "restart" || a[1] == "start"):
		h.restart(last)
		return ok(""), nil
	case len(a) == 4 && a[0] == "systemctl" && a[1] == "stop":
		h.units[last] = "inactive"
		return ok(""), nil
	case len(a) == 4 && a[0] == "systemctl" && (a[1] == "enable" || a[1] == "disable"):
		return ok(""), nil
	case a[0] == "ss":
		out := ""
		if port, up := h.serverOK(); up && h.units[unitName] == "active" {
			out = fmt.Sprintf("udp UNCONN 0 0 *:%d *:* users:((\"hysteria\",pid=4242,fd=7))\n", port)
		}
		for u, st := range h.units {
			if port := h.linkPort(u); st == "active" && port != 0 {
				out += fmt.Sprintf("tcp LISTEN 0 4096 127.0.0.1:%d 0.0.0.0:* users:((\"hysteria\",pid=%d,fd=3))\n", port, linkPID)
			}
		}
		return ok(out + h.listen), nil
	case len(a) > 2 && a[0] == "systemctl" && a[1] == "show":
		st, pid := h.units[last], 0
		switch {
		case st == "":
			return ok("LoadState=not-found\nActiveState=inactive\nMainPID=0\n"), nil
		case st == "active" && last == unitName:
			pid = 4242
		case st == "active":
			pid = linkPID
		}
		return ok(fmt.Sprintf("LoadState=loaded\nActiveState=%s\nMainPID=%d\n", st, pid)), nil
	case a[0] == "journalctl":
		return ok("FATAL something broke (auth fake-alice-pass)\n"), nil
	}
	return remote.Result{ExitCode: 127, Stderr: []byte("host: unknown command " + line)}, nil
}

// ping answers as `hysteria ping --log-format json` does.
func (h *host) ping(a []string) (remote.Result, error) {
	h.mu.Lock()
	hook := h.pingHook
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	h.mu.Lock()
	cfg := h.files[a[2]]
	h.cmds = append(h.cmds, strings.Join(a, " "))
	h.mu.Unlock()
	fail := func(msg string) (remote.Result, error) {
		return remote.Result{ExitCode: 1, Stderr: []byte(`{"level":"info","time":1000,"msg":"ping mode"}` + "\n" +
			`{"level":"fatal","time":1300,"msg":"failed to initialize client","error":"` + msg + `"}` + "\n")}, nil
	}
	c, err := hyconfig.ParseClient(cfg)
	if err != nil {
		return fail("no config")
	}
	x := h.exit
	x.mu.Lock()
	defer x.mu.Unlock()
	srv, err := hyconfig.ParseServer(x.files[cfgPath])
	accepted := false
	if err == nil {
		switch srv.Auth.Type {
		case "password":
			accepted = c.Auth == srv.Auth.Password
		case "userpass":
			u, p, _ := strings.Cut(c.Auth, ":")
			accepted = srv.Auth.UserPass[u] == p && p != ""
		}
	}
	switch {
	case x.down || x.units[unitName] != "active":
		return fail("timeout: no recent network activity")
	case !accepted:
		return fail("authentication error, HTTP status code: 404")
	}
	return remote.Result{Stderr: []byte(`{"level":"info","time":1000,"msg":"ping mode"}` + "\n" +
		`{"level":"info","time":1042,"msg":"connected to server","addr":"203.0.113.2:8443","udpEnabled":true,"tx":0}` + "\n" +
		`{"level":"info","time":1042,"msg":"connecting","addr":"` + a[len(a)-1] + `"}` + "\n" +
		`{"level":"info","time":1055,"msg":"connected","time":"12.5ms"}` + "\n")}, nil
}

func (h *host) Stream(context.Context, remote.Cmd, func(string)) error {
	return errors.New("no streams")
}

func (h *host) ReadFile(_ context.Context, p string, _ bool) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p == h.failRead {
		return nil, errors.New("ssh: connection lost")
	}
	b, found := h.files[p]
	if !found {
		return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
	}
	return append([]byte(nil), b...), nil
}

func (h *host) WriteFile(_ context.Context, p string, data []byte, f remote.FileSpec) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[p] = append([]byte(nil), data...)
	h.modes[p] = fmt.Sprintf("%o %s %s", f.Mode.Perm(), f.Owner, f.Group)
	return nil
}

func (h *host) Close() error { return nil }

func (h *host) file(p string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, found := h.files[p]
	return string(b), found
}

func (h *host) unit(u string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.units[u]
}

func (h *host) restarts(unit string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.cmds {
		if c == "systemctl restart -- "+unit {
			n++
		}
	}
	return n
}

type hosts map[int64]*host

func (hs hosts) Connect(_ context.Context, id int64) (remote.Executor, error) {
	if h, found := hs[id]; found {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.gone {
			return nil, &remote.UnreachableError{Err: errors.New("dial tcp: i/o timeout")}
		}
		return h, nil
	}
	return nil, errors.New("no such server")
}

type world struct {
	t           *testing.T
	db          *sqlite.DB
	keys        *secrets.Keyring
	entry, exit *host
	in, out     int64 // entry and exit server IDs
	chain       int64
	linker      *Linker
	stop        func()
}

func newWorld(t *testing.T, exitCfg string) *world {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{6}, 32)})
	w := &world{t: t, db: db, keys: keys}
	add := func(name, host, cfg string) int64 {
		s := model.Server{Name: name, Host: host, SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		db.CreateServer(ctx, &s, nil)
		db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: binPath, Config: cfgPath, Unit: unitName, User: "hysteria", Version: "v2.12.3", Managed: true, At: time.Now()})
		c := model.ServerConfig{ServerID: s.ID, SHA256: sha([]byte(cfg)), Meta: model.ConfigMeta{TLS: "acme", Auth: "x"}, Source: model.ConfigDeploy, At: time.Now()}
		db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) })
		return s.ID
	}
	w.in, w.out = add("Entry", "198.51.100.1", entryYAML), add("Exit", "203.0.113.2", exitCfg)
	w.exit, w.entry = newHost("exit", exitCfg), newHost("entry", entryYAML)
	w.entry.exit = w.exit
	now := time.Now()
	ch := model.Chain{Name: "DE", Nodes: []int64{w.in, w.out}, Links: []model.ChainLink{{}}, CreatedAt: now, UpdatedAt: now}
	if err := db.CreateChain(ctx, &ch, nil); err != nil {
		t.Fatal(err)
	}
	w.chain = ch.ID
	w.linker, w.stop = w.controller()
	return w
}

// controller starts a controller process on the world's database; stop
// ends it as a dying process would.
func (w *world) controller() (*Linker, func()) {
	eng := jobs.New(w.db, w.keys, redact.New(), hosts{w.in: w.entry, w.out: w.exit}, nil)
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

func (w *world) submit() model.Job {
	w.t.Helper()
	j, err := w.linker.Submit(context.Background(), w.chain, 0, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return j
}

func (w *world) wait(j model.Job) (model.Job, string) {
	w.t.Helper()
	for i := 0; i < 500 && !j.State.Terminal(); i++ {
		time.Sleep(10 * time.Millisecond)
		j, _ = w.db.JobByID(context.Background(), j.ID)
	}
	time.Sleep(20 * time.Millisecond) // the Finished hook
	ls, _ := w.db.JobLogs(context.Background(), j.ID, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return j, b.String()
}

func (w *world) link() model.ChainLink {
	c, err := w.db.ChainByID(context.Background(), w.chain)
	if err != nil {
		w.t.Fatal(err)
	}
	return c.Links[0]
}

func (w *world) revs(server int64) []model.ServerConfig {
	rs, _ := w.db.ListConfigs(context.Background(), server)
	return rs
}

func (w *world) secrets() Secrets {
	sealed, _ := w.db.LinkSecrets(context.Background(), w.chain, 0)
	s, err := OpenSecrets(w.keys, w.chain, 0, sealed)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func linkCfg(w *world) string { return "/etc/hysteria/link-" + ID(w.chain, 0) + ".yaml" }

func TestLinkUserpassExit(t *testing.T) {
	w := newWorld(t, exitUP)
	j := w.submit()
	if j.ServerID != w.in || len(j.Servers) != 1 || j.Servers[0] != w.out {
		t.Fatalf("servers %d %v", j.ServerID, j.Servers)
	}
	j, log := w.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	s := w.secrets()
	if strings.Contains(string(j.Params), s.ExitPassword) || strings.Contains(log, s.ExitPassword) || strings.Contains(log, s.SOCKSPassword) {
		t.Fatalf("a secret of the link in params or log: %s\n%s", j.Params, log)
	}

	// The exit has the link's user, the entry the outbound first.
	exitNow, _ := w.exit.file(cfgPath)
	ec, _ := hyconfig.ParseServer([]byte(exitNow))
	user := User(w.chain, 0)
	if ec.Auth.UserPass[user] != s.ExitPassword || ec.Auth.UserPass["alice"] != "fake-alice-pass" {
		t.Fatalf("exit users %v", ec.Auth.UserPass)
	}
	entryNow, _ := w.entry.file(cfgPath)
	nc, _ := hyconfig.ParseServer([]byte(entryNow))
	p, _ := ParseParams(w.link().Params)
	if len(nc.Outbounds) != 1 || nc.Outbounds[0].Name != OutboundName || nc.Outbounds[0].SOCKS5.Addr != fmt.Sprintf("127.0.0.1:%d", p.LocalPort) || p.LocalPort < 40000 {
		t.Fatalf("entry outbounds %+v, port %d", nc.Outbounds, p.LocalPort)
	}
	client, found := w.entry.file(linkCfg(w))
	cc, _ := hyconfig.ParseClient([]byte(client))
	if !found || cc.Auth != user+":"+s.ExitPassword || cc.SOCKS5.Password != s.SOCKSPassword || w.entry.modes[linkCfg(w)] != "640  hysteria" {
		t.Fatalf("client %v %q %s", found, client, w.entry.modes[linkCfg(w)])
	}
	if u, _ := w.entry.file("/etc/systemd/system/" + UnitName(w.chain, 0)); !strings.Contains(u, "--disable-update-check") || w.entry.unit(UnitName(w.chain, 0)) != "active" {
		t.Fatalf("unit %q, %s", u, w.entry.unit(UnitName(w.chain, 0)))
	}
	if !strings.Contains(log, "рукопожатие 42 мс") || !strings.Contains(log, "открыт 203.0.113.2:22 за 12 мс") {
		t.Fatalf("log:\n%s", log)
	}

	// Both revisions are stored, source cascade; the link is active.
	er, xr := w.revs(w.in), w.revs(w.out)
	if len(er) != 2 || len(xr) != 2 || er[0].Source != model.ConfigCascade || xr[0].Source != model.ConfigCascade || er[0].SHA256 != sha([]byte(entryNow)) || xr[0].SHA256 != sha([]byte(exitNow)) {
		t.Fatalf("revisions %+v %+v", er, xr)
	}
	l := w.link()
	unitText, _ := w.entry.file("/etc/systemd/system/" + UnitName(w.chain, 0))
	if l.State != model.LinkActive || l.FromRevision != er[0].Revision || l.ToRevision != xr[0].Revision || l.ConfigSHA256 != sha([]byte(client)) || l.UnitSHA256 != sha([]byte(unitText)) {
		t.Fatalf("link %+v", l)
	}
	for _, f := range []string{cfgPath + Backup, linkCfg(w) + Backup} {
		if _, found := w.entry.file(f); found {
			t.Fatalf("%s left on the entry", f)
		}
	}

	// Again: nothing to change, no service of a server restarted.
	before := w.exit.restarts(unitName) + w.entry.restarts(unitName)
	j, log = w.wait(w.submit())
	if j.State != model.JobCompleted || w.exit.restarts(unitName)+w.entry.restarts(unitName) != before || len(w.revs(w.in)) != 2 || len(w.revs(w.out)) != 2 {
		t.Fatalf("redeploy: %s, restarts %d → %d\n%s", j.State, before, w.exit.restarts(unitName)+w.entry.restarts(unitName), log)
	}
}

func TestLinkPasswordExit(t *testing.T) {
	w := newWorld(t, exitPW)
	j, log := w.wait(w.submit())
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if now, _ := w.exit.file(cfgPath); now != exitPW || w.exit.restarts(unitName) != 0 || len(w.revs(w.out)) != 1 {
		t.Fatalf("a password exit was changed: restarts %d, revisions %d", w.exit.restarts(unitName), len(w.revs(w.out)))
	}
	client, _ := w.entry.file(linkCfg(w))
	if cc, _ := hyconfig.ParseClient([]byte(client)); cc.Auth != "fake-exit-pass" {
		t.Fatalf("client auth %q", cc.Auth)
	}
	if l := w.link(); l.State != model.LinkActive || l.ToRevision != 1 {
		t.Fatalf("link %+v", l)
	}
}

// The exit does not take its config with the link: it goes back, and
// nothing reaches the entry.
func TestLinkExitFailsRollsBack(t *testing.T) {
	w := newWorld(t, exitUP)
	w.exit.bad = "link-"
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "сервере выхода не заработала") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if strings.Contains(log, "fake-alice-pass") {
		t.Fatalf("journal not redacted:\n%s", log)
	}
	if now, _ := w.exit.file(cfgPath); now != exitUP || w.exit.unit(unitName) != "active" {
		t.Fatalf("exit not restored: %s", w.exit.unit(unitName))
	}
	if now, _ := w.entry.file(cfgPath); now != entryYAML || len(w.entry.cmds) == 0 {
		t.Fatal("entry changed")
	}
	if _, found := w.entry.file(linkCfg(w)); found {
		t.Fatal("link config written")
	}
	if l := w.link(); l.State != model.LinkFailed || len(w.revs(w.out)) != 1 {
		t.Fatalf("link %+v", l)
	}
}

// The link client does not reach the exit: the link's files go, the exit
// gets its config back, the entry is not touched.
func TestLinkClientFailsRollsBack(t *testing.T) {
	w := newWorld(t, exitUP)
	w.exit.down = true
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "Связь не заработала") || !strings.Contains(j.ErrorMessage, "timeout") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	unit := UnitName(w.chain, 0)
	if _, found := w.entry.file("/etc/systemd/system/" + unit); found || w.entry.unit(unit) == "active" {
		t.Fatal("link unit left")
	}
	if _, found := w.entry.file(linkCfg(w)); found {
		t.Fatal("link config left")
	}
	if now, _ := w.exit.file(cfgPath); now != exitUP || w.exit.restarts(unitName) != 2 {
		t.Fatalf("exit restarts %d", w.exit.restarts(unitName))
	}
	if now, _ := w.entry.file(cfgPath); now != entryYAML || w.entry.restarts(unitName) != 0 {
		t.Fatal("entry touched")
	}
	if l := w.link(); l.State != model.LinkFailed {
		t.Fatalf("link %+v", l)
	}
}

// The rollback of a failed first deployment does not finish: the link's
// files stay on the entry, so the link counts as deployed (stale), and
// unlink takes them off.
func TestLinkUnfinishedRollbackStaysDeployed(t *testing.T) {
	w := newWorld(t, exitUP)
	w.exit.down = true
	w.entry.pingHook = func() {
		w.entry.mu.Lock()
		w.entry.fail = "rm "
		w.entry.mu.Unlock()
	}
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || !strings.Contains(log, "Откат не удался") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	unitFile := "/etc/systemd/system/" + UnitName(w.chain, 0)
	if _, found := w.entry.file(unitFile); !found {
		t.Fatal("the unit is gone: the rollback finished")
	}
	if l := w.link(); l.State != model.LinkStale {
		t.Fatalf("link %s after an unfinished rollback", l.State)
	}

	w.entry.mu.Lock()
	w.entry.fail, w.entry.pingHook = "", nil
	w.entry.mu.Unlock()
	w.exit.mu.Lock()
	w.exit.down = false
	w.exit.mu.Unlock()
	if j, log = w.unlink(true); j.State != model.JobCompleted {
		t.Fatalf("unlink: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	_, unitLeft := w.entry.file(unitFile)
	_, cfgLeft := w.entry.file(linkCfg(w))
	if unitLeft || cfgLeft {
		t.Fatalf("left on the entry: unit %v, config %v\n%s", unitLeft, cfgLeft, log)
	}
}

// The rollback of a first deployment does not finish (as above), and a
// retry stops at its check (the exit was edited meanwhile): its rollback
// takes off what the first one left. While that fails too the link stays
// deployed; once it succeeds nothing of the link is left, and the link is
// failed.
func TestLinkRetryAfterUnfinishedRollback(t *testing.T) {
	w := newWorld(t, exitUP)
	ctx := context.Background()
	w.exit.down = true
	w.entry.pingHook = func() {
		w.entry.mu.Lock()
		w.entry.fail = "rm "
		w.entry.mu.Unlock()
	}
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || w.link().State != model.LinkStale {
		t.Fatalf("%s, link %s\n%s", j.State, w.link().State, log)
	}
	edited := exitUP + "# edited over SSH\n"
	w.exit.mu.Lock()
	w.exit.files[cfgPath] = []byte(edited)
	w.exit.down = false
	w.exit.mu.Unlock()
	w.entry.mu.Lock()
	w.entry.pingHook = nil // rm still fails
	w.entry.mu.Unlock()
	unitFile := "/etc/systemd/system/" + UnitName(w.chain, 0)
	for _, rmFails := range []bool{true, false} {
		if !rmFails {
			w.entry.mu.Lock()
			w.entry.fail = ""
			w.entry.mu.Unlock()
		}
		r, err := w.linker.x.Jobs.Retry(ctx, j.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if j, log = w.wait(r); j.State != model.JobFailed || j.CurrentStep != "check" || !strings.Contains(j.ErrorMessage, "изменили не через HyRoute") {
			t.Fatalf("retry: %s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
		}
		_, unitLeft := w.entry.file(unitFile)
		_, cfgLeft := w.entry.file(linkCfg(w))
		want := model.LinkFailed
		if rmFails {
			want = model.LinkStale
		}
		if l := w.link(); l.State != want || unitLeft != rmFails || cfgLeft != rmFails {
			t.Fatalf("rm fails %v: link %s, unit left %v, config left %v\n%s", rmFails, l.State, unitLeft, cfgLeft, log)
		}
		if s, _ := w.db.ServerByID(ctx, w.in); s.State != model.StateNeedsAttention {
			t.Fatalf("entry %s", s.State)
		}
	}
	if now, _ := w.exit.file(cfgPath); now != edited {
		t.Fatalf("the edit is gone:\n%s", now)
	}
}

// Before the first deployment a user or outbound of the link's name made
// by someone else stops the job before anything changes.
func TestLinkRefusesForeignParts(t *testing.T) {
	w := newWorld(t, exitUP)
	foreign := strings.Replace(exitUP, "    alice: fake-alice-pass\n", "    alice: fake-alice-pass\n    "+User(w.chain, 0)+": fake-someone\n", 1)
	w.exit.files[cfgPath] = []byte(foreign)
	ctx := context.Background()
	c := model.ServerConfig{ServerID: w.out, SHA256: sha([]byte(foreign)), Meta: model.ConfigMeta{TLS: "acme"}, Source: model.ConfigEdit, At: time.Now()}
	w.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return w.keys.Seal([]byte(foreign), model.ConfigContext(w.out, rev)) })
	j, _ := w.wait(w.submit())
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "заведённый не этим каскадом") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if now, _ := w.exit.file(cfgPath); now != foreign {
		t.Fatal("exit changed")
	}
}

// The commit cannot read the entry's certificate (the connection broke):
// no revision is stored, and the rollback leaves server and controller
// agreeing. A retry then finishes the link.
func TestLinkCommitReadsServersFirst(t *testing.T) {
	w := newWorld(t, exitUP)
	ctx := context.Background()
	entryTLS := strings.Replace(entryYAML, "acme:\n  domains:\n    - entry.example.com\n", "tls:\n  cert: /etc/hysteria/server.crt\n  key: /etc/hysteria/server.key\n", 1)
	w.rev(w.in, w.entry, entryTLS)
	w.entry.mu.Lock()
	w.entry.failRead = "/etc/hysteria/server.crt"
	w.entry.mu.Unlock()
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || j.CurrentStep != "commit" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if n := len(w.revs(w.out)); n != 1 {
		t.Fatalf("the exit has %d revisions after the rollback\n%s", n, log)
	}
	if now, _ := w.exit.file(cfgPath); now != exitUP {
		t.Fatalf("exit not restored:\n%s", now)
	}
	if l := w.link(); l.State != model.LinkFailed {
		t.Fatalf("link %s", l.State)
	}

	w.entry.mu.Lock()
	w.entry.failRead = ""
	w.entry.mu.Unlock()
	if j, err := w.linker.x.Jobs.Retry(ctx, j.ID, 1); err != nil {
		t.Fatal(err)
	} else if j, log = w.wait(j); j.State != model.JobCompleted {
		t.Fatalf("retry: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if l := w.link(); l.State != model.LinkActive || len(w.revs(w.out)) != 2 {
		t.Fatalf("after the retry: %s, %d exit revisions", l.State, len(w.revs(w.out)))
	}
}

// failRevision is a database that cannot store a revision of one server
// while fail is set.
type failRevision struct {
	*sqlite.DB
	server int64
	fail   *atomic.Bool
}

func (d failRevision) AddConfig(ctx context.Context, c *model.ServerConfig, seal func(int) ([]byte, error)) error {
	if c.ServerID == d.server && d.fail.Load() {
		return errors.New("disk full")
	}
	return d.DB.AddConfig(ctx, c, seal)
}

// Once the exit's revision is stored, a failure to store the entry's does
// not roll the servers back (they would part from the controller): the
// link stays on them, stale, and a retry finishes the commit.
func TestLinkCommitKeepsServersOnceStored(t *testing.T) {
	w := newWorld(t, exitUP)
	w.stop()
	var fail atomic.Bool
	fail.Store(true)
	eng := jobs.New(w.db, w.keys, redact.New(), hosts{w.in: w.entry, w.out: w.exit}, nil)
	eng.Poll = 10 * time.Millisecond
	w.linker = New(Deps{Store: failRevision{w.db, w.in, &fail}, Keys: w.keys, Jobs: eng, VerifyTimeout: 300 * time.Millisecond, Poll: 10 * time.Millisecond})
	eng.Register(w.linker.Kind())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || j.CurrentStep != "commit" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if now, _ := w.exit.file(cfgPath); now == exitUP || len(w.revs(w.out)) != 2 || strings.Contains(log, "Откачено") {
		t.Fatalf("rolled back after the exit's revision was stored:\n%s", log)
	}
	if l := w.link(); l.State != model.LinkStale {
		t.Fatalf("link %s", l.State)
	}
	fail.Store(false)
	if j, err := eng.Retry(context.Background(), j.ID, 1); err != nil {
		t.Fatal(err)
	} else if j, log = w.wait(j); j.State != model.JobCompleted {
		t.Fatalf("retry: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if l := w.link(); l.State != model.LinkActive || len(w.revs(w.in)) != 2 {
		t.Fatalf("after the retry: %s, %d entry revisions", l.State, len(w.revs(w.in)))
	}
}

// A redeployment that fails leaves the link as it was: active, with its
// old client config running.
func TestLinkFailedRedeployKeepsLink(t *testing.T) {
	w := newWorld(t, exitUP)
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, log)
	}
	old, _ := w.entry.file(linkCfg(w))
	l := w.link()
	p, _ := ParseParams(l.Params)
	p.NoUDP = true
	l.Params = p.Raw()
	w.db.UpdateLink(context.Background(), l)
	w.exit.down = true
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed {
		t.Fatalf("%s\n%s", j.State, log)
	}
	if now, _ := w.entry.file(linkCfg(w)); now != old {
		t.Fatal("old client config not back")
	}
	unit := UnitName(w.chain, 0)
	if _, found := w.entry.file("/etc/systemd/system/" + unit); !found {
		t.Fatal("unit of the deployed link removed")
	}
	if got := w.link(); got.State != model.LinkActive {
		t.Fatalf("link %s after a failed redeploy", got.State)
	}
}

// The controller dies while the link comes up: the next one goes on and
// stores each revision once.
func TestLinkResumesAfterRestart(t *testing.T) {
	w := newWorld(t, exitUP)
	reached := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	w.entry.pingHook = func() {
		once.Do(func() { close(reached) })
		<-block
	}
	j := w.submit()
	<-reached
	before, _ := ParseParams(w.link().Params)
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	time.Sleep(30 * time.Millisecond) // the controller is cancelled
	w.entry.mu.Lock()
	w.entry.pingHook = nil
	w.entry.mu.Unlock()
	close(block)
	<-stopped
	w.linker, w.stop = w.controller()
	j, log := w.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if len(w.revs(w.in)) != 2 || len(w.revs(w.out)) != 2 || w.link().State != model.LinkActive {
		t.Fatalf("revisions %d %d, link %s", len(w.revs(w.in)), len(w.revs(w.out)), w.link().State)
	}
	// The recovery checked the servers again, without restarting the
	// exit a second time.
	if n := w.exit.restarts(unitName); n != 1 || !strings.Contains(log, "с шага «check»") {
		t.Fatalf("exit restarted %d times\n%s", n, log)
	}
	// The link's own client on its port is not another program.
	if p, _ := ParseParams(w.link().Params); p.LocalPort != before.LocalPort || strings.Contains(log, "занят другой программой") {
		t.Fatalf("port %d → %d\n%s", before.LocalPort, p.LocalPort, log)
	}
}

// The controller dies while the link comes up, and the next one builds
// other steps for the job: it fails without a rollback. What the job
// recorded is on the servers: the link counts as deployed (stale), and
// both servers need attention.
func TestLinkFailedWithoutRollbackStaysDeployed(t *testing.T) {
	w := newWorld(t, exitUP)
	reached := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	w.entry.pingHook = func() {
		once.Do(func() { close(reached) })
		<-block
	}
	j := w.submit()
	<-reached
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	time.Sleep(30 * time.Millisecond) // the controller is cancelled
	w.entry.mu.Lock()
	w.entry.pingHook = nil
	w.entry.mu.Unlock()
	close(block)
	<-stopped

	eng := jobs.New(w.db, w.keys, redact.New(), hosts{w.in: w.entry, w.out: w.exit}, nil)
	eng.Poll = 10 * time.Millisecond
	w.linker = New(Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 300 * time.Millisecond, Poll: 10 * time.Millisecond})
	k := w.linker.Kind()
	steps := k.Steps
	k.Steps = func(raw json.RawMessage) ([]jobs.Step, error) {
		s, err := steps(raw)
		return append(s, jobs.Step{Name: "newer", Phase: model.JobVerifying, Run: func(context.Context, *jobs.Env) error { return nil }}), err
	}
	eng.Register(k)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	j, log := w.wait(j)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "не может быть продолжено") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if _, found := w.entry.file(linkCfg(w)); !found {
		t.Fatal("the link's client is gone: something was rolled back")
	}
	if l := w.link(); l.State != model.LinkStale {
		t.Fatalf("link %s", l.State)
	}
	for _, id := range []int64{w.in, w.out} {
		if s, _ := w.db.ServerByID(context.Background(), id); s.State != model.StateNeedsAttention {
			t.Fatalf("server %d %s", id, s.State)
		}
	}
}

// The controller dies once the entry has its outbound into the link; at
// the recovery the link's client is down and its port looks taken. The
// entry's config already sends there: the link keeps its port, and the
// entry is neither rewritten nor restarted again.
func TestLinkRecoveryKeepsPortOfEntryConfig(t *testing.T) {
	w := newWorld(t, exitUP)
	reached := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	w.entry.mu.Lock()
	w.entry.runHook = func(line string) {
		if line == "systemctl restart -- "+unitName {
			once.Do(func() { close(reached) })
			<-block
		}
	}
	w.entry.mu.Unlock()
	j := w.submit()
	<-reached
	before, _ := ParseParams(w.link().Params)
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	time.Sleep(30 * time.Millisecond) // the controller is cancelled
	w.entry.mu.Lock()
	w.entry.runHook = nil
	w.entry.units[UnitName(w.chain, 0)] = "failed"
	w.entry.listen = fmt.Sprintf("tcp LISTEN 0 128 127.0.0.1:%d 0.0.0.0:* users:((\"hysteria\",pid=77,fd=3))\n", before.LocalPort)
	w.entry.mu.Unlock()
	close(block)
	<-stopped

	w.linker, w.stop = w.controller()
	j, log := w.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	p, _ := ParseParams(w.link().Params)
	entryNow, _ := w.entry.file(cfgPath)
	nc, _ := hyconfig.ParseServer([]byte(entryNow))
	if p.LocalPort != before.LocalPort || strings.Contains(log, "занят другой программой") || len(nc.Outbounds) != 1 || nc.Outbounds[0].SOCKS5.Addr != fmt.Sprintf("127.0.0.1:%d", before.LocalPort) {
		t.Fatalf("port %d → %d, outbounds %+v\n%s", before.LocalPort, p.LocalPort, nc.Outbounds, log)
	}
	if n := w.entry.restarts(unitName); n != 1 {
		t.Fatalf("entry restarted %d times\n%s", n, log)
	}
}

// After an unlink the link deploys again on its stored port while it is
// free; once another program listens there, the link client gets
// another port.
func TestLinkPortTakenAfterUnlink(t *testing.T) {
	w := linked(t, exitPW)
	first, _ := ParseParams(w.link().Params)
	if j, log := w.unlink(false); j.State != model.JobCompleted {
		t.Fatalf("unlink: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("again: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if p, _ := ParseParams(w.link().Params); p.LocalPort != first.LocalPort {
		t.Fatalf("a free port changed: %d → %d", first.LocalPort, p.LocalPort)
	}
	if j, log := w.unlink(false); j.State != model.JobCompleted {
		t.Fatalf("unlink: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	w.entry.mu.Lock()
	w.entry.listen = fmt.Sprintf("tcp LISTEN 0 128 127.0.0.1:%d 0.0.0.0:* users:((\"python3\",pid=77,fd=3))\n", first.LocalPort)
	w.entry.mu.Unlock()
	j, log := w.wait(w.submit())
	if j.State != model.JobCompleted || !strings.Contains(log, "занят другой программой") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	p, _ := ParseParams(w.link().Params)
	entryNow, _ := w.entry.file(cfgPath)
	nc, _ := hyconfig.ParseServer([]byte(entryNow))
	client, _ := w.entry.file(linkCfg(w))
	cc, _ := hyconfig.ParseClient([]byte(client))
	want := fmt.Sprintf("127.0.0.1:%d", p.LocalPort)
	if p.LocalPort == first.LocalPort || p.LocalPort < 40000 || len(nc.Outbounds) == 0 || nc.Outbounds[0].SOCKS5.Addr != want || cc.SOCKS5.Listen != want {
		t.Fatalf("port %d → %d, outbounds %+v, client %q", first.LocalPort, p.LocalPort, nc.Outbounds, client)
	}
}

// The first deployment fails and is rolled back; the admin then edits
// the exit's config over SSH. A retry checks the servers again and stops
// before writing: the edit stays.
func TestLinkRetryChecksConfigsAgain(t *testing.T) {
	w := newWorld(t, exitUP)
	w.exit.down = true
	j, log := w.wait(w.submit())
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "Связь не заработала") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	edited := exitUP + "# edited over SSH\n"
	w.exit.mu.Lock()
	w.exit.files[cfgPath] = []byte(edited)
	w.exit.down = false
	w.exit.mu.Unlock()
	if j, err := w.linker.x.Jobs.Retry(context.Background(), j.ID, 1); err != nil {
		t.Fatal(err)
	} else if j, log = w.wait(j); j.State != model.JobFailed || j.CurrentStep != "check" || !strings.Contains(j.ErrorMessage, "изменили не через HyRoute") {
		t.Fatalf("retry: %s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if now, _ := w.exit.file(cfgPath); now != edited {
		t.Fatalf("the edit is gone:\n%s", now)
	}
	if l := w.link(); l.State != model.LinkFailed {
		t.Fatalf("link %s", l.State)
	}
}

func TestParsePing(t *testing.T) {
	out := []byte(`{"level":"info","time":1000,"msg":"ping mode"}
{"level":"info","time":1042,"msg":"connected to server","addr":"x","udpEnabled":true,"tx":0}
{"level":"info","time":1043,"msg":"connecting","addr":"1.1.1.1:443"}
{"level":"info","time":1055,"msg":"connected","time":"12.5ms"}
`)
	p := ParsePing(out)
	if !p.Connected || p.Handshake != 42*time.Millisecond || !p.TCP || p.TCPTime != 12500*time.Microsecond || p.Error != "" {
		t.Fatalf("%+v", p)
	}
	p = ParsePing([]byte(`{"level":"info","time":1000,"msg":"ping mode"}
{"level":"info","time":1040,"msg":"connected to server"}
{"level":"fatal","time":1300,"msg":"failed to connect","error":"connection refused","time":"200ms"}
`))
	if !p.Connected || p.TCP || p.Error != "failed to connect: connection refused" {
		t.Fatalf("%+v", p)
	}
	if p = ParsePing([]byte("garbage\n{\"msg\":\"failed to initialize client\",\"error\":\"timeout\"}")); p.Connected || p.Error == "" {
		t.Fatalf("%+v", p)
	}
}

func TestPickPort(t *testing.T) {
	used := map[int]bool{}
	p := pickPort(3, 0, used)
	if p < 40000 || p > 49999 {
		t.Fatal(p)
	}
	used[p] = true
	if q := pickPort(3, 0, used); q == p || q < 40000 || q > 49999 {
		t.Fatal(q)
	}
}
