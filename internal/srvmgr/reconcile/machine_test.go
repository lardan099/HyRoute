package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// Canary secrets: none may show in a diff, a summary, an event or the
// stored result.
const (
	canaryAuth  = "fake-canary-auth-7f3a"
	canaryObfs  = "fake-canary-obfs-91c2"
	canaryStats = "fake-canary-stats-d40e"
	canaryProxy = "fake-canary-proxy-55b1"
	canaryNew   = "fake-canary-new-8e21"
)

const (
	cfgPath  = "/etc/hysteria/config.yaml"
	binPath  = "/usr/local/bin/hysteria"
	unitName = "hysteria-server.service"
	unitPath = "/etc/systemd/system/hysteria-server.service"
	dropIn   = "/etc/systemd/system/hysteria-server.service.d/override.conf"
)

var revisionCfg = `listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: ` + canaryAuth + `
obfs:
  type: salamander
  salamander:
    password: ` + canaryObfs + `
trafficStats:
  listen: 127.0.0.1:25413
  secret: ` + canaryStats + `
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      username: u
      password: ` + canaryProxy + `
masquerade:
  type: proxy
  proxy:
    url: https://www.example.com
`

var (
	binary     = []byte("#!fake hysteria v2.12.3")
	unitText   = "[Unit]\nDescription=Hysteria Server Service\n\n[Service]\nExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml\n"
	geoIPData  = []byte("geoip v1")
	geoSiteDat = []byte("geosite v1")
	linkCfg    = []byte("server: 198.51.100.7:443\nauth: link-1-0:" + canaryNew + "\n")
	linkUnit   = "[Unit]\nDescription=HyRoute cascade link\n"
)

func hexSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// machine is a fake server: files, systemd units (their files), and a
// Hysteria service that runs the config on disk. Its executor records
// every call.
type machine struct {
	*fake.Executor
	mu     sync.Mutex
	units  map[string][]string // unit → its files: unit file, drop-ins
	active bool
	port   int
	// bad: a config containing it makes the service fail.
	bad string
}

func newMachine() *machine {
	m := &machine{Executor: fake.New(), units: map[string][]string{}}
	m.On("id", "-un").Reply("root\n", 0)
	m.On("id", "-u").Reply("0\n", 0)
	m.On("uname", "-n").Reply("vps\n", 0)
	m.On("uname", "-sr").Reply("Linux 6.8.0\n", 0)
	m.On("uname", "-m").Reply("x86_64\n", 0)
	m.On("sha256sum", "--").Do(func(c remote.Cmd) (remote.Result, error) {
		p := c.Args[len(c.Args)-1]
		b, ok := m.File(p)
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("sha256sum: " + p + ": No such file or directory")}, nil
		}
		return remote.Result{Stdout: []byte(hexSHA(b) + "  " + p + "\n")}, nil
	})
	m.On("systemctl", "show", "--no-pager", "-p", "LoadState,FragmentPath,DropInPaths", "--").Do(func(c remote.Cmd) (remote.Result, error) {
		m.mu.Lock()
		files := m.units[c.Args[len(c.Args)-1]]
		m.mu.Unlock()
		if len(files) == 0 {
			return remote.Result{Stdout: []byte("LoadState=not-found\nFragmentPath=\nDropInPaths=\n")}, nil
		}
		return remote.Result{Stdout: []byte("LoadState=loaded\nFragmentPath=" + files[0] + "\nDropInPaths=" + strings.Join(files[1:], " ") + "\n")}, nil
	})
	m.On(binPath, "version").Reply("Version:\tv2.12.3\n", 0)
	m.RootPaths()
	// What the apply job does.
	m.On("stat", "-L", "-c", "%a %U %G %s", "--").Do(func(c remote.Cmd) (remote.Result, error) {
		p := c.Args[len(c.Args)-1]
		b, ok := m.File(p)
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("stat: No such file or directory")}, nil
		}
		return remote.Result{Stdout: []byte(fmt.Sprintf("640 root hysteria %d\n", len(b)))}, nil
	})
	m.On("cp").Do(func(c remote.Cmd) (remote.Result, error) {
		b, _ := m.File(c.Args[len(c.Args)-2])
		m.SetFile(c.Args[len(c.Args)-1], b)
		return remote.Result{}, nil
	})
	m.On("mv").Do(func(c remote.Cmd) (remote.Result, error) {
		src, dst := c.Args[len(c.Args)-2], c.Args[len(c.Args)-1]
		b, ok := m.File(src)
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("mv: cannot stat")}, nil
		}
		m.SetFile(dst, b)
		m.DeleteFile(src)
		return remote.Result{}, nil
	})
	m.On("rm").Do(func(c remote.Cmd) (remote.Result, error) {
		m.DeleteFile(c.Args[len(c.Args)-1])
		return remote.Result{}, nil
	})
	m.On("systemctl", "is-active").Do(func(remote.Cmd) (remote.Result, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.active {
			return remote.Result{Stdout: []byte("active\n")}, nil
		}
		return remote.Result{Stdout: []byte("failed\n"), ExitCode: 3}, nil
	})
	m.On("systemctl", "restart").Do(func(remote.Cmd) (remote.Result, error) {
		m.start()
		return remote.Result{}, nil
	})
	m.On("ss").Do(func(remote.Cmd) (remote.Result, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.active {
			return remote.Result{}, nil
		}
		return remote.Result{Stdout: []byte(fmt.Sprintf("udp UNCONN 0 0 *:%d *:* users:((\"hysteria\",pid=4242,fd=7))\n", m.port))}, nil
	})
	m.On("journalctl").Reply("", 0)
	return m
}

// start runs the config on disk.
func (m *machine) start() {
	b, _ := m.File(cfgPath)
	c, err := hyconfig.ParseServer(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || (m.bad != "" && bytes.Contains(b, []byte(m.bad))) {
		m.active, m.port = false, 0
		return
	}
	l, _ := hyconfig.ParseListen(c.Listen)
	m.active, m.port = true, l.First
}

// unit puts a unit and its files on the machine.
func (m *machine) unit(name string, files ...string) {
	m.mu.Lock()
	m.units[name] = files
	m.mu.Unlock()
}

// Reads replays every command the machine got through remote.ReadOnly:
// an error is a command that is not a reading one.
func readsOnly(t *testing.T, m *machine, from int) {
	t.Helper()
	calls := m.Calls()[from:]
	for _, c := range calls {
		switch c.Op {
		case "write":
			t.Fatalf("a write during the reconciliation: %s", c.Path)
		case "run", "stream":
			if _, err := remote.ReadOnly(nop{}).Run(context.Background(), remote.Cmd{Args: c.Args, Sudo: c.Sudo}); errors.Is(err, remote.ErrNotReadOnly) {
				t.Fatalf("a command that is not reading: %q", c.Args)
			}
		}
	}
	if len(calls) == 0 {
		t.Fatal("nothing read")
	}
}

type nop struct{}

func (nop) Run(context.Context, remote.Cmd) (remote.Result, error)           { return remote.Result{}, nil }
func (nop) Stream(context.Context, remote.Cmd, func(string)) error           { return nil }
func (nop) ReadFile(context.Context, string, bool) ([]byte, error)           { return nil, nil }
func (nop) WriteFile(context.Context, string, []byte, remote.FileSpec) error { return nil }
func (nop) Close() error                                                     { return nil }

// conn hands out the machine of each server; a closed connection does
// not close the machine. connects counts the connections per server.
type conn struct {
	mu       sync.Mutex
	machines map[int64]*machine
	connects map[int64]int
}

func (c *conn) Connect(_ context.Context, id int64) (remote.Executor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connects[id]++
	m, ok := c.machines[id]
	if !ok {
		return nil, &remote.UnreachableError{Err: errors.New("dial tcp 192.0.2.99:22: i/o timeout")}
	}
	return keep{m}, nil
}

func (c *conn) count(id int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connects[id]
}

type keep struct{ *machine }

func (keep) Close() error { return nil }

// events records what the reconciliation reports.
type events struct {
	mu       sync.Mutex
	drift    []string // "<server name>: <what>"
	resolved []string // server names
}

func (e *events) Drift(_ context.Context, srv model.Server, what string) {
	e.mu.Lock()
	e.drift = append(e.drift, srv.Name+": "+what)
	e.mu.Unlock()
}

func (e *events) DriftGone(_ context.Context, srv model.Server) {
	e.mu.Lock()
	e.resolved = append(e.resolved, srv.Name)
	e.mu.Unlock()
}

func (e *events) get() ([]string, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.drift...), append([]string(nil), e.resolved...)
}

// world is a controller with server a (Hysteria by HyRoute, geo
// databases, the entry of a cascade to b) and b (its exit, no trusted
// key: never connected).
type world struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	conn   *conn
	ev     *events
	r      *Reconciler
	m      *machine
	a, b   int64
	chain  int64
	linkAt string // the link's client config on a
	linkU  string // the link's unit
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	w := &world{t: t, db: db, keys: keys, ev: &events{}, m: newMachine()}
	for i, name := range []string{"Frankfurt", "Helsinki"} {
		s := model.Server{Name: name, Host: fmt.Sprintf("192.0.2.%d", 10+i), SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		in := model.Installation{ServerID: s.ID, Binary: binPath, Config: cfgPath, Unit: unitName, User: "hysteria", Version: "v2.12.3", Managed: true,
			BinarySHA256: hexSHA(binary), UnitSHA256: hexSHA([]byte(unitText)), At: time.Now()}
		if err := db.SetInstallation(ctx, in); err != nil {
			t.Fatal(err)
		}
		c := model.ServerConfig{ServerID: s.ID, SHA256: hexSHA([]byte(revisionCfg)), Source: model.ConfigDeploy, At: time.Now()}
		if err := db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(revisionCfg), model.ConfigContext(s.ID, rev)) }); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			w.a = s.ID
		} else {
			w.b = s.ID
		}
	}
	if err := db.SetHostKey(ctx, model.HostKey{ServerID: w.a, Type: "ssh-ed25519", Key: []byte{1}, Fingerprint: "SHA256:fake", TrustedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetServerGeo(ctx, model.ServerGeo{ServerID: w.a, Release: "202610010000", GeoIP: hexSHA(geoIPData), GeoSite: hexSHA(geoSiteDat), At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ch := &model.Chain{Name: "Через Хельсинки", Nodes: []int64{w.a, w.b}, Links: []model.ChainLink{{Params: []byte(`{"localPort":40001}`)}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.CreateChain(ctx, ch, func([]model.Chain) error { return nil }); err != nil {
		t.Fatal(err)
	}
	w.chain = ch.ID
	in, _ := db.Installation(ctx, w.a)
	w.linkAt, w.linkU = cascade.ConfigPath(in, ch.ID, 0), cascade.UnitName(ch.ID, 0)
	l := ch.Links[0]
	l.State, l.ConfigSHA256, l.UnitSHA256, l.UpdatedAt = model.LinkActive, hexSHA(linkCfg), hexSHA([]byte(linkUnit)), time.Now()
	if err := db.UpdateLink(ctx, l); err != nil {
		t.Fatal(err)
	}

	m := w.m
	m.SetFile(cfgPath, []byte(revisionCfg))
	m.SetFile(binPath, binary)
	m.SetFile(unitPath, []byte(unitText))
	m.unit(unitName, unitPath)
	m.SetFile(geo.ServerDir+"/"+geo.GeoIP, geoIPData)
	m.SetFile(geo.ServerDir+"/"+geo.GeoSite, geoSiteDat)
	m.SetFile(w.linkAt, linkCfg)
	m.SetFile("/etc/systemd/system/"+w.linkU, []byte(linkUnit))
	m.unit(w.linkU, "/etc/systemd/system/"+w.linkU)
	m.start()

	w.conn = &conn{machines: map[int64]*machine{w.a: m}, connects: map[int64]int{}}
	w.r = &Reconciler{Store: db, Conn: w.conn, Keys: keys, Events: w.ev, Poll: 10 * time.Millisecond}
	// No rounds of its own (Interval 0): the watches of revert jobs end
	// with the test.
	rctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.r.Run(rctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return w
}

func (w *world) drift(id int64) model.Drift {
	w.t.Helper()
	d, err := w.db.Drift(context.Background(), id)
	if err != nil {
		w.t.Fatal(err)
	}
	return d
}

func (w *world) state(id int64) model.ServerState {
	s, _ := w.db.ServerByID(context.Background(), id)
	return s.State
}

func keys(items []model.DriftItem) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Key)
	}
	return out
}
