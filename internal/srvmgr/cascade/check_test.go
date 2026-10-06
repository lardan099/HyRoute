package cascade

import (
	"context"
	"errors"
	"io"
	"net"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// entryBox is an entry for CheckLink: the link service's state, what
// `hysteria ping` prints, and (tunnel set) its loopback, where a SOCKS5
// server stands for the link client. The binary is root's unless
// writable says which path another user may write.
type entryBox struct {
	service  string
	ping     string
	tunnel   func(ctx context.Context, port int) (net.Conn, error)
	writable string
	pinged   bool
}

func (e *entryBox) Run(_ context.Context, cmd remote.Cmd) (remote.Result, error) {
	a := cmd.Args
	switch {
	case len(a) == 4 && a[0] == "systemctl" && a[1] == "is-active":
		return remote.Result{Stdout: []byte(e.service + "\n")}, nil
	case len(a) > 1 && a[len(a)-2] == "ping":
		e.pinged = true
		return remote.Result{Stderr: []byte(e.ping)}, nil
	case a[0] == "readlink":
		return remote.Result{Stdout: []byte(a[len(a)-1] + "\n")}, nil
	case a[0] == "stat":
		var out string
		for _, p := range a[5:] {
			if p == e.writable {
				out += "999 999 755\n"
			} else {
				out += "0 0 755\n"
			}
		}
		return remote.Result{Stdout: []byte(out)}, nil
	}
	return remote.Result{ExitCode: 127}, nil
}
func (e *entryBox) Stream(context.Context, remote.Cmd, func(string)) error { return nil }
func (e *entryBox) ReadFile(context.Context, string, bool) ([]byte, error) { return nil, nil }
func (e *entryBox) WriteFile(context.Context, string, []byte, remote.FileSpec) error {
	return errors.New("no writes")
}
func (e *entryBox) Close() error { return nil }

// tunneled is an entryBox whose loopback the check can reach.
type tunneled struct{ *entryBox }

func (t tunneled) DialLoopback(ctx context.Context, port int) (net.Conn, error) {
	return t.tunnel(ctx, port)
}

const (
	pingOK = `{"level":"info","time":1000,"msg":"ping mode"}
{"level":"info","time":1042,"msg":"connected to server"}
{"level":"info","time":1055,"msg":"connected","time":"12.5ms"}
`
	pingSlow = `{"level":"info","time":1000,"msg":"ping mode"}
{"level":"info","time":4100,"msg":"connected to server"}
{"level":"info","time":4110,"msg":"connected","time":"9ms"}
`
	pingNoTarget = `{"level":"info","time":1000,"msg":"ping mode"}
{"level":"info","time":1040,"msg":"connected to server"}
{"level":"fatal","time":1300,"msg":"failed to connect","error":"connect: connection refused","time":"200ms"}
`
	pingDown = `{"level":"info","time":1000,"msg":"ping mode"}
{"level":"fatal","time":6000,"msg":"failed to initialize client","error":"timeout: no recent network activity"}
`
)

// linkClient is a SOCKS5 server with the link's login on this machine's
// loopback; open says whether it reaches the check target.
func linkClient(t *testing.T, user, pass string, open bool) string {
	t.Helper()
	// The check target: a listener on loopback that takes connections.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(time.Second); c.Close() }()
		}
	}()
	s := &socks5.Server{Username: user, Password: pass, Dial: func(network, addr string) (net.Conn, error) {
		if !open {
			return nil, errors.New("refused")
		}
		return net.Dial("tcp", target.Addr().String())
	}}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s.Addr()
}

func probe() Probe {
	return Probe{Chain: 3, Link: model.ChainLink{Idx: 0}, Params: Params{LocalPort: 41000},
		Secrets: Secrets{SOCKSUser: "hyroute", SOCKSPassword: "fake-socks-pass", ExitPassword: "fake-link-pass"},
		Entry:   model.Installation{Binary: binPath, Config: cfgPath}, Exit: model.Server{Name: "Exit", Host: "203.0.113.2", SSHPort: 22}}
}

func TestCheckLink(t *testing.T) {
	ctx := context.Background()
	dialTo := func(addr string) func(context.Context, int) (net.Conn, error) {
		return func(ctx context.Context, port int) (net.Conn, error) {
			if port != 41000 {
				return nil, errors.New("wrong port")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	good := linkClient(t, "hyroute", "fake-socks-pass", true)
	for _, tc := range []struct {
		desc   string
		ex     remote.Executor
		status model.ServerState
		reason string
	}{
		{"all works", tunneled{&entryBox{service: "active", ping: pingOK, tunnel: dialTo(good)}}, model.StateHealthy, ""},
		{"no tunnel: ping alone", &entryBox{service: "active", ping: pingOK}, model.StateHealthy, ""},
		{"service down", tunneled{&entryBox{service: "failed", ping: pingOK, tunnel: dialTo(good)}}, model.StateOffline, "не работает (failed)"},
		{"other password", tunneled{&entryBox{service: "active", ping: pingOK, tunnel: dialTo(linkClient(t, "hyroute", "fake-other", true))}}, model.StateOffline, "не принял пароль"},
		{"nothing listens", tunneled{&entryBox{service: "active", ping: pingOK, tunnel: func(context.Context, int) (net.Conn, error) {
			return nil, errors.New("connect failed")
		}}}, model.StateOffline, "не отвечает на 127.0.0.1:41000"},
		{"exit down", tunneled{&entryBox{service: "active", ping: pingDown, tunnel: dialTo(linkClient(t, "hyroute", "fake-socks-pass", false))}}, model.StateOffline, "сервер выхода не отвечает"},
		{"target closed", tunneled{&entryBox{service: "active", ping: pingNoTarget, tunnel: dialTo(linkClient(t, "hyroute", "fake-socks-pass", false))}}, model.StateDegraded, "не открывает 203.0.113.2:22"},
		{"target closed to ping only", tunneled{&entryBox{service: "active", ping: pingNoTarget, tunnel: dialTo(good)}}, model.StateHealthy, ""},
		{"slow", &entryBox{service: "active", ping: pingSlow}, model.StateDegraded, "рукопожатие 3100 мс"},
	} {
		c := CheckLink(ctx, tc.ex, probe(), time.Unix(1_700_000_000, 0))
		if c.Status != tc.status || !strings.Contains(c.Reason, tc.reason) {
			t.Errorf("%s: %s %q", tc.desc, c.Status, c.Reason)
		}
		if strings.Contains(c.Reason, "fake-") {
			t.Errorf("%s: a secret in %q", tc.desc, c.Reason)
		}
	}
	c := CheckLink(ctx, tunneled{&entryBox{service: "active", ping: pingOK, tunnel: dialTo(good)}}, probe(), time.Unix(1_700_000_000, 0))
	if c.HandshakeMillis != 42 || c.TCPMillis != 12 || c.Service != "active" || c.ChainID != 3 {
		t.Fatalf("%+v", c)
	}
	// A binary another user can replace is not run as root.
	box := &entryBox{service: "active", ping: pingOK, writable: path.Dir(binPath)}
	c = CheckLink(ctx, box, probe(), time.Unix(1_700_000_000, 0))
	if c.Status != model.StateOffline || !strings.Contains(c.Reason, "не только root") || box.pinged {
		t.Fatalf("writable binary directory: %+v pinged=%v", c, box.pinged)
	}
}

// noDeadline is a connection like an SSH channel: no deadlines.
type noDeadline struct{ net.Conn }

func (noDeadline) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (noDeadline) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (noDeadline) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

// Another program on the link's port takes the connection and stays
// silent: the probe gives up on its own, without deadlines.
func TestCheckLinkSilentPort(t *testing.T) {
	defer func(d time.Duration) { tunnelProbe = d }(tunnelProbe)
	tunnelProbe = 200 * time.Millisecond
	silent := func(context.Context, int) (net.Conn, error) {
		a, b := net.Pipe()
		go io.Copy(io.Discard, b) // reads, never answers
		t.Cleanup(func() { b.Close() })
		return noDeadline{a}, nil
	}
	done := make(chan model.LinkCheck, 1)
	go func() {
		done <- CheckLink(context.Background(), tunneled{&entryBox{service: "active", ping: pingOK, tunnel: silent}}, probe(), time.Unix(1_700_000_000, 0))
	}()
	select {
	case c := <-done:
		if c.Status != model.StateOffline || !strings.Contains(c.Reason, "не отвечает на 127.0.0.1:41000") {
			t.Fatalf("%s %q", c.Status, c.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the probe hangs")
	}
}

// The monitor's checker on a deployed link: results are stored, a broken
// link names its exit.
func TestCheckerCheckLinks(t *testing.T) {
	w := linked(t, exitUP)
	ctx := context.Background()
	k := &Checker{Store: w.db, Keys: w.keys, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	entry, _ := w.db.ServerByID(ctx, w.in)
	exit, _ := w.db.ServerByID(ctx, w.out)
	if !k.HasLinks(ctx, w.in) || k.HasLinks(ctx, w.out) {
		t.Fatal("HasLinks")
	}
	if down, err := k.CheckLinks(ctx, entry, w.entry); err != nil || down != "" {
		t.Fatalf("%q %v", down, err)
	}
	if down, err := k.CheckLinks(ctx, exit, w.exit); err != nil || down != "" {
		t.Fatalf("the exit has no link to check: %q %v", down, err)
	}
	w.exit.mu.Lock()
	w.exit.down = true
	w.exit.mu.Unlock()
	k.Now = func() time.Time { return time.Unix(1_700_000_060, 0) }
	down, err := k.CheckLinks(ctx, entry, w.entry)
	if err != nil || !strings.Contains(down, "каскад до «Exit» не работает") {
		t.Fatalf("%q %v", down, err)
	}
	cs, _ := w.db.LinkChecks(ctx, w.chain, 0, time.Time{}, 0)
	if len(cs) != 2 || cs[0].Status != model.StateOffline || cs[1].Status != model.StateHealthy || cs[1].HandshakeMillis != 42 {
		t.Fatalf("%+v", cs)
	}
	if err := k.Prune(ctx, time.Unix(1_700_000_030, 0)); err != nil {
		t.Fatal(err)
	}
	if cs, _ = w.db.LinkChecks(ctx, w.chain, 0, time.Time{}, 0); len(cs) != 1 {
		t.Fatalf("after prune: %d", len(cs))
	}
}
