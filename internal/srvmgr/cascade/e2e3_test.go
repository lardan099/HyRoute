package cascade

// The end-to-end test of a chain of three (P4-08): entry → relay → exit
// over real SSH (sshexec against in-process SSH servers on the host
// simulator), each link checked through its SSH tunnel to a SOCKS5
// server on this machine's loopback, and the chain taken off again.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

func TestEndToEndThree(t *testing.T) {
	ctx := context.Background()
	w := three(t)
	w.stop() // the simulators' own controller: this one goes by SSH
	conn := sshHosts{}
	for i, id := range w.ids {
		conn[id] = serve(t, w.hosts[i])
	}
	eng := jobs.New(w.db, w.keys, redact.New(), conn, nil)
	eng.Poll = 10 * time.Millisecond
	l := New(Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 2 * time.Second, Poll: 10 * time.Millisecond})
	eng.Register(l.Kind())
	eng.Register(l.UnlinkKind())
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { eng.Run(runCtx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	w.linker = l

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	var reached atomic.Int32
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			c.Close()
		}
	}()
	more := func(than int32) bool {
		for i := 0; i < 100 && reached.Load() <= than; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		return reached.Load() > than
	}
	// The client of each link stands on this machine's loopback with its
	// link's login: the entry's to the relay, the relay's to the exit.
	var socksPass []string
	for idx := range 2 {
		sec := Secrets{SOCKSUser: fmt.Sprintf("link-e2e-%d", idx), SOCKSPassword: fmt.Sprintf("fake-e2e-socks-%d", idx), ExitPassword: fmt.Sprintf("fake-e2e-exit-%d", idx)}
		socksPass = append(socksPass, sec.SOCKSPassword, sec.ExitPassword)
		sealed, err := SealSecrets(w.keys, w.chain, idx, sec)
		if err != nil {
			t.Fatal(err)
		}
		w.db.SetLinkSecrets(ctx, w.chain, idx, sealed, time.Now())
		client := &socks5.Server{Username: sec.SOCKSUser, Password: sec.SOCKSPassword}
		if err := client.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		_, port, _ := net.SplitHostPort(client.Addr())
		var localPort int
		fmt.Sscan(port, &localPort)
		link := w.links()[idx]
		link.Params = Params{LocalPort: localPort, CheckTarget: target.Addr().String()}.Raw()
		if err := w.db.UpdateLink(ctx, link); err != nil {
			t.Fatal(err)
		}
	}

	// Both links, by one job, the exit's first.
	j, log := w.deploy()
	if j.State != model.JobCompleted {
		t.Fatalf("link: %s %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	if !before(log, "Через сервер «Exit» открыт "+target.Addr().String(), "Через сервер «Relay» открыт "+target.Addr().String()) || !more(1) {
		t.Fatalf("links not checked through the tunnels (target reached %d times):\n%s", reached.Load(), log)
	}
	for i, h := range w.hosts[:2] {
		cfg, _ := h.file(cfgPath)
		c, err := hyconfig.ParseServer([]byte(cfg))
		if err != nil || len(c.Outbounds) == 0 || c.Outbounds[0].Name != OutboundName || h.unit(UnitName(w.chain, i)) != "active" {
			t.Fatalf("%s: outbounds %v\n%s", h.name, err, cfg)
		}
	}
	rc, _ := w.hosts[1].file(cfgPath)
	if c, _ := hyconfig.ParseServer([]byte(rc)); c.Auth.UserPass[User(w.chain, 0)] != "fake-e2e-exit-0" {
		t.Fatalf("relay users:\n%s", rc)
	}

	// Each link checked now from the server it starts at, over SSH,
	// through its tunnel.
	k := &Checker{Store: w.db, Keys: w.keys}
	for idx := range 2 {
		srv, _ := w.db.ServerByID(ctx, w.ids[idx])
		ex, err := conn.Connect(ctx, w.ids[idx])
		if err != nil {
			t.Fatal(err)
		}
		was := reached.Load()
		down, err := k.CheckLinks(ctx, srv, ex)
		ex.Close()
		if err != nil || down != "" || !more(was) {
			t.Fatalf("check from %s: %q %v", srv.Name, down, err)
		}
		checks, _ := w.db.LinkChecks(ctx, w.chain, idx, time.Time{}, 1)
		if len(checks) != 1 || checks[0].Status != model.StateHealthy || checks[0].Idx != idx {
			t.Fatalf("checks of link %d: %+v", idx, checks)
		}
	}

	// The chain off: the entry first, the exit last.
	j, log = w.unlinkAll(false)
	if j.State != model.JobCompleted {
		t.Fatalf("unlink: %s %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	if !before(log, "С сервера «Entry» убран outbound", "С сервера «Relay» убран outbound") || !before(log, "С сервера «Relay» убран outbound", "С сервера «Exit» убран пользователь связи") {
		t.Fatalf("unlink order:\n%s", log)
	}
	for i, h := range w.hosts {
		cfg, _ := h.file(cfgPath)
		c, _ := hyconfig.ParseServer([]byte(cfg))
		if HasOutbound(c) || HasUser(c, User(w.chain, 0)) || HasUser(c, User(w.chain, 1)) {
			t.Fatalf("%s after unlink:\n%s", h.name, cfg)
		}
		if i < 2 {
			if _, found := h.file(w.linkCfgOf(i)); found {
				t.Fatalf("link client left on %s", h.name)
			}
		}
	}
	for i, l := range w.links() {
		if l.State != model.LinkNew {
			t.Fatalf("link %d %s", i, l.State)
		}
	}
	// No secret of either link on a command line of any server.
	for _, id := range w.ids {
		lines := strings.Join(conn[id].Lines(), "\n")
		for _, secret := range socksPass {
			if strings.Contains(lines, secret) {
				t.Fatalf("a secret on a command line of server %d", id)
			}
		}
		if !strings.Contains(lines, "systemctl restart") {
			t.Fatalf("server %d not restarted by SSH:\n%s", id, lines)
		}
	}
}
