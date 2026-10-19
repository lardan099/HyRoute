package routing

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const traceEntry = `listen: :443
auth:
  type: password
  password: fake-trace-entry
acl:
  inline:
    - direct(suffix:ru)
    - reject(suffix:ads.example)
    - cascade(suffix:hijack.example, tcp/443, 198.51.100.9)
outbounds:
  - name: cascade
    type: socks5
    socks5:
      addr: 127.0.0.1:40001
      username: hyroute
      password: fake-trace-socks
`

const traceRelay = `listen: :443
auth:
  type: password
  password: fake-trace-relay
acl:
  inline:
    - warp(suffix:openai.com)
    - direct(198.51.100.9)
outbounds:
  - name: cascade
    type: socks5
    socks5:
      addr: 127.0.0.1:40002
      username: hyroute
      password: fake-trace-socks2
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
`

const traceExit = `listen: :443
auth:
  type: password
  password: fake-trace-exit
acl:
  inline:
    - reject(suffix:blocked.example)
`

// traceChain stores servers with the configs and returns the routing
// service, the chain of them (links active) and their names.
func traceChain(t *testing.T, cfgs ...string) (*Service, model.Chain, map[int64]string) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{4}, 32)})
	c := model.Chain{ID: 3, Name: "Три"}
	names := map[int64]string{}
	for i, cfg := range cfgs {
		name := "Relay"
		switch i {
		case 0:
			name = "Entry"
		case len(cfgs) - 1:
			name = "Exit"
		}
		srv := model.Server{Name: name, Host: "192.0.2.70", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &srv, nil); err != nil {
			t.Fatal(err)
		}
		if cfg != "" {
			sc := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
			if err := db.AddConfig(ctx, &sc, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) }); err != nil {
				t.Fatal(err)
			}
		}
		names[srv.ID] = srv.Name
		c.Nodes = append(c.Nodes, srv.ID)
		if i > 0 {
			c.Links = append(c.Links, model.ChainLink{ChainID: c.ID, Idx: i - 1, From: c.Nodes[i-1], To: srv.ID, State: model.LinkActive})
		}
	}
	return &Service{Editor: &apply.Editor{Store: db, Keys: keys}, Chains: chains{c}}, c, names
}

// route is the servers a trace went through, their outbounds and the end.
func route(t Trace) string {
	var b strings.Builder
	for _, h := range t.Hops {
		b.WriteString(h.Name + ":")
		if h.Verdict != nil {
			b.WriteString(h.Verdict.Outbound)
		}
		b.WriteString(" ")
	}
	return b.String() + "| " + t.Summary
}

// The rule check along a chain: the entry's rules, and while they send a
// request into the cascade, the next server's, to the server it leaves
// from.
func TestTrace(t *testing.T) {
	ctx := context.Background()
	svc, c, names := traceChain(t, traceEntry, traceRelay, traceExit)
	for _, tc := range []struct {
		host string
		want string
	}{
		{"mail.ru", "Entry:direct | Уйдёт в интернет с «Entry» через «direct»."},
		{"www.example.com", "Entry:cascade Relay:cascade Exit:direct | Уйдёт в интернет с «Exit» через «direct»."},
		{"chat.openai.com", "Entry:cascade Relay:warp | Уйдёт в интернет с «Relay» через «warp»."},
		{"x.blocked.example", "Entry:cascade Relay:cascade Exit:reject | Соединение отклонит «Exit»."},
		{"ads.example", "Entry:reject | Соединение отклонит «Entry»."},
		// The entry hijacks it to an address the relay sends direct.
		{"hijack.example", "Entry:cascade Relay:direct | Уйдёт в интернет с «Relay» через «direct»."},
	} {
		tr, err := svc.Trace(ctx, c, 0, nil, acl.Request{Host: tc.host, Port: 443}, names)
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		if got := route(tr); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.host, got, tc.want)
		}
		if tr.Rejected != strings.Contains(tc.want, "отклонит") {
			t.Errorf("%s: rejected %v", tc.host, tr.Rejected)
		}
		last := tr.Hops[len(tr.Hops)-1]
		if last.Next || (len(tr.Hops) > 1 && !tr.Hops[0].Next) {
			t.Errorf("%s: next %+v", tc.host, tr.Hops)
		}
	}
	tr, _ := svc.Trace(ctx, c, 0, nil, acl.Request{Host: "chat.openai.com", Port: 443}, names)
	if v := tr.Hops[1].Verdict; v.Rule != 0 || !strings.Contains(v.Reason, "Правило 1") || tr.Hops[1].Role != model.RoleRelay {
		t.Fatalf("relay verdict %+v", tr.Hops[1])
	}

	// From the relay (its routing editor), with the editor's draft there.
	tr, err := svc.Trace(ctx, c, 1, &Draft{ACL: acl.ParseInline([]string{"direct(suffix:openai.com)"}), Outbounds: []string{"cascade", "warp"}}, acl.Request{Host: "chat.openai.com", Port: 443}, names)
	if err != nil || route(tr) != "Relay:direct | Уйдёт в интернет с «Relay» через «direct»." {
		t.Fatalf("draft: %s %v", route(tr), err)
	}

	// A link not deployed: the outbound goes nowhere yet.
	c.Links[1].State = model.LinkNew
	tr, _ = svc.Trace(ctx, c, 0, nil, acl.Request{Host: "www.example.com", Port: 443}, names)
	if route(tr) != "Entry:cascade Relay:cascade | Уйдёт в outbound «cascade» сервера «Relay», но связь каскада до «Exit» не развёрнута." {
		t.Fatalf("link not deployed: %s", route(tr))
	}

	var fe *model.FieldError
	if _, err := svc.Trace(ctx, c, 0, nil, acl.Request{Host: "www.example.com"}, names); !errors.As(err, &fe) || fe.Field != "request" {
		t.Fatalf("no port: %v", err)
	}
}

// Two nodes already: the entry sends a domain into the cascade, and the
// exit's own rules decide where it ends. A server whose rules HyRoute
// does not have ends the trace.
func TestTraceTwoNodes(t *testing.T) {
	ctx := context.Background()
	svc, c, names := traceChain(t, traceEntry, traceExit)
	tr, err := svc.Trace(ctx, c, 0, nil, acl.Request{Host: "www.blocked.example", Port: 443}, names)
	if err != nil || route(tr) != "Entry:cascade Exit:reject | Соединение отклонит «Exit»." || tr.Hops[0].Role != model.RoleEntry || tr.Hops[1].Role != model.RoleExit {
		t.Fatalf("%s %v", route(tr), err)
	}

	svc, c, names = traceChain(t, traceEntry, strings.Replace(traceRelay, "acl:\n  inline:\n    - warp(suffix:openai.com)\n    - direct(198.51.100.9)\n", "acl:\n  file: /etc/hysteria/acl.txt\n", 1), "")
	tr, _ = svc.Trace(ctx, c, 0, nil, acl.Request{Host: "www.example.com", Port: 443}, names)
	if !strings.Contains(route(tr), "На «Relay» маршрут не проверить: правила сервера в файле /etc/hysteria/acl.txt") || tr.Hops[1].Verdict != nil {
		t.Fatalf("acl.file: %s", route(tr))
	}
	c.Nodes, c.Links = []int64{c.Nodes[0], c.Nodes[2]}, c.Links[:1]
	c.Links[0].To = c.Nodes[1]
	tr, _ = svc.Trace(ctx, c, 0, nil, acl.Request{Host: "www.example.com", Port: 443}, names)
	if !strings.Contains(route(tr), "На «Exit» маршрут не проверить: HyRoute не знает конфиг этого сервера") {
		t.Fatalf("no config: %s", route(tr))
	}
}

// A relay's outbound "cascade" belongs to its cascade in the editor, as
// the entry's does.
func TestRelayOutboundLocked(t *testing.T) {
	svc, c, _ := traceChain(t, traceEntry, traceRelay, traceExit)
	v, err := svc.Open(context.Background(), c.Nodes[1])
	if err != nil {
		t.Fatal(err)
	}
	if v.Cascade == nil || v.Cascade.Name != "Три" || !v.Outbounds[0].Locked || v.Outbounds[1].Locked {
		t.Fatalf("%+v", v)
	}
	if v, _ := svc.Open(context.Background(), c.Nodes[2]); v.Cascade != nil {
		t.Fatalf("the exit sends through a cascade: %+v", v.Cascade)
	}
}
