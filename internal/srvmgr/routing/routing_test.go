package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const config = `listen: :443
acme:
  domains:
    - vpn.example.com
auth:
  type: password
  password: fake-routing-auth
masquerade:
  type: proxy
  proxy:
    url: https://www.example.com
resolver:
  type: udp
  udp:
    addr: 1.1.1.1:53
acl:
  inline:
    - reject(geoip:private)
    - 'proxy(suffix:example.com) # ex'
    - web(all, tcp/80)
outbounds:
  - name: cascade
    type: socks5
    socks5:
      addr: 127.0.0.1:40001
      username: link-1-0
      password: fake-cascade-pass
  - name: proxy
    type: socks5
    socks5:
      addr: 203.0.113.5:1080
      username: u
      password: fake-proxy-pass
      dialTimeout: 5s
  - name: web
    type: http
    http:
      url: http://alice:fake-http-pass@203.0.113.6:3128
  - name: isp
    type: direct
    direct:
      mode: "46"
      bindDevice: eth1
`

type chains []model.Chain

func (c chains) ListChains(context.Context) ([]model.Chain, error) { return c, nil }

type env struct {
	t      *testing.T
	db     *sqlite.DB
	svc    *Service
	server int64
	eng    *jobs.Engine
}

func newEnv(t *testing.T, cfg string, linked bool) *env {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{5}, 32)})
	srv := model.Server{Name: "entry", Host: "192.0.2.60", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := db.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte(cfg))
	c := model.ServerConfig{ServerID: srv.ID, SHA256: hex.EncodeToString(s[:]), Source: model.ConfigDeploy, At: time.Now()}
	if err := db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) }); err != nil {
		t.Fatal(err)
	}
	eng := jobs.New(db, keys, redact.New(), nil, nil)
	app := apply.New(apply.Deps{Store: db, Keys: keys, Jobs: eng})
	eng.Register(app.Kind())
	var cs chains
	if linked {
		cs = chains{{ID: 7, Name: "RU→NL", Nodes: []int64{srv.ID, 99}, Links: []model.ChainLink{{ChainID: 7, State: model.LinkActive}}}}
	}
	return &env{t: t, db: db, server: srv.ID, eng: eng, svc: &Service{Editor: &apply.Editor{Store: db, Keys: keys}, Applier: app, Chains: cs}}
}

// input is the view sent back unchanged.
func (e *env) input() Input {
	v, err := e.svc.Open(context.Background(), e.server)
	if err != nil {
		e.t.Fatal(err)
	}
	return Input{Base: v.Revision, ACL: v.ACL, Outbounds: v.Outbounds, Resolver: v.Resolver}
}

func TestOpen(t *testing.T) {
	e := newEnv(t, config, true)
	v, err := e.svc.Open(context.Background(), e.server)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "fake-") {
		t.Fatalf("a password in the view: %s", b)
	}
	if v.Cascade == nil || v.Cascade.Name != "RU→NL" || len(v.Outbounds) != 4 || !v.Outbounds[0].Locked || v.Outbounds[1].Locked {
		t.Fatalf("%+v", v)
	}
	if o := v.Outbounds[2]; o.Type != "http" || o.HTTP.URL != "http://alice@203.0.113.6:3128" || o.HTTP.Password != apply.Hidden {
		t.Fatalf("http %+v", o.HTTP)
	}
	if o := v.Outbounds[3]; o.Direct.Mode != "46" || o.Direct.BindDevice != "eth1" || o.From != "isp" {
		t.Fatalf("direct %+v", o)
	}
	if v.Resolver != (Resolver{Type: "udp", Addr: "1.1.1.1:53"}) || len(v.ACL.Rules) != 3 || v.ACL.Rules[1].Comment != "ex" {
		t.Fatalf("%+v %+v", v.Resolver, v.ACL)
	}
	// The entry of a cascade with plain DNS: the lint says so.
	if !slices.ContainsFunc(v.Problems, func(p acl.Problem) bool { return p.Code == "plain_resolver" }) {
		t.Fatalf("%+v", v.Problems)
	}
}

// The view sent back unchanged changes nothing; passwords stay.
func TestUnchanged(t *testing.T) {
	e := newEnv(t, config, true)
	p, cand, _, err := e.svc.candidate(context.Background(), e.server, e.input())
	if err != nil {
		t.Fatal(err)
	}
	if apply.Changed(p.Diff) || len(p.Secrets) != 0 || len(p.Changes) != 0 || !p.OK {
		t.Fatalf("%+v", p)
	}
	for _, s := range []string{"fake-cascade-pass", "fake-proxy-pass", "alice:fake-http-pass@", "dialTimeout: 5s"} {
		if !strings.Contains(string(cand), s) {
			t.Errorf("%s lost:\n%s", s, cand)
		}
	}
	var fe *model.FieldError
	if _, err := e.svc.Apply(context.Background(), e.server, e.input(), 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "Изменений нет") {
		t.Fatalf("%v", err)
	}
}

func TestEdit(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, config, true)
	in := e.input()
	// Rename proxy to nl (its rules follow), drop web (its rule goes too),
	// a new socks5 with its password, DoH, a rule more.
	in.Outbounds[1].Name = "nl"
	in.Outbounds = append(in.Outbounds[:2], in.Outbounds[3], Outbound{Name: "extra", Type: "socks5", SOCKS5: &SOCKS5{Addr: "203.0.113.7:1080", Password: "fake-new-pass"}})
	in.ACL.Rules = append(in.ACL.Rules[:2], acl.Rule{Outbound: "isp", Address: "geoip:ru"})
	in.Resolver = Resolver{Type: "https", Addr: "1.1.1.1:443"}
	in.Requests = []acl.Request{{Host: "www.example.com", Port: 443}}
	p, cand, _, err := e.svc.candidate(ctx, e.server, in)
	if err != nil {
		t.Fatal(err)
	}
	if !p.OK || p.ACL.Rules[1].Outbound != "nl" || p.ACL.Rules[1].Text != "proxy(suffix:example.com) # ex" {
		t.Fatalf("%+v\n%+v", p.ACL.Rules, p.Rules)
	}
	c, err := hyconfig.ParseServer(cand)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.ACL.Inline, "\n"); got != "reject(geoip:private)\nnl(suffix:example.com) # ex\nisp(geoip:ru)" {
		t.Fatalf("acl:\n%s", got)
	}
	var names []string
	for _, o := range c.Outbounds {
		names = append(names, o.Name)
	}
	if !slices.Equal(names, []string{"cascade", "nl", "isp", "extra"}) || c.Outbounds[1].SOCKS5.Password != "fake-proxy-pass" || c.Outbounds[3].SOCKS5.Password != "fake-new-pass" ||
		c.Outbounds[1].SOCKS5.Unknown == nil {
		t.Fatalf("outbounds %+v", c.Outbounds)
	}
	if c.Resolver.Type != "https" || c.Resolver.HTTPS.Addr != "1.1.1.1:443" || c.Resolver.UDP.Addr != "1.1.1.1:53" {
		t.Fatalf("resolver %+v", c.Resolver)
	}
	// DoH on the entry: no plain DNS lint. The web rule is gone: port 80
	// goes to the cascade now.
	if slices.ContainsFunc(p.Rules, func(pr acl.Problem) bool { return pr.Code == "plain_resolver" }) {
		t.Fatalf("%+v", p.Rules)
	}
	var changed []string
	for _, ch := range p.Changes {
		changed = append(changed, ch.Request.Host+":"+ch.Before.Outbound+">"+ch.After.Outbound)
	}
	if !slices.Contains(changed, "www.example.com:proxy>nl") {
		t.Fatalf("%q", changed)
	}
	// The current passwords stay hidden; the new one is the admin's own.
	if strings.Contains(p.YAML, "fake-proxy-pass") || strings.Contains(p.YAML, "fake-cascade-pass") || len(p.Secrets) == 0 {
		t.Fatalf("yaml %s\nsecrets %v", p.YAML, p.Secrets)
	}

	j, err := e.svc.Apply(ctx, e.server, in, 0)
	if err != nil {
		t.Fatal(err)
	}
	var params apply.Params
	json.Unmarshal(j.Params, &params)
	if j.Kind != apply.JobKind || params.Change != apply.ChangeRouting || params.Base != 1 {
		t.Fatalf("%+v %+v", j, params)
	}
}

func TestRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, config, true)
	var fe *model.FieldError
	for name, change := range map[string]func(in *Input){
		"cascade moved":   func(in *Input) { in.Outbounds[0], in.Outbounds[1] = in.Outbounds[1], in.Outbounds[0] },
		"cascade removed": func(in *Input) { in.Outbounds = in.Outbounds[1:] },
		"cascade renamed": func(in *Input) { in.Outbounds[0].Name = "nl" },
		"cascade taken":   func(in *Input) { in.Outbounds[1].Name = "Cascade" },
		"no password": func(in *Input) {
			in.Outbounds = append(in.Outbounds, Outbound{Name: "x", Type: "socks5", SOCKS5: &SOCKS5{Addr: "a:1", Password: apply.Hidden}})
		},
		"type":        func(in *Input) { in.Outbounds[3].Type = "wireguard" },
		"stale from":  func(in *Input) { in.Outbounds[3].From = "gone" },
		"rule error":  func(in *Input) { in.ACL.Rules = append(in.ACL.Rules, acl.Rule{Outbound: "nowhere", Address: "all"}) },
		"bad request": func(in *Input) { in.Requests = []acl.Request{{Host: "x.com"}} },
		"http type, hidden": func(in *Input) {
			in.Outbounds[3].Type, in.Outbounds[3].HTTP = "http", &HTTP{URL: "http://h:1", Password: apply.Hidden}
		},
	} {
		in := e.input()
		change(&in)
		if _, err := e.svc.Apply(ctx, e.server, in, 0); !errors.As(err, &fe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A config check error refuses too: two outbounds of one name.
	in := e.input()
	in.Outbounds[2].Name = "proxy"
	if p, err := e.svc.Preview(ctx, e.server, in); err != nil || p.OK {
		t.Fatalf("dup: %v %+v", err, p.Problems)
	}
	if _, err := e.svc.Apply(ctx, e.server, in, 0); !errors.As(err, &fe) {
		t.Fatalf("dup: %v", err)
	}
	// Stale base.
	in = e.input()
	in.Base = 5
	var stale *apply.StaleError
	if _, err := e.svc.Preview(ctx, e.server, in); !errors.As(err, &stale) {
		t.Fatalf("stale: %v", err)
	}
}

// Without a deployed cascade the outbound named cascade is an ordinary
// one.
func TestNotLinked(t *testing.T) {
	e := newEnv(t, config, false)
	in := e.input()
	if in.Outbounds[0].Locked {
		t.Fatal("locked")
	}
	in.Outbounds = in.Outbounds[1:]
	p, cand, _, err := e.svc.candidate(context.Background(), e.server, in)
	if err != nil || !p.OK || strings.Contains(string(cand), "fake-cascade-pass") {
		t.Fatalf("%v %+v", err, p)
	}
}

const fileConfig = `listen: :443
acme:
  domains:
    - vpn.example.com
auth:
  type: password
  password: fake-routing-auth
masquerade:
  type: proxy
  proxy:
    url: https://www.example.com
acl:
  file: /etc/hysteria/acl.txt
`

type fileHost struct {
	remote.Executor
	data []byte
	err  error
}

func (h fileHost) Run(context.Context, remote.Cmd) (remote.Result, error) {
	return remote.Result{Stdout: []byte("0\n")}, nil
}
func (h fileHost) ReadFile(context.Context, string, bool) ([]byte, error) { return h.data, h.err }
func (fileHost) Close() error                                             { return nil }

func TestFile(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, fileConfig, false)
	v, err := e.svc.Open(ctx, e.server)
	if err != nil || v.File != "/etc/hysteria/acl.txt" || len(v.ACL.Rules) != 0 || len(v.Problems) != 0 {
		t.Fatalf("%v %+v", err, v)
	}
	host := fileHost{data: []byte("# rules\ndirect(geoip:ru)\nreject(all, udp/443)\n")}
	e.svc.Connect = func(context.Context, int64) (remote.Executor, error) { return host, nil }
	f, err := e.svc.File(ctx, e.server)
	doc := f.ACL
	if err != nil || f.Path != "/etc/hysteria/acl.txt" || len(doc.Rules) != 2 || doc.Text() != string(host.data) || len(f.Problems) == 0 {
		t.Fatalf("%v %+v", err, f)
	}

	// Keep the file: the ACL is not touched.
	in := Input{Base: v.Revision, KeepFile: true, Resolver: Resolver{Type: "tls", Addr: "1.1.1.1:853"}}
	p, cand, _, err := e.svc.candidate(ctx, e.server, in)
	if err != nil || !p.OK || !strings.Contains(string(cand), "file: /etc/hysteria/acl.txt") {
		t.Fatalf("%v %+v\n%s", err, p, cand)
	}
	// Move into acl.inline.
	in = Input{Base: v.Revision, ACL: doc, Resolver: v.Resolver}
	p, cand, _, err = e.svc.candidate(ctx, e.server, in)
	c, _ := hyconfig.ParseServer(cand)
	if err != nil || c.ACL.File != "" || len(c.ACL.Inline) != 3 || c.ACL.Inline[1] != "direct(geoip:ru)" {
		t.Fatalf("%v %+v", err, c.ACL)
	}

	// Not a rules file: nothing of it comes back.
	host.data = []byte("root:$6$fake-hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\ndirect(all)\n")
	e.svc.Connect = func(context.Context, int64) (remote.Executor, error) { return host, nil }
	if f, err := e.svc.File(ctx, e.server); err == nil || len(f.ACL.Rules) != 0 || strings.Contains(err.Error(), "fake-hash") {
		t.Fatalf("shadow: %v %+v", err, f)
	}

	host.data = bytes.Repeat([]byte("#"), MaxFile+1)
	e.svc.Connect = func(context.Context, int64) (remote.Executor, error) { return host, nil }
	var fe *model.FieldError
	if _, err := e.svc.File(ctx, e.server); !errors.As(err, &fe) {
		t.Fatalf("big: %v", err)
	}
	e2 := newEnv(t, config, false)
	if _, err := e2.svc.File(ctx, e2.server); !errors.As(err, &fe) {
		t.Fatalf("inline: %v", err)
	}
}

func TestExportImport(t *testing.T) {
	e := newEnv(t, config, true)
	v, _ := e.svc.Open(context.Background(), e.server)
	x := v.Export()
	b, _ := json.Marshal(x)
	if strings.Contains(string(b), "fake-") || strings.Contains(string(b), redact.Mask) || strings.Contains(string(b), "127.0.0.1:40001") {
		t.Fatalf("export: %s", b)
	}
	if len(x.Outbounds) != 3 || x.Outbounds[0].From != "" || x.Outbounds[1].HTTP.URL != "http://alice@203.0.113.6:3128" {
		t.Fatalf("%+v", x.Outbounds)
	}
	back, err := Import(b)
	if err != nil || !reflectEqual(back, x) {
		t.Fatalf("%v\n%+v", err, back)
	}

	// A hand-made file with passwords: they do not come in.
	in := `{"format":"hyroute-routing","version":1,"acl":{"rules":[{"outbound":"p","address":"all"}]},"outbounds":[{"name":"p","type":"http","http":{"url":"http://u:fake-x@h:1","password":"fake-y"}},{"name":"q","type":"socks5","socks5":{"addr":"h:2","password":"fake-z"}}]}`
	got, err := Import([]byte(in))
	if b, _ := json.Marshal(got); err != nil || strings.Contains(string(b), "fake-") {
		t.Fatalf("%v %s", err, b)
	}
	// A Hysteria ACL as text.
	got, err = Import([]byte("direct(all)\n"))
	if err != nil || len(got.ACL.Rules) != 1 || got.ACL.Text() != "direct(all)\n" {
		t.Fatalf("%v %+v", err, got)
	}
	var fe *model.FieldError
	for _, bad := range []string{`{"format":"other","version":1}`, `{"format":"hyroute-routing","version":2}`, `{"format":`, strings.Repeat(" ", MaxImport+1)} {
		if _, err := Import([]byte(bad)); !errors.As(err, &fe) {
			t.Errorf("%.40q: %v", bad, err)
		}
	}
}

func reflectEqual(a, b Export) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// A rule follows a rename only while its old name is free: a new outbound
// taking the old name keeps the rules naming it.
func TestRenameOldNameTaken(t *testing.T) {
	e := newEnv(t, config, true)
	in := e.input()
	in.Outbounds[1].Name = "proxy_old"
	in.Outbounds = append(in.Outbounds, Outbound{Name: "proxy", Type: "socks5", SOCKS5: &SOCKS5{Addr: "203.0.113.9:1080"}})
	p, _, _, err := e.svc.candidate(context.Background(), e.server, in)
	if err != nil {
		t.Fatal(err)
	}
	if p.ACL.Rules[1].Outbound != "proxy" {
		t.Fatalf("the rule went to %s", p.ACL.Rules[1].Outbound)
	}
	// Without the new one the rule follows the rename.
	in = e.input()
	in.Outbounds[1].Name = "proxy_old"
	if p, _, _, _ = e.svc.candidate(context.Background(), e.server, in); p.ACL.Rules[1].Outbound != "proxy_old" {
		t.Fatalf("the rule stayed on %s", p.ACL.Rules[1].Outbound)
	}
}

// A proxy URL is kept byte for byte when the editor sends it back: built
// again it would show the password as new.
func TestHTTPURLKept(t *testing.T) {
	cfg := strings.Replace(config, "http://alice:fake-http-pass@203.0.113.6:3128", "HTTP://alice:fake-pa!ss@203.0.113.6:3128/?token=fake-tok", 1)
	e := newEnv(t, cfg, true)
	v, _ := e.svc.Open(context.Background(), e.server)
	if b, _ := json.Marshal(v); strings.Contains(string(b), "fake-") {
		t.Fatalf("view: %s", b)
	}
	p, cand, _, err := e.svc.candidate(context.Background(), e.server, e.input())
	if err != nil || !p.Same || !strings.Contains(string(cand), "HTTP://alice:fake-pa!ss@203.0.113.6:3128/?token=fake-tok") || strings.Contains(p.YAML, "fake-pa") {
		t.Fatalf("%v same=%v\n%s", err, p.Same, p.YAML)
	}
}

// A secret in a comment of the rules is redacted in the view and the
// export, and kept in the config when the editor sends the rules back.
func TestRuleSecretsHidden(t *testing.T) {
	cfg := strings.Replace(config, "    - web(all, tcp/80)\n", "    - 'web(all, tcp/80) # via socks5://u:fake-comment-pw@203.0.113.8:1080'\n", 1)
	e := newEnv(t, cfg, true)
	v, _ := e.svc.Open(context.Background(), e.server)
	b, _ := json.Marshal(v)
	x, _ := json.Marshal(v.Export())
	if strings.Contains(string(b), "fake-comment-pw") || strings.Contains(string(x), "fake-comment-pw") {
		t.Fatalf("view or export: %s", b)
	}
	in := e.input()
	in.ACL.Rules = append(in.ACL.Rules, acl.Rule{Outbound: "direct", Address: "suffix:ru"})
	p, cand, _, err := e.svc.candidate(context.Background(), e.server, in)
	if err != nil || !strings.Contains(string(cand), "fake-comment-pw") {
		t.Fatalf("%v\n%s", err, cand)
	}
	if pb, _ := json.Marshal(p); strings.Contains(string(pb), "fake-comment-pw") {
		t.Fatalf("preview: %s", pb)
	}
}

// With the rules in acl.file, outbounds they may name keep their names.
func TestKeepFileOutbounds(t *testing.T) {
	cfg := fileConfig + "outbounds:\n  - name: proxy\n    type: socks5\n    socks5:\n      addr: 203.0.113.5:1080\n"
	e := newEnv(t, cfg, false)
	var fe *model.FieldError
	for name, change := range map[string]func(in *Input){
		"rename": func(in *Input) { in.Outbounds[0].Name = "nl" },
		"remove": func(in *Input) { in.Outbounds = nil },
	} {
		in := e.input()
		in.KeepFile = true
		change(&in)
		if _, err := e.svc.Preview(context.Background(), e.server, in); !errors.As(err, &fe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := e.input()
	in.KeepFile = true
	in.Outbounds = append(in.Outbounds, Outbound{Name: "extra", Type: "direct"})
	if _, err := e.svc.Preview(context.Background(), e.server, in); err != nil {
		t.Fatalf("adding one: %v", err)
	}
}
