package apply

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const current = `# managed by hand
listen: :443 # the public port
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: fake-current-auth
obfs:
  type: salamander
  salamander:
    password: fake-current-obfs
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      password: fake-warp-pass
  - name: direct
    type: direct
trafficStats:
  listen: 127.0.0.1:9999
  secret: fake-stats-secret
futureOption: true
`

func TestMaskKeepsCommentsAndHidesSecrets(t *testing.T) {
	m, paths, err := Mask([]byte(current))
	if err != nil {
		t.Fatal(err)
	}
	s := string(m)
	for _, secret := range []string{"fake-current-auth", "fake-current-obfs", "fake-warp-pass", "fake-stats-secret"} {
		if strings.Contains(s, secret) {
			t.Fatalf("%s visible:\n%s", secret, s)
		}
	}
	if !strings.Contains(s, "# managed by hand") || !strings.Contains(s, "# the public port") || !strings.Contains(s, "futureOption: true") {
		t.Fatalf("comments or unknown fields lost:\n%s", s)
	}
	want := []string{"auth.password", "obfs.salamander.password", "outbounds[name=warp].socks5.password", "trafficstats.secret"}
	if !slices.Equal(paths, want) {
		t.Fatalf("%q", paths)
	}
	// Masked back to unmasked: the same config.
	back, err := Unmask(m, []byte(current))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := hyconfig.ParseServer(back)
	b, _ := hyconfig.ParseServer([]byte(current))
	if a.Auth.Password != b.Auth.Password || a.Obfs.Salamander.Password != b.Obfs.Salamander.Password || a.Outbounds[0].SOCKS5.Password != "fake-warp-pass" {
		t.Fatal("secrets not restored")
	}
}

func TestUnmaskMatchesListItemsByName(t *testing.T) {
	m, _, _ := Mask([]byte(current))
	// The admin swaps the outbounds: the password follows its outbound.
	swapped := strings.Replace(string(m), `  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      password: '[REDACTED]'
  - name: direct
    type: direct
`, `  - name: direct
    type: direct
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      password: '[REDACTED]'
`, 1)
	if swapped == string(m) {
		t.Fatalf("fixture did not match:\n%s", m)
	}
	back, err := Unmask([]byte(swapped), []byte(current))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := hyconfig.ParseServer(back)
	if c.Outbounds[1].Name != "warp" || c.Outbounds[1].SOCKS5.Password != "fake-warp-pass" {
		t.Fatalf("%+v", c.Outbounds)
	}
	// A hidden value with nothing behind it.
	_, err = Unmask([]byte("auth:\n  type: userpass\n  userpass:\n    newuser: '[REDACTED]'\n"), []byte(current))
	var fe *model.FieldError
	if !errors.As(err, &fe) || fe.Field != "auth.userpass.newuser" {
		t.Fatalf("%v", err)
	}
}

func TestBuildFromText(t *testing.T) {
	m, _, _ := Mask([]byte(current))
	text := strings.Replace(string(m), "listen: :443", "listen: :8443", 1)
	ch, cand, err := Build([]byte(current), text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.OK || ch.Fields.Listen != ":8443" || len(ch.Secrets) != 0 || !slices.Equal(ch.Unknown, []string{"futureOption"}) {
		t.Fatalf("%+v", ch)
	}
	var added, removed int
	for _, l := range ch.Diff {
		switch l.Op {
		case "+":
			added++
			if !strings.Contains(l.Text, "8443") {
				t.Fatalf("diff: %+v", ch.Diff)
			}
		case "-":
			removed++
		}
	}
	if added != 1 || removed != 1 {
		t.Fatalf("diff: %+v", ch.Diff)
	}
	if strings.Contains(ch.YAML, "fake-current") || strings.Contains(diffText(ch.Diff), "fake-current") {
		t.Fatal("secret in the editor's view")
	}
	c, _ := hyconfig.ParseServer(cand)
	if c.Listen != ":8443" || c.Auth.Password != "fake-current-auth" || !strings.Contains(string(cand), "# the public port") {
		t.Fatalf("candidate:\n%s", cand)
	}

	// A broken config is refused with a message; an invalid one is built
	// with its problems and not OK.
	if _, _, err := Build([]byte(current), "listen: [", nil); err == nil {
		t.Fatal("broken YAML built")
	}
	ch, _, err = Build([]byte(current), strings.Replace(string(m), "listen: :443", "listen: :99999", 1), nil)
	if err != nil || ch.OK || !hyconfig.HasErrors(ch.Problems) {
		t.Fatalf("%+v %v", ch.Problems, err)
	}
}

func TestBuildFromFields(t *testing.T) {
	m, _, _ := Mask([]byte(current))
	mc, _ := hyconfig.ParseServer(m)
	f := FieldsOf(mc)
	if f.TLS != "file" || f.AuthPassword != Hidden || f.Obfs != "salamander" || f.ObfsPassword != Hidden {
		t.Fatalf("%+v", f)
	}
	// Switch to ACME, change the auth password, drop obfs, add a site.
	f.TLS, f.ACMEDomains, f.ACMEEmail = "acme", []string{"vpn.example.com"}, "admin@example.com"
	f.AuthPassword = "fake-new-auth-password"
	f.Obfs = ""
	f.Masquerade, f.MasqueradeURL, f.RewriteHost = "proxy", "https://www.example.com", true
	ch, cand, err := Build([]byte(current), string(m), &f)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := hyconfig.ParseServer(cand)
	if c.TLS != nil || c.ACME == nil || c.ACME.Domains[0] != "vpn.example.com" || c.Auth.Password != "fake-new-auth-password" || c.Obfs.Type != "" ||
		c.Masquerade.Proxy.URL != "https://www.example.com" || c.Outbounds[0].SOCKS5.Password != "fake-warp-pass" || c.TrafficStats.Secret != "fake-stats-secret" {
		t.Fatalf("candidate:\n%s", cand)
	}
	if !slices.Contains(ch.Secrets, "auth.password") || !slices.Contains(ch.Secrets, "obfs.salamander.password") {
		t.Fatalf("changed secrets %q", ch.Secrets)
	}
	// The new password is shown (the admin typed it); the kept ones are not.
	if !strings.Contains(ch.YAML, "fake-new-auth-password") || strings.Contains(ch.YAML, "fake-warp-pass") {
		t.Fatalf("%s", ch.YAML)
	}
	// And the next round keeps it.
	ch2, cand2, err := Build([]byte(current), ch.YAML, nil)
	if err != nil || !strings.Contains(string(cand2), "fake-new-auth-password") || !ch2.OK {
		t.Fatalf("%v\n%s", err, cand2)
	}

	// An empty password is generated.
	f = FieldsOf(mc)
	f.AuthPassword = ""
	_, cand, _ = Build([]byte(current), string(m), &f)
	c, _ = hyconfig.ParseServer(cand)
	if len(c.Auth.Password) != 32 || c.Auth.Password == "fake-current-auth" {
		t.Fatalf("generated %q", c.Auth.Password)
	}
}

func diffText(d []Line) string {
	var b strings.Builder
	for _, l := range d {
		b.WriteString(l.Op + l.Text + "\n")
	}
	return b.String()
}

func TestDiff(t *testing.T) {
	d := Diff("a\nb\nc\n", "a\nx\nc\nd\n")
	if diffText(d) != " a\n-b\n+x\n c\n+d\n" {
		t.Fatalf("%q", diffText(d))
	}
	if Changed(Diff("a\n", "a")) || !Changed(Diff("", "a")) {
		t.Fatal("Changed")
	}
}

// A config with a big inline ACL: a local edit is exact, a change too
// large for the table comes as removed and added lines.
func TestDiffLarge(t *testing.T) {
	var a, b strings.Builder
	for i := range 100000 {
		fmt.Fprintf(&a, "    - direct(10.%d.%d.0/24)\n", i>>8&255, i&255)
		if i == 50000 {
			b.WriteString("    - reject(all)\n")
		}
		fmt.Fprintf(&b, "    - direct(10.%d.%d.0/24)\n", i>>8&255, i&255)
	}
	d := Diff(a.String(), b.String())
	if len(d) != 100001 || d[50000] != (Line{"+", "    - reject(all)"}) {
		t.Fatalf("local edit: %d lines, %v", len(d), d[50000])
	}
	var c strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&c, "    - proxy(10.%d.%d.0/24)\n", i>>8&255, i&255)
	}
	x := "acl:\n  inline:\n" + strings.Join(strings.SplitAfter(a.String(), "\n")[:5000], "") + "outbounds: []\n"
	y := "acl:\n  inline:\n" + c.String() + "outbounds: []\n"
	d = Diff(x, y)
	if len(d) != 10003 || d[1].Op != " " || d[2].Op != "-" || d[5002].Op != "+" || d[10002] != (Line{" ", "outbounds: []"}) {
		t.Fatalf("large change: %d lines, %v %v %v", len(d), d[2], d[5002], d[10002])
	}
}

// Secrets that do not sit under a secret-named key: an anchored value
// used as a password through an alias, a userpass map behind an alias, a
// password inside a URL of an unknown field, a share link in a comment.
const tricky = `shared: &pw fake-anchored-pass
users: &u
  alice: fake-alice-pass
auth:
  type: password
  password: *pw
extra:
  upstream: https://bob:fake-url-pass@proxy.example.com/
  proxy: http://:fake-nouser-pass@203.0.113.5:3128
  second:
    type: userpass
    userpass: *u
masquerade:
  type: proxy
  proxy:
    url: https://example.com/ # old: hysteria2://fake-comment-pass@203.0.113.1:443
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
`

func TestMaskFollowsAliasesURLsAndComments(t *testing.T) {
	m, paths, err := Mask([]byte(tricky))
	if err != nil {
		t.Fatal(err)
	}
	s := string(m)
	for _, secret := range []string{"fake-anchored-pass", "fake-alice-pass", "fake-url-pass", "fake-nouser-pass", "fake-comment-pass"} {
		if strings.Contains(s, secret) {
			t.Fatalf("%s visible:\n%s", secret, s)
		}
	}
	for _, p := range []string{"shared", "users.alice", "extra.upstream", "extra.proxy"} {
		if !slices.Contains(paths, p) {
			t.Errorf("%s not listed: %q", p, paths)
		}
	}
	// Kept as they were when the editor does not touch them, comments
	// included.
	back, err := Unmask(m, []byte(tricky))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fake-anchored-pass", "fake-alice-pass", "fake-url-pass", "fake-comment-pass", "*pw", "*u"} {
		if !strings.Contains(string(back), secret) {
			t.Fatalf("%s lost:\n%s", secret, back)
		}
	}
	if cs := ChangedSecrets([]byte(tricky), back); len(cs) != 0 {
		t.Fatalf("changed %q", cs)
	}
	// Through the typed model (the form), where aliases are resolved.
	mc, err := hyconfig.ParseServer(m)
	if err != nil {
		t.Fatal(err)
	}
	f := FieldsOf(mc)
	f.Listen = ":8443"
	ch, cand, err := Build([]byte(tricky), s, &f)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := hyconfig.ParseServer(cand)
	if c.Auth.Password != "fake-anchored-pass" || c.Listen != ":8443" {
		t.Fatalf("candidate %+v", c.Auth)
	}
	if strings.Contains(ch.YAML, "fake-") || strings.Contains(fmt.Sprint(ch.Diff), "fake-") {
		t.Fatalf("secret in the check:\n%s\n%v", ch.YAML, ch.Diff)
	}
}

// The stats API: the field turns it on on loopback with a generated
// secret the editor never shows; the panel refuses an API reachable from
// the network or without a secret.
func TestTrafficStats(t *testing.T) {
	const bare = "listen: :443\ntls:\n  cert: /etc/hysteria/server.crt\n  key: /etc/hysteria/server.key\nauth:\n  type: password\n  password: fake-current-auth\n"
	m, _, _ := Mask([]byte(bare))
	f := FieldsOf(mustParse(t, m))
	if f.TrafficStats {
		t.Fatal("stats on in a config without them")
	}
	f.TrafficStats = true
	ch, cand, err := Build([]byte(bare), string(m), &f)
	if err != nil || !ch.OK {
		t.Fatalf("%v %+v", err, ch.Problems)
	}
	c := mustParse(t, cand)
	if c.TrafficStats.Listen != StatsListen || len(c.TrafficStats.Secret) < 32 {
		t.Fatalf("%+v", c.TrafficStats)
	}
	if strings.Contains(ch.YAML, c.TrafficStats.Secret) || !ch.Fields.TrafficStats || !slices.Contains(ch.Secrets, "trafficstats.secret") {
		t.Fatalf("secret shown or not listed: %q\n%s", ch.Secrets, ch.YAML)
	}
	// The text the editor sends back hides the new secret: apply
	// generates it.
	ch3, cand3, err := Build([]byte(bare), ch.YAML, nil)
	if err != nil || !ch3.OK || len(mustParse(t, cand3).TrafficStats.Secret) < 32 || mustParse(t, cand3).TrafficStats.Secret == Hidden {
		t.Fatalf("%v %+v\n%s", err, ch3.Problems, cand3)
	}
	// Saved, edited again: the secret stays.
	ch2, cand2, err := Build(cand, ch.YAML, &ch.Fields)
	if err != nil || mustParse(t, cand2).TrafficStats.Secret != c.TrafficStats.Secret || len(ch2.Secrets) != 0 {
		t.Fatalf("%v %q", err, ch2.Secrets)
	}

	// An API on every interface: the field moves it to loopback, same port.
	exposed := bare + "trafficStats:\n  listen: :9999\n  secret: fake-stats-secret\n"
	m, _, _ = Mask([]byte(exposed))
	ch, _, err = Build([]byte(exposed), string(m), nil)
	if err != nil || ch.OK || !hasProblem(ch.Problems, "trafficStats.listen") {
		t.Fatalf("exposed API accepted: %v %+v", err, ch.Problems)
	}
	f = FieldsOf(mustParse(t, m))
	if !f.TrafficStats {
		t.Fatal("stats off")
	}
	ch, cand, err = Build([]byte(exposed), string(m), &f)
	if err != nil || !ch.OK || mustParse(t, cand).TrafficStats.Listen != "127.0.0.1:9999" || mustParse(t, cand).TrafficStats.Secret != "fake-stats-secret" {
		t.Fatalf("%v %+v\n%s", err, ch.Problems, cand)
	}

	// Without a secret: an error, not Hysteria's warning as well.
	open := bare + "trafficStats:\n  listen: 127.0.0.1:9999\n"
	ch, _, err = Build([]byte(open), open, nil)
	if err != nil || ch.OK || len(ch.Problems) != 1 || ch.Problems[0].Field != "trafficStats.secret" || ch.Problems[0].Warning {
		t.Fatalf("%v %+v", err, ch.Problems)
	}
	for _, listen := range []string{"192.0.2.1:9999", "0.0.0.0:9999", "[::]:9999", "example.com:9999"} {
		y := bare + "trafficStats:\n  listen: " + listen + "\n  secret: fake-stats-secret\n"
		y = strings.Replace(y, "listen: [::]:9999", `listen: "[::]:9999"`, 1)
		if ch, _, err := Build([]byte(y), y, nil); err != nil || ch.OK {
			t.Errorf("%s accepted", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:9999", "[::1]:9999", "localhost:9999"} {
		y := bare + "trafficStats:\n  listen: " + listen + "\n  secret: fake-stats-secret\n"
		y = strings.Replace(y, "listen: [::1]:9999", `listen: "[::1]:9999"`, 1)
		if ch, _, _ := Build([]byte(y), y, nil); !ch.OK {
			t.Errorf("%s refused: %+v", listen, ch.Problems)
		}
	}

	// Off: the section goes.
	f.TrafficStats = false
	_, cand, _ = Build([]byte(exposed), string(m), &f)
	if strings.Contains(string(cand), "trafficStats") || strings.Contains(string(cand), "fake-stats-secret") {
		t.Fatalf("stats left:\n%s", cand)
	}
}

func mustParse(t *testing.T, b []byte) *hyconfig.Server {
	t.Helper()
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasProblem(ps []hyconfig.Problem, field string) bool {
	return slices.ContainsFunc(ps, func(p hyconfig.Problem) bool { return p.Field == field && !p.Warning })
}
