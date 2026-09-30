package apply

import (
	"errors"
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
