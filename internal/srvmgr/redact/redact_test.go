package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// All secrets below are fake values made for these tests.
const (
	fakePass  = "fake-Pa55word-xyz"
	fakeObfs  = "fake-obfs-secret-123"
	fakeToken = "123456789:AAFakeTelegramTokenForTests_abcdefghij"
)

func mustNotContain(t *testing.T, got string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Fatalf("secret %q left in:\n%s", s, got)
		}
	}
}

func TestStringPatterns(t *testing.T) {
	cases := []struct {
		in      string
		secrets []string
		keep    []string
	}{
		{"password: " + fakePass, []string{fakePass}, []string{"password: " + Mask}},
		{`{"password":"` + fakePass + `","user":"root"}`, []string{fakePass}, []string{`"user":"root"`}},
		{"ssh_password=" + fakePass + " host=example.com", []string{fakePass}, []string{"host=example.com"}},
		{"obfs-password=" + fakeObfs + "&sni=example.com", []string{fakeObfs}, []string{"sni=example.com"}},
		{"auth: " + fakePass, []string{fakePass}, nil},
		{"secret: '" + fakePass + "'", []string{fakePass}, nil},
		{`csrfToken="` + fakePass + `"`, []string{fakePass}, nil},
		{"api_key=" + fakePass, []string{fakePass}, nil},
		{"passphrase: " + fakePass, []string{fakePass}, nil},
		{"Authorization: Bearer " + fakePass, []string{fakePass}, []string{"Authorization: " + Mask}},
		{"hysteria2://" + fakePass + "@203.0.113.1:443/?obfs=salamander&obfs-password=" + fakeObfs + "#name", []string{fakePass, fakeObfs, "203.0.113.1"}, []string{"hysteria2://" + Mask}},
		{"link hy2://user:" + fakePass + "@example.com:443 done", []string{fakePass}, []string{"hy2://" + Mask + " done"}},
		{"https://admin:" + fakePass + "@panel.example.com/api", []string{fakePass}, []string{"https://admin:" + Mask + "@panel.example.com/api"}},
		{"bot token " + fakeToken + " ok", []string{fakeToken}, []string{" ok"}},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nfakekeymaterial\n-----END OPENSSH PRIVATE KEY-----\nnext line", []string{"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "fakekeymaterial"}, []string{"next line"}},
		{"-----BEGIN EC PRIVATE KEY-----\ntruncated fakekeymaterial", []string{"fakekeymaterial"}, nil},
	}
	for _, c := range cases {
		got := String(c.in)
		mustNotContain(t, got, c.secrets...)
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%q: want %q in %q", c.in, k, got)
			}
		}
	}
}

// Ordinary text must survive: redaction that eats everything hides the
// logs people need.
func TestStringKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"type: password",
		"token_hash=abc sessions=3",
		"pinSHA256: deadbeef",
		"authorized_keys updated",
		"author: someone",
		"auth:",
		"connecting to example.com:22 as root",
		"https://github.com/apernet/hysteria/releases",
		"step 3/9: installing",
	} {
		if got := String(s); got != s {
			t.Errorf("%q became %q", s, got)
		}
	}
}

func TestRedactorValues(t *testing.T) {
	r := New()
	r.Add(fakePass, "abc", fakePass+"-longer")
	got := r.String("echo " + fakePass + "-longer and " + fakePass + " and abc")
	mustNotContain(t, got, fakePass)
	if !strings.Contains(got, "and abc") {
		t.Fatalf("short value redacted: %q", got)
	}
	if strings.Count(got, Mask) != 2 {
		t.Fatalf("%q", got)
	}
	var nilR *Redactor
	if nilR.String("password=x1") != "password="+Mask {
		t.Fatal("nil redactor must still apply patterns")
	}
}

func TestYAML(t *testing.T) {
	in := `# server config
listen: :443
auth:
  type: password
  password: ` + fakePass + `
obfs:
  type: salamander
  salamander:
    password: "` + fakeObfs + `"
trafficStats:
  listen: 127.0.0.1:9999
  secret: ` + fakePass + `2
acme:
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: ` + fakeToken + `
outbounds:
  - name: up
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user
      password: ` + fakePass + `3
masquerade:
  type: proxy
  proxy:
    url: https://user:` + fakePass + `4@example.com/
auth2:
  type: userpass
  userpass:
    alice: ` + fakePass + `5
    bob: ` + fakePass + `6
`
	out, err := New().YAML([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	mustNotContain(t, got, fakePass, fakeObfs, fakeToken)
	for _, keep := range []string{"# server config", "type: password", "type: salamander", "listen: 127.0.0.1:9999", "username: user", "alice: '" + Mask + "'", "name: cloudflare"} {
		if !strings.Contains(got, keep) {
			t.Errorf("want %q in:\n%s", keep, got)
		}
	}
	if _, err := New().YAML([]byte("a: [unclosed")); err == nil {
		t.Fatal("broken YAML: no error")
	}
	if s := New().YAMLString("password: " + fakePass + "\n  bad: [indent"); strings.Contains(s, fakePass) {
		t.Fatalf("fallback to text redaction: %q", s)
	}
}

func TestSlogHandler(t *testing.T) {
	var buf bytes.Buffer
	r := New()
	r.Add(fakeObfs)
	log := slog.New(r.Handler(slog.NewTextHandler(&buf, nil)))
	log.With("password", fakePass).Info("connect hysteria2://"+fakePass+"@h:443",
		"obfs", fakeObfs,
		"err", errors.New("auth failed: password="+fakePass),
		slog.Group("ssh", "user", "root", "secret", fakePass),
		"cfg", map[string]string{"k": fakeObfs},
		"n", 3)
	got := buf.String()
	mustNotContain(t, got, fakePass, fakeObfs)
	for _, keep := range []string{"user=root", "n=3", "hysteria2://" + Mask} {
		if !strings.Contains(got, keep) {
			t.Errorf("want %q in %s", keep, got)
		}
	}
}

func TestYAMLAliasedSecret(t *testing.T) {
	out, err := New().YAML([]byte("shared: &pw fake-anchored-pass\nauth:\n  password: *pw\n"))
	if err != nil || strings.Contains(string(out), "fake-anchored-pass") {
		t.Fatalf("%v\n%s", err, out)
	}
}
