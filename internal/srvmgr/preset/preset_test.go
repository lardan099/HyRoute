package preset

import (
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
)

// A config with a secret or an address in every place one can be.
const full = `listen: 192.0.2.10:443,20000-50000
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
acme:
  domains: [vpn.example.com]
  email: admin@example.com
  type: dns
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: fake-preset-dns-token
auth:
  type: userpass
  userpass:
    alice: fake-preset-alice-pass
obfs:
  type: salamander
  salamander:
    password: fake-preset-obfs-pass
masquerade:
  type: proxy
  proxy:
    url: https://user:fake-preset-masq-pass@www.example.com
    rewriteHost: true
  listenHTTP: 192.0.2.10:80
  listenHTTPS: 192.0.2.10:443
bandwidth:
  up: 500 mbps
  down: 200 mbps
quic:
  maxIdleTimeout: 60s
udpIdleTimeout: 120s
resolver:
  type: https
  https:
    addr: 1.1.1.1:443
sniff:
  enable: true
acl:
  inline:
    - warp(geosite:openai)
    - direct(all)
outbounds:
  - name: direct
    type: direct
    direct:
      mode: "46"
      bindIPv4: 192.0.2.10
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      username: warp
      password: fake-preset-socks-pass
  - name: far
    type: http
    http:
      url: http://user:fake-preset-http-pass@198.51.100.7:8080
trafficStats:
  listen: 127.0.0.1:9999
  secret: fake-preset-stats-secret
futureField: fake-preset-unknown-value
`

// A preset has no secret and no address of a server, whatever the
// config holds; notes say what was left out.
func TestExtractNoSecretsOrHosts(t *testing.T) {
	c, err := hyconfig.ParseServer([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	p, notes := Extract(c)
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	y := string(b)
	for _, bad := range []string{"fake-preset", "192.0.2.10", "198.51.100.7", "vpn.example.com", "admin@example.com", "cloudflare", "server.key", "userpass", "alice", "trafficStats", "9999", "futureField"} {
		if strings.Contains(y, bad) {
			t.Errorf("preset has %q:\n%s", bad, y)
		}
	}
	for _, keep := range []string{"listen: :443,20000-50000", "type: salamander", "www.example.com", "listenHTTPS: :443", "up: 500 mbps", "maxIdleTimeout: 60s", "udpIdleTimeout: 120s", "1.1.1.1:443", "warp(geosite:openai)", "127.0.0.1:40000", `mode: "46"`} {
		if !strings.Contains(y, keep) {
			t.Errorf("preset lost %q:\n%s", keep, y)
		}
	}
	if got := Has(p); !slices.Equal(got, []string{Ports, Obfs, Masquerade, Speed, QUIC, UDP, Resolver, Sniff, ACL, Outbounds}) {
		t.Errorf("sections %v", got)
	}
	n := strings.Join(notes, "\n")
	for _, want := range []string{"far", "warp", "привязка", "сайта-маскировки", "не знает"} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
	// What is left is a valid partial config.
	back, err := hyconfig.ParseServer(b)
	if err != nil || len(hyconfig.UnknownFields(back)) != 0 {
		t.Fatalf("%v %v", err, hyconfig.UnknownFields(back))
	}
}

const target = `listen: 0.0.0.0:8443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: fake-target-pass
bandwidth:
  up: 100 mbps
sniff:
  enable: true
  timeout: 5s
`

func overlay(t *testing.T, sections ...string) (*hyconfig.Server, *hyconfig.Server, bool) {
	t.Helper()
	src, _ := hyconfig.ParseServer([]byte(full))
	p, _ := Extract(src)
	c, _ := hyconfig.ParseServer([]byte(target))
	newObfs, err := Overlay(c, p, sections, func() string { return "fake-new-obfs-pass" })
	if err != nil {
		t.Fatal(err)
	}
	before, _ := hyconfig.ParseServer([]byte(target))
	return before, c, newObfs
}

// A section changes only itself: the rest of the config, secrets and
// addresses included, stays.
func TestOverlayOnlySection(t *testing.T) {
	before, c, _ := overlay(t, Speed)
	if c.Bandwidth.Up != "500 mbps" || c.Bandwidth.Down != "200 mbps" {
		t.Fatalf("%+v", c.Bandwidth)
	}
	c.Bandwidth = before.Bandwidth
	a, _ := c.Marshal()
	b, _ := before.Marshal()
	if string(a) != string(b) {
		t.Fatalf("other sections changed:\n%s\n---\n%s", a, b)
	}

	// Ports keep the target's address; QUIC and ACL together.
	_, c, _ = overlay(t, Ports, QUIC, ACL)
	if c.Listen != "0.0.0.0:443,20000-50000" || c.QUIC.MaxIdleTimeout != "60s" || len(c.ACL.Inline) != 2 || c.Sniff.Timeout != "5s" || c.Auth.Password != "fake-target-pass" {
		t.Fatalf("%+v", c)
	}
}

// Obfuscation gets a password: the target's when it has the same type,
// else a new one.
func TestOverlayObfs(t *testing.T) {
	_, c, newObfs := overlay(t, Obfs)
	if c.Obfs.Type != "salamander" || c.Obfs.Salamander.Password != "fake-new-obfs-pass" || !newObfs {
		t.Fatalf("%+v %v", c.Obfs, newObfs)
	}
	src, _ := hyconfig.ParseServer([]byte(full))
	p, _ := Extract(src)
	c, _ = hyconfig.ParseServer([]byte(target + "obfs:\n  type: salamander\n  salamander:\n    password: fake-kept-obfs\n"))
	if n, _ := Overlay(c, p, []string{Obfs}, func() string { return "x" }); n || c.Obfs.Salamander.Password != "fake-kept-obfs" {
		t.Fatalf("%+v %v", c.Obfs, n)
	}
	// A stale block of the other type does not go into the password.
	for _, typ := range []string{"gecko", "salamander"} {
		c, _ = hyconfig.ParseServer([]byte(target + "obfs:\n  type: " + typ + "\n  gecko:\n    password: fake-gecko-obfs\n  salamander:\n    password: fake-salamander-obfs\n"))
		p := &hyconfig.Server{Obfs: hyconfig.Obfs{Type: typ}}
		n, err := Overlay(c, p, []string{Obfs}, func() string { return "x" })
		pw := c.Obfs.Salamander.Password
		if typ == "gecko" {
			pw = c.Obfs.Gecko.Password
		}
		if err != nil || n || pw != "fake-"+typ+"-obfs" {
			t.Fatalf("%s: %v %+v %v", typ, err, c.Obfs, n)
		}
	}
}

func TestOverlayRefused(t *testing.T) {
	p := &hyconfig.Server{Bandwidth: hyconfig.Bandwidth{Up: "10 mbps"}}
	c, _ := hyconfig.ParseServer([]byte(target))
	for _, s := range []string{ACL, "tls", ""} {
		if _, err := Overlay(c, p, []string{Speed, s}, nil); err == nil {
			t.Errorf("%q applied", s)
		}
	}
	if c.Bandwidth.Up != "100 mbps" {
		t.Fatal("a refused overlay changed the config")
	}
}
