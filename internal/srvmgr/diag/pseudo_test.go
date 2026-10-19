package diag

import (
	"encoding/json"
	"strings"
	"testing"
)

// All names, addresses and secrets below are made up for these tests
// (documentation ranges and example.com).

func TestPseudonymsReplaceTheSameEverywhere(t *testing.T) {
	p := newPseudonyms()
	if got := p.name(kindServer, "Germany Main"); got != "server-1" {
		t.Fatalf("server %q", got)
	}
	if got := p.name(kindHost, "203.0.113.10"); got != "host-1" {
		t.Fatalf("host %q", got)
	}
	if got := p.name(kindUser, "canary-alice"); got != "user-1" {
		t.Fatalf("user %q", got)
	}
	if got := p.name(kindHost, "VPN.Example.com."); got != "host-2" {
		t.Fatalf("host %q", got)
	}
	// The same value as another kind keeps its pseudonym.
	if got := p.name(kindDomain, "vpn.example.com"); got != "host-2" {
		t.Fatalf("domain %q", got)
	}
	if got := p.name(kindUser, "root"); got != "root" {
		t.Fatalf("root became %q", got)
	}
	if got := p.name(kindHost, "192.168.1.10"); got != "192.168.1.10" {
		t.Fatalf("a private address became %q", got)
	}
	cases := []struct{ in, want string }{
		{"monitor: server reachable again server=\"Germany Main\"", "monitor: server reachable again server=\"server-1\""},
		{"сервер germany main: Подключено как canary-alice к 203.0.113.10:22", "сервер server-1: Подключено как user-1 к host-1:22"},
		{"dial vpn.example.com:443: timeout; VPN.EXAMPLE.COM.", "dial host-2:443: timeout; host-2."},
		// Whole words only: a longer address or name is another value.
		{"203.0.113.100 and canary-alice2", "host-3 and canary-alice2"},
		{"route to [2001:db8::5]:443 and 2001:db8::5.", "route to [host-4]:443 and host-4."},
		{"egress 198.51.100.7, loopback 127.0.0.1, lan 10.0.0.5, dns 1.1.1.1", "egress host-5, loopback 127.0.0.1, lan 10.0.0.5, dns 1.1.1.1"},
		{"cert for other.example.org and пример.рф, see github.com/apernet/hysteria", "cert for domain-1 and domain-2, see github.com/apernet/hysteria"},
		{"acme: admin@example.net registered", "acme: email-1 registered"},
		{"wrote /etc/hysteria/config.yaml, restarted hysteria-server.service and hysteria-server@config.service", "wrote /etc/hysteria/config.yaml, restarted hysteria-server.service and hysteria-server@config.service"},
		{"Ubuntu 22.04.3 LTS, 6.1.0-18-amd64 x86_64, v2.6.0, 12:30:45", "Ubuntu 22.04.3 LTS, 6.1.0-18-amd64 x86_64, v2.6.0, 12:30:45"},
		{"2026-10-08T12:00:00Z unspecified :: and fe80::1", "2026-10-08T12:00:00Z unspecified :: and fe80::1"},
		// A dynamic DNS name is a domain; a name under no public suffix is
		// not one (a file, a LAN name).
		{"ddns myvpn.duckdns.org, lan nas.lan", "ddns domain-3, lan nas.lan"},
	}
	for _, c := range cases {
		if got := p.String(c.in); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	// Found once, the same pseudonym later and in other kinds of text.
	if got := p.String("xn--e1afmkfd.xn--p1ai OTHER.example.org"); got != "domain-2 domain-1" {
		t.Fatalf("%q", got)
	}
	// A server called by a common word gets a pseudonym as a field, and
	// the texts keep the word.
	if got := p.name(kindServer, "Ubuntu"); got != "server-2" {
		t.Fatalf("%q", got)
	}
	if got := p.String("Ubuntu 22.04.3 LTS"); got != "Ubuntu 22.04.3 LTS" {
		t.Fatalf("%q", got)
	}
}

func TestPseudonymsMaskKeyMaterial(t *testing.T) {
	p := newPseudonyms()
	p.secret("fake-Pa55word-xyz", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----")
	secrets := []string{
		"fake-Pa55word-xyz",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
		"MIIBszCCAVmgAwIBAgIUfakecertificatebody",
		"AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyMaterialForTests",
		"Xk3fakeFingerprintBase64ForTests0123456789A",
		"6fe0c2d13a9d0f3a1e4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9011",
		"QmFzZTY0TG9va2luZ1Rva2VuRm9yVGVzdHMxMjM0NTY",
	}
	in := strings.Join([]string{
		"password typed: fake-Pa55word-xyz",
		"line b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ of the key",
		"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUfakecertificatebody\n-----END CERTIFICATE-----",
		"host key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyMaterialForTests",
		"fingerprint SHA256:Xk3fakeFingerprintBase64ForTests0123456789A",
		"pinSHA256: 6fe0c2d13a9d0f3a1e4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9011",
		"token QmFzZTY0TG9va2luZ1Rva2VuRm9yVGVzdHMxMjM0NTY in a url",
		"link hysteria2://fake-Pa55word-xyz@vpn.example.com:443/?sni=vpn.example.com#me",
	}, "\n")
	got := p.String(in)
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Fatalf("%q left in:\n%s", s, got)
		}
	}
	for _, keep := range []string{"-----BEGIN CERTIFICATE-----", "ssh-ed25519 [REDACTED]", "SHA256:[REDACTED]", "pinSHA256: [REDACTED]", "hysteria2://[REDACTED]"} {
		if !strings.Contains(got, keep) {
			t.Errorf("want %q in:\n%s", keep, got)
		}
	}
}

func TestPseudonymsJSON(t *testing.T) {
	p := newPseudonyms()
	p.name(kindUser, "canary-bob")
	v := p.raw([]byte(`{"users":["canary-bob"],"canary-bob":{"tx":1},"auth":"userpass","password":"fake-secret-123","domain":"vpn.example.com","pinSHA256":"aa:bb","port":443,"dns":{"apiToken":12345}}`))
	b, _ := json.Marshal(v)
	got := string(b)
	for _, s := range []string{"canary-bob", "fake-secret-123", "vpn.example.com", "aa:bb", "12345"} {
		if strings.Contains(got, s) {
			t.Fatalf("%q left in %s", s, got)
		}
	}
	for _, keep := range []string{`"users":["user-1"]`, `"user-1":{"tx":1}`, `"auth":"userpass"`, `"port":443`, `"domain":"domain-1"`} {
		if !strings.Contains(got, keep) {
			t.Errorf("want %s in %s", keep, got)
		}
	}
	if got := p.raw([]byte("not json, admin@example.net")); got != "not json, email-1" {
		t.Fatalf("%v", got)
	}
}
