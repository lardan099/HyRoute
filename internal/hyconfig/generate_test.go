package hyconfig

import (
	"reflect"
	"strings"
	"testing"
)

const fakePin = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func TestClientForSelfSigned(t *testing.T) {
	s := parseServer(t, []byte(minimal+"obfs:\n  type: salamander\n  salamander:\n    password: fake-obfs-password\n"))
	c, err := ClientFor(s, ClientOptions{Host: "192.0.2.1", PinSHA256: fakePin, SNI: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "192.0.2.1:443" || c.Auth != "fake-auth-password" {
		t.Fatalf("%+v", c)
	}
	// A pinned self-signed certificate: skip the chain, check the pin.
	if !c.TLS.Insecure || c.TLS.PinSHA256 != fakePin || c.TLS.SNI != "www.example.com" {
		t.Fatalf("tls %+v", c.TLS)
	}
	if c.Obfs.Type != "salamander" || c.Obfs.Salamander.Password != "fake-obfs-password" {
		t.Fatalf("obfs %+v", c.Obfs)
	}
	if c.SOCKS5.Listen != "127.0.0.1:1080" || c.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatalf("modes %+v %+v", c.SOCKS5, c.HTTP)
	}
	out := marshal(t, c)
	back, err := ParseClient([]byte(out))
	if err != nil || back.Server != c.Server || !reflect.DeepEqual(back.TLS, c.TLS) {
		t.Fatalf("%v\n%s", err, out)
	}
	if ps := back.Validate(); len(ps) != 0 {
		t.Fatalf("generated config: %v", ps)
	}
}

func TestClientForACME(t *testing.T) {
	s := parseServer(t, []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-auth-password\n"))
	c, err := ClientFor(s, ClientOptions{Host: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.TLS, ClientTLS{}) {
		t.Fatalf("domain host needs no TLS options: %+v", c.TLS)
	}
	// Connecting by IP keeps the certificate check on the domain.
	c, err = ClientFor(s, ClientOptions{Host: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "[2001:db8::1]:443" || c.TLS.SNI != "vpn.example.com" || c.TLS.Insecure {
		t.Fatalf("%+v", c)
	}
}

func TestClientForPortHopping(t *testing.T) {
	s := parseServer(t, []byte(strings.Replace(minimal, "listen: :443", "listen: :20000-50000", 1)))
	c, err := ClientFor(s, ClientOptions{Host: "vpn.example.com", HopInterval: "30s", Bandwidth: Bandwidth{Up: "20 mbps", Down: "100 mbps"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "vpn.example.com:20000-50000" || c.Transport.UDP.HopInterval != "30s" || c.Bandwidth.Down != "100 mbps" {
		t.Fatalf("%+v", c)
	}
	// No hop interval on a single port.
	s = parseServer(t, []byte(minimal))
	if c, _ = ClientFor(s, ClientOptions{Host: "vpn.example.com", HopInterval: "30s"}); c.Transport.UDP.HopInterval != "" {
		t.Fatalf("hop on one port: %+v", c.Transport)
	}
	// Public ports differ from listen (NAT).
	if c, _ = ClientFor(s, ClientOptions{Host: "vpn.example.com", Ports: "8443"}); c.Server != "vpn.example.com:8443" {
		t.Fatalf("%s", c.Server)
	}
}

func TestClientForAuth(t *testing.T) {
	up := parseServer(t, []byte("tls: {cert: a.crt, key: a.key}\nauth:\n  type: userpass\n  userpass:\n    anna: fake-pass-1\n    boris: fake-pass-2\n"))
	if _, err := ClientFor(up, ClientOptions{Host: "vpn.example.com"}); err == nil {
		t.Fatal("two users and none picked")
	}
	c, err := ClientFor(up, ClientOptions{Host: "vpn.example.com", User: "Boris"})
	if err != nil || c.Auth != "boris:fake-pass-2" {
		t.Fatalf("%v %+v", err, c)
	}
	if _, err := ClientFor(up, ClientOptions{Host: "vpn.example.com", User: "vera"}); err == nil {
		t.Fatal("unknown user")
	}
	one := parseServer(t, []byte("tls: {cert: a.crt, key: a.key}\nauth:\n  type: userpass\n  userpass:\n    anna: fake-pass-1\n"))
	if c, _ := ClientFor(one, ClientOptions{Host: "vpn.example.com"}); c == nil || c.Auth != "anna:fake-pass-1" {
		t.Fatalf("single user: %+v", c)
	}
	ext := parseServer(t, []byte("tls: {cert: a.crt, key: a.key}\nauth:\n  type: http\n  http:\n    url: https://auth.example.com\n"))
	if _, err := ClientFor(ext, ClientOptions{Host: "vpn.example.com"}); err == nil {
		t.Fatal("http auth without a password")
	}
	if c, _ := ClientFor(ext, ClientOptions{Host: "vpn.example.com", Auth: "fake-token"}); c == nil || c.Auth != "fake-token" {
		t.Fatalf("explicit auth: %+v", c)
	}
}

func TestClientForRejects(t *testing.T) {
	s := parseServer(t, []byte(minimal))
	for _, o := range []ClientOptions{
		{},
		{Host: "vpn example"},
		{Host: "user@vpn.example.com"},
		{Host: "vpn.example.com", PinSHA256: "not-a-pin"},
		{Host: "vpn.example.com", Ports: "http"},
		{Host: "vpn.example.com", Bandwidth: Bandwidth{Up: "fast"}},
	} {
		if _, err := ClientFor(s, o); err == nil {
			t.Errorf("%+v: no error", o)
		}
	}
	realm := parseServer(t, []byte(strings.Replace(minimal, "listen: :443", "listen: realm://token@realm.example.com/fake", 1)))
	if _, err := ClientFor(realm, ClientOptions{Host: "vpn.example.com"}); err == nil {
		t.Error("realm server")
	}
}

func TestClientForMimicAndGecko(t *testing.T) {
	s := parseServer(t, []byte(minimal+"mimic:\n  enabled: true\n  interface: eth0\nobfs:\n  type: gecko\n  gecko:\n    password: fake-obfs-password\n    minPacketSize: 600\n"))
	c, err := ClientFor(s, ClientOptions{Host: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// Mimic must match; the server's interface and packet sizes are its own.
	if !c.Mimic.Enabled || c.Mimic.Interface != "" || !reflect.DeepEqual(c.Obfs.Gecko, Gecko{Password: "fake-obfs-password"}) {
		t.Fatalf("%+v %+v", c.Mimic, c.Obfs)
	}
}

func TestClientValidate(t *testing.T) {
	c := &Client{Server: "vpn.example.com:443", Auth: "fake-auth-password", SOCKS5: &SOCKS5{Listen: "127.0.0.1:1080"}}
	if ps := c.Validate(); len(ps) != 0 {
		t.Fatal(ps)
	}
	c.Transport.UDP = TransportUDP{HopInterval: "30s", MinHopInterval: "10s"}
	c.QUIC.KeepAlivePeriod = "1s"
	c.Server = "vpn.example.com"
	fields := map[string]bool{}
	for _, p := range c.Validate() {
		fields[p.Field] = !p.Warning
	}
	for _, f := range []string{"transport.udp", "quic.keepAlivePeriod", "server"} {
		if !fields[f] {
			t.Errorf("no error on %s: %v", f, c.Validate())
		}
	}

	// Hysteria refuses hop intervals under 5s (a bare number is
	// nanoseconds); 0 is its default.
	c = &Client{Server: "vpn.example.com:443,20000-30000", Auth: "fake-auth-password", SOCKS5: &SOCKS5{Listen: "127.0.0.1:1080"}}
	for _, u := range []TransportUDP{{HopInterval: "4s"}, {HopInterval: "30"}, {HopInterval: "-1m"}, {MinHopInterval: "1s", MaxHopInterval: "1m"}, {MinHopInterval: "10s", MaxHopInterval: "3s"}} {
		c.Transport.UDP = u
		if !HasErrors(c.Validate()) {
			t.Errorf("%+v: no error", u)
		}
	}
	for _, u := range []TransportUDP{{HopInterval: "5s"}, {HopInterval: "0s"}, {MinHopInterval: "5s", MaxHopInterval: "2h"}} {
		c.Transport.UDP = u
		if ps := c.Validate(); len(ps) != 0 {
			t.Errorf("%+v: %v", u, ps)
		}
	}
}
