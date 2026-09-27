package hysteria

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestParseURIOfficial(t *testing.T) {
	p, warn, err := ParseURI("hysteria2://letmein@example.com:443,20000-50000/?obfs=salamander&obfs-password=gawrgura&sni=real.example.com&insecure=1&pinSHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad#My%20Server")
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 0 {
		t.Fatalf("unexpected warnings %v", warn)
	}
	want := Profile{
		Name: "My Server", Host: "example.com", Ports: "443,20000-50000", Auth: "letmein",
		TLS:         TLS{SNI: "real.example.com", Insecure: true, PinSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		Obfs:        Obfs{Type: "salamander", Password: "gawrgura"},
		PinServerIP: true,
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v\nwant %+v", p, want)
	}
}

// Same shape as links issued by some panels: obfs-password without obfs,
// allowInsecure, security=tls, emoji name, port range only.
func TestParseURIPanelVariant(t *testing.T) {
	p, warn, err := ParseURI("hysteria2://AuthSecret123@203.0.113.7:20000-50000?obfs-password=ObfsSecret456&security=tls&sni=example.org&allowInsecure=true#%F0%9F%87%A9%F0%9F%87%AA%20DE%20up%20to%2010%20Gb/s")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "203.0.113.7" || p.Ports != "20000-50000" || p.Auth != "AuthSecret123" {
		t.Fatalf("server/auth: %+v", p)
	}
	if p.Obfs != (Obfs{Type: "salamander", Password: "ObfsSecret456"}) {
		t.Fatalf("obfs: %+v", p.Obfs)
	}
	if !p.TLS.Insecure || p.TLS.SNI != "example.org" {
		t.Fatalf("tls: %+v", p.TLS)
	}
	if p.Name != "🇩🇪 DE up to 10 Gb/s" {
		t.Fatalf("name %q", p.Name)
	}
	joined := strings.Join(warn, "; ")
	// Aliases (allowInsecure) and cosmetic parameters (security) are not
	// worth a warning; the salamander guess is.
	if len(warn) != 1 || !strings.Contains(joined, "assuming obfs=salamander") {
		t.Fatalf("warnings %q", joined)
	}
}

func TestParseURIVariants(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		ports string
		auth  string
		sni   string
	}{
		{"hy2://pass@example.com", "example.com", "443", "pass", ""},
		{"HY2://pass@example.com:8443/", "example.com", "8443", "pass", ""},
		{"hysteria2://user:p%40ss%3Aw@[2001:db8::1]:443/?sni=a.b", "2001:db8::1", "443", "user:p@ss:w", "a.b"},
		{"hysteria2://p%2Fa%23b@host:1000-2000,3000", "host", "1000-2000,3000", "p/a#b", ""},
		{"hysteria2://x@host:443?mport=20000-30000&peer=peer.example", "host", "443,20000-30000", "x", "peer.example"},
		{"hysteria2://x@[::1]", "::1", "443", "x", ""},
	}
	for _, c := range cases {
		p, _, err := ParseURI(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if p.Host != c.host || p.Ports != c.ports || p.Auth != c.auth || p.TLS.SNI != c.sni {
			t.Fatalf("%s: got host=%q ports=%q auth=%q sni=%q", c.in, p.Host, p.Ports, p.Auth, p.TLS.SNI)
		}
	}
}

func TestParseURIErrors(t *testing.T) {
	for _, in := range []string{
		"vless://x@host:443",
		"not a uri",
		"hysteria2://x@host:0",
		"hysteria2://x@host:70000",
		"hysteria2://x@host:500-100",
		"hysteria2://x@host:abc",
		"hysteria2://x@:443",
		"hysteria2://x@[::1:443",
		"hysteria2://x@host:443?obfs=unknown",
		"hysteria2://x@host:443?obfs=salamander",
		"hysteria2://x@host:443?insecure=maybe",
		"hysteria2://x%zz@host:443",
	} {
		if _, _, err := ParseURI(in); err == nil {
			t.Fatalf("%s: expected error", in)
		}
	}
}

func TestURIRoundTrip(t *testing.T) {
	in := Profile{
		Name: "Тест #1 / DE", Host: "2001:db8::5", Ports: "443,20000-50000", Auth: "user:p@ss w/rd",
		TLS:         TLS{SNI: "example.com", Insecure: true, PinSHA256: "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"},
		Obfs:        Obfs{Type: "gecko", Password: "o&b=f s"},
		PinServerIP: true,
	}
	u := in.URI()
	if !strings.HasPrefix(u, "hysteria2://user:p%40ss%20w%2Frd@[2001:db8::5]:443,20000-50000/?") {
		t.Fatalf("uri %s", u)
	}
	out, warn, err := ParseURI(u)
	if err != nil || len(warn) != 0 {
		t.Fatalf("%v %v", err, warn)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip\n in %+v\nout %+v", in, out)
	}
	// Bandwidth and friends are not part of the share link.
	in.Bandwidth = Bandwidth{Up: "10 mbps"}
	if in.URI() != u {
		t.Fatal("bandwidth leaked into URI")
	}
}

func TestParsePorts(t *testing.T) {
	r, err := ParsePorts("443, 20000-50000")
	if err != nil || !reflect.DeepEqual(r, []PortRange{{443, 443}, {20000, 50000}}) {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{"", "0", "1-", "-5", "5-1", "443,,444"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

// Links from Xray-based panels: pcs is the certificate pin, fm carries the
// salamander obfs, names have spaces and emoji.
func TestParseURIXrayStyle(t *testing.T) {
	pin := "85654a6b27d31ffa57509173d9771ba016971948a1a95ffa267fe0f64e71b352"
	fm := url.QueryEscape(`{"udp":[{"settings":{"password":"obfsSecret1"},"type":"salamander"}]}`)
	p, warn, err := ParseURI("hy2://authSecret@198.51.100.20:443/?sni=example.org&pcs=" + pin + "&fm=" + fm + "&mport=20000-50000&fp=chrome#🇳🇱 Нидерланды напрямую")
	if err != nil || len(warn) != 0 {
		t.Fatalf("%v %v", err, warn)
	}
	if p.TLS.PinSHA256 != pin || p.Obfs.Type != "salamander" || p.Obfs.Password != "obfsSecret1" || p.Ports != "443,20000-50000" || p.Name != "🇳🇱 Нидерланды напрямую" {
		t.Fatalf("%+v", p)
	}
	p2, _, err := ParseURI(p.URI())
	if err != nil || p2.Name != p.Name || p2.Obfs != p.Obfs || p2.TLS.PinSHA256 != pin {
		t.Fatalf("round trip: %+v %v", p2, err)
	}
	if _, warn, _ := ParseURI("hy2://a@h:443/?fm=" + url.QueryEscape(`{"udp":[{"type":"noise"}]}`)); len(warn) != 1 {
		t.Fatalf("unsupported mask must warn: %v", warn)
	}
}
