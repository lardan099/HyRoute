package hy2uri

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

const pin = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func parse(t *testing.T, s string) (Link, []string) {
	t.Helper()
	l, w, err := Parse(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return l, w
}

func TestRoundTrip(t *testing.T) {
	for _, l := range []Link{
		{Host: "vpn.example.com", Ports: "443"},
		{Name: "Сервер #1 / DE 🇩🇪", Auth: "fake-password", Host: "vpn.example.com", Ports: "443"},
		{Auth: "user:p@ss w/rd:x", Host: "2001:db8::5", Ports: "443,20000-50000", ObfsType: "salamander", ObfsPassword: "fake obfs&=?", SNI: "www.example.com", Insecure: true, PinSHA256: pin},
		{Auth: "fake-password", Host: "192.0.2.1", Ports: "20000-50000", ObfsType: "gecko", ObfsPassword: "fake-obfs", ECH: "AEX+DQBBfake"},
		{Auth: "fake-password", Host: "::ffff:192.0.2.1", Ports: "8443"},
	} {
		for _, s := range []string{l.String(), l.Compat()} {
			got, w := parse(t, s)
			if len(w) != 0 {
				t.Errorf("%s: warnings %v", s, w)
			}
			if !reflect.DeepEqual(got, l) {
				t.Errorf("%s:\n got %+v\nwant %+v", s, got, l)
			}
		}
	}
}

func TestOfficialFormat(t *testing.T) {
	l := Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443,20000-50000", ObfsType: "salamander", ObfsPassword: "fake-obfs", SNI: "real.example.com", Insecure: true, PinSHA256: pin, HopInterval: "30s", UpMbps: 50, DownMbps: 100, Name: "DE"}
	want := "hysteria2://fake-password@vpn.example.com:443,20000-50000/?insecure=1&obfs=salamander&obfs-password=fake-obfs&pinSHA256=" + pin + "&sni=real.example.com#DE"
	if got := l.String(); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

// Importers that parse the authority with a URL library (v2rayN and
// other System.Uri-based clients) need one port there; Incy also reads
// mport and mportHopInt.
func TestCompatFormat(t *testing.T) {
	l := Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "20000-50000, 60000", ObfsType: "salamander", ObfsPassword: "fake-obfs", PinSHA256: pin, Insecure: true, HopInterval: "45s"}
	s := l.Compat()
	if !strings.HasPrefix(s, "hysteria2://fake-password@vpn.example.com:20000/?") {
		t.Fatalf("authority: %s", s)
	}
	for _, p := range []string{"mport=20000-50000%2C60000", "mportHopInt=45", "pinSHA256=" + pin, "insecure=1", "obfs=salamander"} {
		if !strings.Contains(s, p) {
			t.Errorf("%s lacks %s", s, p)
		}
	}
	back, _ := parse(t, s)
	if back.Ports != "20000-50000,60000" || back.HopInterval != "45s" {
		t.Fatalf("%+v", back)
	}
	// One port: nothing to add.
	one := Link{Host: "vpn.example.com", Ports: "443"}
	if one.Compat() != one.String() {
		t.Fatal(one.Compat())
	}
}

// Links as other clients and panels write them.
func TestParseForeign(t *testing.T) {
	cases := []struct {
		in   string
		want Link
		warn []string
	}{
		// HApp and Incy docs: multi-port in the authority.
		{"hy2://fake-password@vpn.example.com:1234,5000-6000,7044/?obfs=salamander&obfs-password=fake-obfs#HApp",
			Link{Name: "HApp", Auth: "fake-password", Host: "vpn.example.com", Ports: "1234,5000-6000,7044", ObfsType: "salamander", ObfsPassword: "fake-obfs"}, nil},
		// Incy: mport, mportHopInt, up/down, fp and alpn.
		{"hysteria2://fake-password@vpn.example.com:443?mport=443,5000-6000&mportHopInt=30&up=50&down=200&fp=chrome&alpn=h3&insecure=1&pinSHA256=" + pin,
			Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443,5000-6000", HopInterval: "30s", UpMbps: 50, DownMbps: 200, Insecure: true, PinSHA256: pin}, nil},
		// v2rayN: extra ports in mport without the main one.
		{"hysteria2://fake-password@vpn.example.com:443?mport=20000-30000&peer=peer.example.com&allowInsecure=1",
			Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443,20000-30000", SNI: "peer.example.com", Insecure: true}, nil},
		// The documented alias "ports".
		{"hy2://fake-password@vpn.example.com:443/?ports=443,20000-50000",
			Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443,20000-50000"}, nil},
		// Xray: pcs and fm.
		{`hy2://fake-password@[2001:db8::1]:443?pcs=` + pin + `&fm={"udp":[{"type":"salamander","settings":{"password":"fake-obfs"}}]}`,
			Link{Auth: "fake-password", Host: "2001:db8::1", Ports: "443", ObfsType: "salamander", ObfsPassword: "fake-obfs", PinSHA256: pin}, nil},
		// No port: 443.
		{"hy2://fake-password@vpn.example.com",
			Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443"}, nil},
		// Guesses and leftovers are reported.
		{"hy2://fake-password@vpn.example.com:443?obfs-password=fake-obfs&mportHopInt=soon&up=fast&foo=1&pinSHA256=abc",
			Link{Auth: "fake-password", Host: "vpn.example.com", Ports: "443", ObfsType: "salamander", ObfsPassword: "fake-obfs", PinSHA256: "abc"},
			[]string{`ignored mportHopInt "soon": not a number of seconds`, `ignored up "fast": not a number of Mbps`, "obfs-password without obfs: assuming obfs=salamander", "pinSHA256 is not a 64-digit hex SHA-256: the certificate will never match", "ignored parameter foo"}},
	}
	for _, c := range cases {
		got, w := parse(t, c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.in, got, c.want)
		}
		if !slices.Equal(w, c.warn) {
			t.Errorf("%s: warnings %q, want %q", c.in, w, c.warn)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"",
		"vpn.example.com:443",
		"vless://fake@vpn.example.com:443",
		"hy2://fake@:443",
		"hy2://fake@[2001:db8::1",
		"hy2://fake@[2001:db8::1]x",
		"hy2://fake@vpn.example.com:0",
		"hy2://fake@vpn.example.com:http",
		"hy2://fake@vpn.example.com:500-400",
		"hy2://fake@vpn.example.com:443?mport=a-b",
		"hy2://fake@vpn.example.com:443?obfs=xor&obfs-password=x",
		"hy2://fake@vpn.example.com:443?obfs=salamander",
		"hy2://fake@vpn.example.com:443?insecure=maybe",
		"hy2://fake%zz@vpn.example.com:443",
		"hy2://fake@vpn.example.com:443?a=%zz",
	} {
		if _, _, err := Parse(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

func TestNormalizePorts(t *testing.T) {
	for in, want := range map[string]string{
		"443":                      "443",
		"443,443":                  "443",
		"443,443,20000-30000":      "443,20000-30000",
		"20000-30000,443":          "443,20000-30000",
		"25000,20000-30000":        "20000-30000",
		"443, 444,445-500,499-600": "443-600",
		"1-65535,443":              "1-65535",
		"8443,443":                 "443,8443",
		"443,,444":                 "443,,444", // invalid: as is, without spaces
		" 0 , 1":                   "0,1",
	} {
		if got := NormalizePorts(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
		if got := NormalizePorts(want); got != want {
			t.Errorf("%q again: %q", want, got)
		}
	}
	// What HyRoute up to v1.3.0-beta.3 saved for a link (authority port,
	// then mport) is the same set as what the parser gives now.
	for _, c := range [][2]string{{"443", "443,20000-30000"}, {"25000", "20000-30000"}, {"443", "443"}, {"20000-30000", "25000-26000"}, {"443", " 20000-30000 "}} {
		if a, b := NormalizePorts(c[0]+","+c[1]), NormalizePorts(mergePorts(c[0], c[1])); a != b {
			t.Errorf("%q + %q: before %q, now %q", c[0], c[1], a, b)
		}
	}
}

func TestValidPin(t *testing.T) {
	colons := strings.ToUpper(strings.Join(splitEvery(pin, 2), ":"))
	for _, p := range []string{pin, colons, strings.ReplaceAll(colons, ":", "-")} {
		if !ValidPin(p) {
			t.Errorf("%s", p)
		}
	}
	for _, p := range []string{"", "abc", pin[:62], pin[:63] + "g"} {
		if ValidPin(p) {
			t.Errorf("%s", p)
		}
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func FuzzParse(f *testing.F) {
	f.Add("hysteria2://fake@vpn.example.com:443,20000-50000/?obfs=salamander&obfs-password=x&sni=a&insecure=1&pinSHA256=" + pin + "#n")
	f.Add("hy2://u:p@[2001:db8::1]:443?mport=443,1000-2000&mportHopInt=5")
	f.Fuzz(func(t *testing.T, s string) {
		l, _, err := Parse(s)
		if err != nil {
			return
		}
		for _, out := range []string{l.String(), l.Compat()} {
			back, _, err := Parse(out)
			if err != nil {
				t.Fatalf("%q → %q: %v", s, out, err)
			}
			if back.Auth != l.Auth || back.Host != l.Host || back.ObfsPassword != l.ObfsPassword || back.PinSHA256 != l.PinSHA256 || back.Name != l.Name {
				t.Fatalf("%q → %q:\n%+v\n%+v", s, out, l, back)
			}
		}
	})
}
