package awg

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// key is a test key: 32 bytes of b. No real keys in tests.
func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

// amneziaConf is laid out as the Amnezia app's template writes it:
// empty values for what the server does not use.
func amneziaConf() string {
	return `[Interface]
Address = 10.8.1.2/32
DNS = 1.1.1.1, 1.0.0.1
PrivateKey = ` + key(1) + `
Jc = 4
Jmin = 10
Jmax = 50
S1 = 72
S2 = 56
S3 = 32
S4 = 16
H1 = 1020325451-1020325500
H2 = 3288052141-3288052200
H3 = 1766607858
H4 = 2114195553
I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0><r 16><t>
I2 =
I3 =
I4 =
I5 =
HeaderProtectionKey =
RandomTrailers =

[Peer]
PublicKey = ` + key(2) + `
PresharedKey = ` + key(3) + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
`
}

func TestParseConfAmnezia(t *testing.T) {
	c, warns, err := ParseConf(amneziaConf())
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	s := c.Settings
	if c.Host != "203.0.113.5" || c.Port != 51820 {
		t.Errorf("endpoint %s:%d", c.Host, c.Port)
	}
	if s.PrivateKey != key(1) || s.PublicKey != key(2) || s.PresharedKey != key(3) {
		t.Error("keys")
	}
	if s.Address != "10.8.1.2/32" || s.DNS != "1.1.1.1, 1.0.0.1" || s.Keepalive != "25" {
		t.Errorf("address %q dns %q keepalive %q", s.Address, s.DNS, s.Keepalive)
	}
	if s.Jc != 4 || s.Jmin != 10 || s.Jmax != 50 || s.S1 != 72 || s.S2 != 56 || s.S3 != 32 || s.S4 != 16 {
		t.Errorf("numbers %+v", s)
	}
	if s.H1 != "1020325451-1020325500" || s.H4 != "2114195553" || !strings.HasPrefix(s.I1, "<b 0xc6") || s.I2 != "" {
		t.Errorf("headers %q %q %q", s.H1, s.H4, s.I1)
	}
	if !s.Obfuscated() {
		t.Error("not obfuscated")
	}
}

func TestParseConfWarnings(t *testing.T) {
	text := `# Name = Офис
[Interface]
PrivateKey = ` + key(1) + `
Address = 10.0.0.2/32
Address = fd00::2/128
DNS = 10.0.0.1, corp.example
PostUp = iptables -A FORWARD
ListenPort = 51820
Jc = 3 # comment
[Peer]
PublicKey = ` + key(2) + `
AllowedIPs = 10.0.0.0/8
Endpoint = [2001:db8::5]:443
[Peer]
PublicKey = ` + key(4) + `
Endpoint = 198.51.100.1:1
`
	c, warns, err := ParseConf(text)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Офис" || c.Host != "2001:db8::5" || c.Port != 443 || c.Settings.PublicKey != key(2) {
		t.Errorf("conf %+v", c)
	}
	if c.Settings.Address != "10.0.0.2/32, fd00::2/128" || c.Settings.DNS != "10.0.0.1" || c.Settings.Jc != 3 {
		t.Errorf("settings %+v", c.Settings)
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{"несколько [Peer]", "домены поиска", "PostUp", "AllowedIPs"} {
		if !strings.Contains(all, want) {
			t.Errorf("no warning with %q in %q", want, all)
		}
	}
	if c.Settings.Obfuscated() == false {
		t.Error("Jc set, yet plain WireGuard")
	}
}

func TestParseConfErrors(t *testing.T) {
	good := amneziaConf()
	for name, text := range map[string]string{
		"no peer":     strings.Split(good, "[Peer]")[0],
		"no endpoint": strings.Replace(good, "Endpoint = 203.0.113.5:51820", "", 1),
		"bad port":    strings.Replace(good, ":51820", ":0", 1),
		"short key":   strings.Replace(good, key(2), "AAAA", 1),
		"bad number":  strings.Replace(good, "Jc = 4", "Jc = four", 1),
		"bad tag":     strings.Replace(good, "<t>", "<x>", 1),
		"jmin > jmax": strings.Replace(good, "Jmin = 10", "Jmin = 60", 1),
		"no address":  strings.Replace(good, "Address = 10.8.1.2/32", "", 1),
		"bad section": strings.Replace(good, "[Peer]", "[Server]", 1),
	} {
		if _, _, err := ParseConf(text); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestConfRoundTrip(t *testing.T) {
	c, _, err := ParseConf(amneziaConf())
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "Нидерланды\nвторая строка"
	c.Settings.HeaderProtectionKey = key(5)
	c.Settings.RandomTrailers = true
	c.Settings.RekeyAfterTime = "100-120"
	text := c.String()
	if strings.Contains(text, "\nвторая") {
		t.Error("a line break of the name made a line of its own")
	}
	back, warns, err := ParseConf(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	c.Name = "Нидерланды вторая строка"
	if back != c {
		t.Errorf("round trip:\n%+v\n%+v", back, c)
	}
}

func TestSplitConfs(t *testing.T) {
	one := amneziaConf()
	two := "# Name = second\n" + strings.Replace(one, "203.0.113.5", "203.0.113.6", 1)
	got := SplitConfs(one + "\n" + two)
	if len(got) != 2 {
		t.Fatalf("%d parts", len(got))
	}
	c, _, err := ParseConf(got[1])
	if err != nil || c.Name != "second" || c.Host != "203.0.113.6" {
		t.Errorf("second: %+v %v", c, err)
	}
	if c, _, err := ParseConf(got[0]); err != nil || c.Name != "" || c.Host != "203.0.113.5" {
		t.Errorf("first: %+v %v", c, err)
	}
}

func TestValidate(t *testing.T) {
	base, _, err := ParseConf(amneziaConf())
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Settings){
		"line break":   func(s *Settings) { s.I1 = "<r 1>\nprivate_key=00" },
		"bad hex tag":  func(s *Settings) { s.I1 = "<b 0xabc>" },
		"negative len": func(s *Settings) { s.I1 = "<r -1>" },
		"open tag":     func(s *Settings) { s.I1 = "<r 1" },
		"h range":      func(s *Settings) { s.H1 = "5-4" },
		"h too big":    func(s *Settings) { s.H2 = "4294967296" },
		"jc":           func(s *Settings) { s.Jc = 1000 },
		"mtu":          func(s *Settings) { s.MTU = 100 },
		"dns name":     func(s *Settings) { s.DNS = "dns.example" },
		"psk":          func(s *Settings) { s.PresharedKey = "x" },
		"keepalive":    func(s *Settings) { s.Keepalive = "70000" },
		"h overlap":    func(s *Settings) { s.H2 = "1020325460" },
		"h default":    func(s *Settings) { s.H1, s.H4 = "", "1-10" },
		"hpk small s":  func(s *Settings) { s.HeaderProtectionKey, s.S4 = key(5), 8 },
	} {
		s := base.Settings
		edit(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	plain := Settings{PrivateKey: key(1), PublicKey: key(2), Address: "10.0.0.2"}
	if err := plain.Validate(); err != nil {
		t.Errorf("plain WireGuard: %v", err)
	}
	if plain.Obfuscated() {
		t.Error("plain WireGuard is obfuscated")
	}
}

func TestUAPI(t *testing.T) {
	c, _, err := ParseConf(amneziaConf())
	if err != nil {
		t.Fatal(err)
	}
	c.Settings.DisableCookies = true
	u, err := c.Settings.UAPI(mustAddrPort("203.0.113.5:51820"))
	if err != nil {
		t.Fatal(err)
	}
	hex1 := strings.Repeat("01", 32)
	want := []string{
		"private_key=" + hex1, "jc=4", "jmin=10", "jmax=50", "s1=72", "s4=16",
		"h1=1020325451-1020325500", "i1=<b 0xc6000000010843290a47ba8ba2ed000044d0><r 16><t>", "disable_cookies=true",
		"replace_peers=true", "public_key=" + strings.Repeat("02", 32), "preshared_key=" + strings.Repeat("03", 32),
		"endpoint=203.0.113.5:51820", "persistent_keepalive_interval=25", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0",
	}
	lines := strings.Split(strings.TrimSuffix(u, "\n"), "\n")
	for _, w := range want {
		if !strings.Contains("\n"+u, "\n"+w+"\n") {
			t.Errorf("no line %q in\n%s", w, u)
		}
	}
	// Device keys come before the peer's: public_key starts the peer.
	idx := map[string]int{}
	for i, l := range lines {
		k, _, _ := strings.Cut(l, "=")
		if _, ok := idx[k]; !ok {
			idx[k] = i
		}
	}
	if idx["public_key"] < idx["i1"] || idx["endpoint"] < idx["public_key"] {
		t.Errorf("order:\n%s", u)
	}
	if strings.Contains(u, "i2=") || strings.Contains(u, "random_trailers") {
		t.Errorf("unset values written:\n%s", u)
	}
	secrets := c.Settings.HexSecrets()
	if len(secrets) != 2 || secrets[0] != hex1 {
		t.Errorf("hex secrets %v", secrets)
	}
}
