package app

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/hysteria"
)

// awgTestKey is a test key: 32 bytes of b. No real keys in tests.
func awgTestKey(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func awgConfText(host string) string {
	return "[Interface]\nPrivateKey = " + awgTestKey('a') + "\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 10\nJmax = 50\n" +
		"S1 = 20\nS2 = 30\nH1 = 1000\nH2 = 2000\nH3 = 3000\nH4 = 4000\nPostUp = true\n\n[Peer]\nPublicKey = " + awgTestKey('b') +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + host + ":51820\nPersistentKeepalive = 25\n"
}

func TestParseLinksAWGConfs(t *testing.T) {
	l := ParseLinks(awgConfText("203.0.113.5") + "\n# Name = второй\n" + awgConfText("203.0.113.6"))
	if len(l.Profiles) != 2 || len(l.Errors) != 0 {
		t.Fatalf("%+v", l)
	}
	a, b := l.Profiles[0], l.Profiles[1]
	if !a.IsAWG() || a.Name != "203.0.113.5" || a.Ports != "51820" || a.AWG.Jc != 4 || b.Name != "второй" || b.Host != "203.0.113.6" {
		t.Fatalf("%+v\n%+v", a, b)
	}
	if len(l.Warnings) != 2 || !strings.Contains(l.Warnings[0], "203.0.113.5: ") || !strings.Contains(l.Warnings[0], "PostUp") {
		t.Fatalf("warnings %q", l.Warnings)
	}
	bad := ParseLinks(strings.Replace(awgConfText("203.0.113.5"), "Endpoint", "# Endpoint", 1))
	if len(bad.Profiles) != 0 || len(bad.Errors) != 1 || !strings.HasPrefix(bad.Errors[0], "конфиг: ") {
		t.Fatalf("%+v", bad)
	}
}

func TestParseLinksVPNKey(t *testing.T) {
	c, _, err := awg.ParseConf(awgConfText("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "ключ"
	l := ParseLinks("hy2://pw@h.example:443#one\n" + awg.VPNKey(c) + "\nvpn://broken")
	if len(l.Profiles) != 2 || len(l.Errors) != 1 || l.IgnoredTotal() != 0 {
		t.Fatalf("%+v", l)
	}
	if p := l.Profiles[1]; !p.IsAWG() || p.Name != "ключ" || p.AWG.PrivateKey != c.Settings.PrivateKey {
		t.Fatalf("%+v", p)
	}
	if !strings.HasPrefix(l.Errors[0], "ссылка 3: ") {
		t.Fatalf("%q", l.Errors)
	}
}

// A server imported from a .conf saves, and the same server is not added
// twice.
func TestImportAWGConf(t *testing.T) {
	c, _ := newCtl(t)
	res, err := c.ImportURIs(awgConfText("203.0.113.5"))
	if err != nil || len(res.Added) != 1 || res.Added[0].Protocol != "awg" || res.Added[0].Transport != "" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = c.ImportURIs(awgConfText("203.0.113.5"))
	if err != nil || len(res.Added) != 0 || len(res.Skipped) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	p, err := c.Profile(c.Profiles()[0].ID)
	if err != nil || p.Protocol != hysteria.ProtoAWG || p.AWG.PrivateKey != awgTestKey('a') {
		t.Fatalf("%+v %v", p, err)
	}
}
