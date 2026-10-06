package hysteria

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// echList builds an ECHConfigList with the given configs' contents.
func echList(contents ...[]byte) []byte {
	var list []byte
	for _, c := range contents {
		list = append(list, 0xfe, 0x0d, byte(len(c)>>8), byte(len(c)))
		list = append(list, c...)
	}
	return append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
}

func TestECHInline(t *testing.T) {
	good := echList([]byte("config-one-contents?"), []byte{0xff, 0xfe, 0xfd})
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if s := enc.EncodeToString(good); !ECHInline(s) || !ECHInline("  "+s+"\n") {
			t.Fatalf("%q", s)
		}
	}
	bad := [][]byte{
		good[:len(good)-1],                    // truncated
		append(good[:len(good):len(good)], 0), // trailing data
		{0, 0},                                // zero configs
		{0, 3, 0xfe, 0x0d, 0},                 // half a config
	}
	for _, b := range bad {
		if ECHInline(base64.StdEncoding.EncodeToString(b)) {
			t.Fatalf("%x", b)
		}
	}
	for _, s := range []string{"", `\\attacker\share\x`, `\\?\UNC\h\s\x`, `C:\ech.pem`, "ech.pem", "garbage!!"} {
		if ECHInline(s) {
			t.Fatal(s)
		}
	}
}

func TestSameConnectionNoSecrets(t *testing.T) {
	a := Profile{ID: "a", Name: "A", Host: "h.example", Ports: "443", Auth: "x", Obfs: Obfs{Type: "salamander", Password: "p"}}
	b := a
	b.ID, b.Name, b.Auth, b.Obfs.Password = "b", "B", "", ""
	if !SameConnectionNoSecrets(a, b) || SameConnection(a, b) {
		t.Fatal("secrets")
	}
	b.TLS.SNI = "other"
	if SameConnectionNoSecrets(a, b) {
		t.Fatal("sni")
	}
}

// A link names ECH only inline: a file path from a link or a
// subscription is dropped with a warning.
func TestParseURIECH(t *testing.T) {
	inline := base64.StdEncoding.EncodeToString(echList([]byte("contents")))
	p, warn, err := ParseURI("hysteria2://pw@example.com:443/?ech=" + url.QueryEscape(inline))
	if err != nil || p.TLS.ECH != inline || len(warn) != 0 {
		t.Fatalf("inline: %q %v %v", p.TLS.ECH, warn, err)
	}
	for _, v := range []string{`\host\share\x`, `C:\ech.pem`, "ech.pem"} {
		p, warn, err := ParseURI("hysteria2://pw@example.com:443/?ech=" + url.QueryEscape(v))
		if err != nil || p.TLS.ECH != "" || len(warn) != 1 || !strings.Contains(warn[0], "ech") {
			t.Fatalf("%q: %q %v %v", v, p.TLS.ECH, warn, err)
		}
	}
}

// Validate (and with it BuildConfig) takes a non-inline ECH only as a
// full path on a drive letter.
func TestValidateECHPath(t *testing.T) {
	for v, ok := range map[string]bool{
		`C:\Users\me\ech.pem`: true, `d:\ech`: true,
		`\host\share\x`: false, `\?\UNC\h\s\x`: false, `\.\pipe\x`: false, `//host/share/x`: false,
		`ech.pem`: false, `C:ech`: false, `C:/ech`: false, `C:\a:b`: false, ` C:\ech`: false,
	} {
		p := Profile{Host: "example.com", Ports: "443", TLS: TLS{ECH: v}}
		if err := p.Validate(); (err == nil) != ok {
			t.Fatalf("%q: %v", v, err)
		}
	}
}
