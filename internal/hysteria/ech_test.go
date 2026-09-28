package hysteria

import (
	"encoding/base64"
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
