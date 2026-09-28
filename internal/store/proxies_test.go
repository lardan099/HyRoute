package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// socks-udp: proxies.json of v1.0.0 … v1.2.0 (no "udp") loads with the
// defaults; a proxy at its default is written without the key; "on" and
// "off" round-trip; any other value loads as the default.
func TestProxiesUDPCompat(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v12 := `[
  {"id": "a1", "name": "Binance", "enabled": true, "profile": "", "port": 10801, "lan": false, "username": ""},
  {"id": "b2", "name": "Phone", "enabled": true, "profile": "p1", "port": 10802, "lan": true, "username": ""}
]`
	if err := os.WriteFile(filepath.Join(st.Dir, "proxies.json"), []byte(v12), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := st.LoadProxies()
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	if list[0].UDP != "" || !list[0].UDPOn() || list[1].UDP != "" || list[1].UDPOn() {
		t.Fatalf("%+v", list)
	}
	if err := st.SaveProxies(list); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(st.Dir, "proxies.json"))
	if strings.Contains(string(b), `"udp"`) {
		t.Fatalf("default written: %s", b)
	}
	list[0].UDP, list[1].UDP = "off", "on"
	if err := st.SaveProxies(list); err != nil {
		t.Fatal(err)
	}
	back, err := st.LoadProxies()
	if err != nil || back[0].UDP != "off" || back[0].UDPOn() || back[1].UDP != "on" || !back[1].UDPOn() {
		t.Fatal(back, err)
	}
	for _, v := range []string{`"maybe"`, `true`, `1`, `null`, `{}`, `["on"]`} {
		raw := `[{"id": "a1", "name": "x", "enabled": true, "port": 10801, "lan": true, "udp": ` + v + `, "username": ""}]`
		os.WriteFile(filepath.Join(st.Dir, "proxies.json"), []byte(raw), 0o600)
		list, err := st.LoadProxies()
		if err != nil || len(list) != 1 || list[0].UDP != "" || list[0].UDPOn() {
			t.Fatalf("%s: %+v %v", v, list, err)
		}
	}
}

func TestNormalizeUDP(t *testing.T) {
	for _, c := range []struct {
		lan      bool
		in, want UDPMode
	}{
		{false, "on", ""}, {false, "off", "off"}, {false, "", ""},
		{true, "off", ""}, {true, "on", "on"}, {true, "", ""},
	} {
		p := LocalProxy{LAN: c.lan, UDP: c.in}
		p.NormalizeUDP()
		if p.UDP != c.want {
			t.Errorf("lan %v %q: %q", c.lan, c.in, p.UDP)
		}
	}
}
