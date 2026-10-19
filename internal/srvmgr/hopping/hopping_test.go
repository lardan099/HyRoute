package hopping

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func TestParse(t *testing.T) {
	s := Spec{Ports: []string{" 20000-50000 ", "", "443", "8443"}}
	rs, err := s.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if Join(rs) != "443,8443,20000-50000" || Count(rs) != 30003 || !Hopping(rs) {
		t.Fatalf("%v %d", rs, Count(rs))
	}
	// Hysteria listens on the lowest port.
	if got := s.Listen(rs); got != ":443,8443,20000-50000" {
		t.Fatal(got)
	}
	one, _ := Spec{Ports: []string{"443"}, Host: "0.0.0.0"}.Parse()
	if Hopping(one) || (Spec{Ports: []string{"443"}, Host: "0.0.0.0"}).Listen(one) != "0.0.0.0:443" {
		t.Fatal(one)
	}
	if r, _ := (Spec{Ports: []string{"443"}, Host: "2001:db8::10"}).Parse(); (Spec{Ports: []string{"443"}, Host: "2001:db8::10"}).Listen(r) != "[2001:db8::10]:443" {
		t.Fatal("v6 host")
	}
	// Adjacent ranges are fine.
	if _, err := (Spec{Ports: []string{"20000-29999", "30000-40000"}}).Parse(); err != nil {
		t.Fatal(err)
	}
}

func TestParseRefused(t *testing.T) {
	many := make([]string, MaxEntries+1)
	for i := range many {
		many[i] = strconv.Itoa(1000 + i)
	}
	cases := map[string]Spec{
		"пересекаются":  {Ports: []string{"20000-30000", "25000-40000"}},
		"400-500 и 443": {Ports: []string{"443", "400-500"}},
		"8443 и 8443":   {Ports: []string{"8443", "8443"}},
		"начало диапазона больше": {Ports: []string{"50000-20000"}},
		"от 1 до 65535":           {Ports: []string{"70000"}},
		"\"0-10\"":                {Ports: []string{"0-10"}},
		"\"abc\"":                 {Ports: []string{"abc"}},
		"хотя бы один":            {Ports: []string{" ", ""}},
		"не больше 16":            {Ports: many},
		"нужен IP-адрес":          {Ports: []string{"443"}, Host: "vpn.example.com"},
	}
	for want, s := range cases {
		if _, err := s.Parse(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", s, err, want)
		}
	}
}

func TestFromListen(t *testing.T) {
	for listen, want := range map[string]string{
		":443":                      ":443",
		":443,20000-50000":          ":443,20000-50000",
		"0.0.0.0:20000-50000":       "0.0.0.0:20000-50000",
		"[::]:443":                  ":443",
		"[2001:db8::10]:443":        "[2001:db8::10]:443",
		":20000-50000,443":          ":443,20000-50000",
		"192.0.2.10:8443,9000-9100": "192.0.2.10:8443,9000-9100",
	} {
		s, rs, err := FromListen(listen)
		if err != nil || s.Listen(rs) != want {
			t.Errorf("%s: %q %v, want %s", listen, s.Listen(rs), err, want)
		}
	}
}

func TestFamilies(t *testing.T) {
	for host, want := range map[string][2]bool{"": {true, true}, "0.0.0.0": {true, false}, "[::]": {true, true}, "192.0.2.10": {true, false}, "[2001:db8::10]": {false, true}} {
		if v4, v6 := families(host); [2]bool{v4, v6} != want {
			t.Errorf("%q: %v %v", host, v4, v6)
		}
	}
}

const ssOut = "udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=4242,fd=7))\n" +
	"udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:((\"wg-quick\",pid=900,fd=3))\n" +
	"udp UNCONN 0 0 [::]:51820 [::]:* users:((\"wg-quick\",pid=900,fd=4))\n" +
	"udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=500,fd=13))\n" +
	"tcp LISTEN 0 4096 0.0.0.0:30000 0.0.0.0:* users:((\"nginx\",pid=700,fd=6))\n"

func server(tools ...string) *fake.Executor {
	ex := fake.New()
	ex.On("ss", "-Hlntup").Reply(ssOut, 0)
	ex.On("test").Reply("", 1)
	for _, t := range tools {
		ex.On("test", "-e", t).Reply("", 0)
	}
	return ex
}

// A port of another program's UDP socket is refused (TCP and Hysteria's
// own are not), with what holds it.
func TestCheckBusy(t *testing.T) {
	ctx := context.Background()
	ex := server("/usr/sbin/nft")
	ok := Spec{Ports: []string{"443", "20000-50000"}}
	rs, _ := ok.Parse()
	if err := Check(ctx, ex, ok, rs, false); err != nil {
		t.Fatal(err)
	}
	for ports, want := range map[string]string{"443,50000-60000": "UDP 51820 — wg-quick", "443,1-100": "UDP 53 — systemd-resolve", "53": "UDP 53"} {
		s := Spec{Ports: strings.Split(ports, ",")}
		rs, _ := s.Parse()
		var he *Error
		if err := Check(ctx, ex, s, rs, false); !errors.As(err, &he) || !strings.Contains(he.Msg, want) || strings.Count(he.Msg, "51820") > 1 {
			t.Errorf("%s: %v", ports, err)
		}
	}
}

// Hopping needs nftables, or iptables for IPv4 and ip6tables for IPv6.
func TestCheckTools(t *testing.T) {
	ctx := context.Background()
	both := Spec{Ports: []string{"443", "20000-50000"}}
	v4 := Spec{Ports: []string{"443", "20000-50000"}, Host: "0.0.0.0"}
	rs, _ := both.Parse()
	cases := []struct {
		tools []string
		spec  Spec
		want  string // "" ok
	}{
		{[]string{"/usr/sbin/nft"}, both, ""},
		{[]string{"/sbin/iptables", "/sbin/ip6tables"}, both, ""},
		{[]string{"/usr/sbin/iptables"}, both, "ip6tables"},
		{[]string{"/usr/sbin/iptables"}, v4, ""},
		{nil, v4, "iptables"},
		{nil, both, "iptables и ip6tables"},
	}
	for _, c := range cases {
		err := Check(ctx, server(c.tools...), c.spec, rs, false)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%v %q: %v", c.tools, c.spec.Host, err)
		}
	}
	// One port: no redirect, no tool needed.
	one := Spec{Ports: []string{"8443"}}
	r1, _ := one.Parse()
	if err := Check(ctx, server(), one, r1, false); err != nil {
		t.Fatal(err)
	}
}

// Without ss the ports are not checked; the tools still are.
func TestCheckNoSS(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("ss").Reply("", 127)
	ex.On("test").Reply("", 1)
	s := Spec{Ports: []string{"443", "20000-50000"}}
	rs, _ := s.Parse()
	var he *Error
	if err := Check(ctx, ex, s, rs, false); !errors.As(err, &he) {
		t.Fatalf("no tools: %v", err)
	}
	ex.On("test", "-e", "/usr/sbin/nft").Reply("", 0)
	if err := Check(ctx, ex, s, rs, false); !errors.Is(err, ErrNoSS) {
		t.Fatalf("%v", err)
	}
}
