package firewall

import (
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
)

func TestPorts(t *testing.T) {
	for yaml, want := range map[string]string{
		"listen: :443\n":                                "443/udp",
		"listen: :443,20000-50000\n":                    "443/udp, 20000-50000/udp",
		"listen: 0.0.0.0:8443\n":                        "8443/udp",
		"acme:\n  domains: [a.example]\n":               "443/udp, 80/tcp, 443/tcp",
		"acme:\n  domains: [a.example]\n  type: http\n": "443/udp, 80/tcp",
		"acme:\n  domains: [a.example]\n  type: tls\n  tls:\n    altPort: 8444\n": "443/udp, 8444/tcp",
		"acme:\n  domains: [a.example]\n  type: dns\n":                            "443/udp",
		"acme:\n  domains: [a.example]\n  disableHTTP: true\n":                    "443/udp, 443/tcp",
	} {
		c, err := hyconfig.ParseServer([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		ps, err := Ports(c)
		if err != nil || List(ps) != want {
			t.Errorf("%q: %s %v, want %s", yaml, List(ps), err, want)
		}
	}
}

func TestSet(t *testing.T) {
	s := parse(" 443/udp,20000-50000/udp,443/udp, ")
	if s.String() != "20000-50000/udp,443/udp" || !s.has("443/udp") || s.has("80/tcp") {
		t.Fatalf("%q", s)
	}
	if parse("").String() != "" {
		t.Fatal("empty")
	}
}
