package hysteria

import (
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows checkouts may turn the golden files' LF into CRLF.
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if string(got) != string(want) {
		t.Fatalf("%s mismatch\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

var runOpts = RunOptions{SOCKSListen: "127.0.0.1:50001", SOCKSUsername: "u", SOCKSPassword: "p"}

func TestConfigMinimal(t *testing.T) {
	p := Profile{Host: "203.0.113.10", Ports: "443", Auth: "secret"}
	b, err := BuildConfig(&p, runOpts)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "minimal.yaml", b)
}

func TestConfigFull(t *testing.T) {
	p := Profile{
		Host: "example.com", Ports: "443,20000-50000", Auth: "user:pass",
		TLS:        TLS{Insecure: false, PinSHA256: "ba:88", CA: `C:\certs\ca.pem`},
		Obfs:       Obfs{Type: "salamander", Password: "obfs: #pw"},
		Hop:        Hop{Interval: "30s"},
		Bandwidth:  Bandwidth{Up: "50 mbps", Down: "200 mbps"},
		Congestion: Congestion{Type: "bbr", BBRProfile: "standard"},
		QUIC:       QUIC{InitStreamReceiveWindow: 8388608, MaxIdleTimeout: "30s", DisablePathMTUDiscovery: true},
		FastOpen:   true,
	}
	// Pinned IP: server becomes the IP, SNI falls back to the domain.
	o := runOpts
	o.ServerIP = "203.0.113.10"
	b, err := BuildConfig(&p, o)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "full_pinned.yaml", b)
}

func TestConfigGeckoIPv6(t *testing.T) {
	p := Profile{
		Host: "example.com", Ports: "443", Auth: "a",
		TLS:  TLS{SNI: "explicit.example"},
		Obfs: Obfs{Type: "gecko", Password: "g", MinPacketSize: 100, MaxPacketSize: 1200},
		Hop:  Hop{MinInterval: "10s", MaxInterval: "60s"},
	}
	o := runOpts
	o.ServerIP = "2001:db8::10"
	b, err := BuildConfig(&p, o)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "gecko_ipv6.yaml", b)
}

func TestConfigRejectsInvalid(t *testing.T) {
	for _, p := range []Profile{
		{Ports: "443"},
		{Host: "h", Ports: "x"},
		{Host: "h", Ports: "443", Obfs: Obfs{Type: "salamander"}},
		{Host: "h", Ports: "443", Hop: Hop{Interval: "soon"}},
	} {
		if _, err := BuildConfig(&p, runOpts); err == nil {
			t.Fatalf("%+v should fail", p)
		}
	}
}

// Validate accepts the obfs type in any case, so the config and the link
// must too instead of silently dropping the obfs.
func TestObfsTypeAnyCase(t *testing.T) {
	p := Profile{Host: "203.0.113.1", Ports: "443", Obfs: Obfs{Type: "Salamander", Password: "pw12"}}
	b, err := BuildConfig(&p, runOpts)
	if err != nil {
		t.Fatal(err)
	}
	var c yConfig
	if err := yaml.Unmarshal(b, &c); err != nil || c.Obfs == nil || c.Obfs.Type != "salamander" || c.Obfs.Salamander == nil || c.Obfs.Salamander.Password != "pw12" {
		t.Fatalf("obfs dropped:\n%s", b)
	}
	if u := p.URI(); !strings.Contains(u, "obfs=salamander") || !strings.Contains(u, "obfs-password=pw12") {
		t.Fatalf("obfs dropped from the link: %s", u)
	}
}

// The server field must be something Hysteria parses: net.SplitHostPort,
// then every port with strconv.ParseUint (no spaces).
func TestServerStringForHysteria(t *testing.T) {
	for _, c := range []struct{ host, ports, want string }{
		{"example.com", "443", "example.com:443"},
		{"203.0.113.1", "443, 20000 - 50000", "203.0.113.1:443,20000-50000"},
		{"2001:db8::1", "443,20000-50000", "[2001:db8::1]:443,20000-50000"},
		{"::ffff:203.0.113.5", "8443", "[::ffff:203.0.113.5]:8443"},
	} {
		got := ServerString(c.host, c.ports)
		if got != c.want {
			t.Errorf("%s %q: got %q want %q", c.host, c.ports, got, c.want)
			continue
		}
		if h, _, err := net.SplitHostPort(got); err != nil || h != c.host {
			t.Errorf("%q: host %q err %v", got, h, err)
		}
	}
	p := Profile{Host: "203.0.113.1", Ports: "443, 20000-50000"}
	b, err := BuildConfig(&p, runOpts)
	if err != nil || !strings.HasPrefix(string(b), "server: 203.0.113.1:443,20000-50000\n") {
		t.Fatalf("%v\n%s", err, b)
	}
}
