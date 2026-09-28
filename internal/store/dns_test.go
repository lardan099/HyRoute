package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

func TestDNSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	c, err := s.LoadDNS()
	if err != nil || c != (dnspolicy.Config{}) {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	if _, err := os.Stat(filepath.Join(dir, dnsFile)); !os.IsNotExist(err) {
		t.Fatal("LoadDNS created the file")
	}
	const secret = "https://dns.nextdns.io/abc123secret"
	want := dnspolicy.Config{BlockBrowserDoH: true, StripECH: true, ByRules: true, IgnoreAddrRules: true,
		Tunnel: dnspolicy.Upstream{Preset: "google", URL: "dropped"}, Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: secret}}
	if err := s.SaveDNS(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadDNS()
	want.Tunnel.URL = ""
	if err != nil || got != want {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, dnsFile))
	if runtime.GOOS == "windows" && strings.Contains(string(b), "abc123secret") {
		t.Fatal("custom URL in plain text")
	}
	if strings.Contains(string(b), "dropped") || strings.Contains(string(b), `"url"`) {
		t.Fatalf("stored the URL of a preset: %s", b)
	}
	// Off options are left out: a user of one option has a short file.
	if err := s.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, dnsFile))
	if strings.TrimSpace(string(b)) != "{\n  \"byRules\": true\n}" {
		t.Fatalf("%s", b)
	}
	// Refused and broken.
	if err := s.SaveDNS(dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "tcp://9.9.9.9"}}); err == nil {
		t.Fatal("invalid config saved")
	}
	for label, body := range map[string]string{
		"json":    "{",
		"preset":  `{"tunnel":{"preset":"nope"}}`,
		"sealed":  `{"direct":{"preset":"custom","sealedURL":"***"}}`,
		"invalid": `{"direct":{"preset":"custom"}}`,
	} {
		os.WriteFile(filepath.Join(dir, dnsFile), []byte(body), 0o600)
		if _, err := s.LoadDNS(); err == nil {
			t.Errorf("%s: loaded", label)
		}
	}
	// Unknown fields and a BOM are fine.
	os.WriteFile(filepath.Join(dir, dnsFile), []byte("\xef\xbb\xbf{\"byRules\":true,\"future\":1}"), 0o600)
	if c, err := s.LoadDNS(); err != nil || !c.ByRules {
		t.Fatalf("lenient: %+v %v", c, err)
	}
}
