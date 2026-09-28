package rules

import (
	"strings"
	"testing"
)

// countingGeo fails the test on any lookup: Check must not touch the
// rule databases.
type countingGeo struct{ t *testing.T }

func (g countingGeo) Site(n string) (DomainMatcher, error) {
	g.t.Errorf("Check looked up geosite:%s", n)
	return nil, ErrGeoNoData
}

func (g countingGeo) IP(n string) (IPMatcher, error) {
	g.t.Errorf("Check looked up geoip:%s", n)
	return nil, ErrGeoNoData
}

// TestCheck: Check accepts geosite:/geoip: without geodata and never looks
// them up, and refuses exactly what Compile refuses.
func TestCheck(t *testing.T) {
	withGeo(t, countingGeo{t})
	off := false
	ok := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "geo", Domains: []string{"geosite:youtube", "geoip:ru", "10.0.0.0/8"}, Action: Tunnel},
		{Name: "re", Domains: []string{"regexp:^ad[0-9]+\\."}, Action: Block},
		{Name: "app", Apps: []AppMatch{{Pattern: "chrome.exe"}}, Action: Direct},
		// Disabled rules are not compiled (as by Compile).
		{Name: "off", Enabled: &off, Domains: []string{"regexp:("}, Action: Block},
	}}
	if err := Check(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Rule{
		{Name: "re", Domains: []string{"regexp:("}, Action: Block},
		{Name: "pat", Domains: []string{"a b.com"}, Action: Block},
		{Name: "empty", Action: Block},
		{Name: "kind", Apps: []AppMatch{{Pattern: "x.exe", Kind: "weird"}}, Action: Block},
		{Name: "ip", Domains: []string{"geoip:"}, Action: Block},
		{Name: "proto", Domains: []string{"a.com"}, Protocol: "sctp", Action: Block},
		{Name: "port", Protocol: "tcp", Ports: PortList{"70000"}, Action: Block},
	} {
		cfg := Config{DefaultAction: Direct, Rules: []Rule{bad}}
		err := Check(cfg)
		_, cerr := compileWith(cfg, nil)
		if err == nil || cerr == nil || err.Error() != cerr.Error() || !strings.Contains(err.Error(), bad.Name) {
			t.Errorf("%s: Check %v, Compile %v", bad.Name, err, cerr)
		}
	}
}
