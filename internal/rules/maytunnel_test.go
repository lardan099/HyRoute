package rules

import "testing"

func TestMayTunnel(t *testing.T) {
	chrome := proc(`C:\Chrome\chrome.exe`, nil)
	curl := proc(`C:\curl.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "curl", App: &AppMatch{Pattern: "curl.exe"}, Action: Direct},
		{Name: "ads", Domain: &DomainMatch{".ads.test"}, Action: Block},
		{Name: "yt", Domain: &DomainMatch{".youtube.com"}, Action: Tunnel},
	}})
	// A domain rule sends it to the tunnel for some names.
	if !s.MayTunnel(sub(chrome, 6)) {
		t.Fatal("domain rule to the tunnel not seen")
	}
	// A rule before the domain rules settles it.
	if s.MayTunnel(sub(curl, 6)) {
		t.Fatal("curl never goes through the tunnel")
	}
	// Direct and Block only.
	s2 := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ads", Domain: &DomainMatch{".ads.test"}, Action: Block},
	}})
	if s2.MayTunnel(sub(chrome, 6)) {
		t.Fatal("no outcome is Tunnel")
	}
	// The default route counts.
	s3 := mustCompile(t, Config{DefaultAction: Tunnel, Rules: []Rule{
		{Name: "ads", Domain: &DomainMatch{".ads.test"}, Action: Block},
	}})
	if !s3.MayTunnel(sub(chrome, 6)) {
		t.Fatal("default Tunnel not seen")
	}
}
