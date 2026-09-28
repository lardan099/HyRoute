package app

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

// The user reconnects after the engine failed, the kill switch off: the
// resets of the failed engine may not have got through, as with the
// automatic reconnect.
func TestReconnectAfterEngineFailureResetsUnknownDomains(t *testing.T) {
	c, started := newCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	(*started)[0].fail()
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if !(*started)[1].cfg.ResetUnknownDomain {
		t.Fatal("reconnect after the engine failure keeps unknown domains direct")
	}
	// A reconnect of a working session, and a Connect after Disconnect
	// (the connections went direct meanwhile), reset nothing.
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	(*started)[2].fail()
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if (*started)[2].cfg.ResetUnknownDomain || (*started)[3].cfg.ResetUnknownDomain {
		t.Fatal("reset without an engine failure before")
	}
}

// prefs.json did not load: its defaults are not the user's choices. Logs
// stay in memory and the rule databases are not replaced with the
// default source's.
func TestUnloadedPrefsKeepUserChoices(t *testing.T) {
	c, _ := newCtl(t)
	if err := c.SetGeoPrefs("v2fly", "", "", false, 12); err != nil {
		t.Fatal(err)
	}
	v2, _ := geodata.FindSource("v2fly")
	geoRules(t, c, "geoip:ru")
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: &geodata.FileState{SHA256: "ab", URL: v2.IP}, Checked: time.Now()})
	if _, due := c.geoDue(); due {
		t.Fatal("up to date")
	}
	if err := os.WriteFile(filepath.Join(c.Store.Dir, "prefs.json"), []byte(`{"geoSource":"v2fly","logsToDisk":false`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Load(); err == nil {
		t.Fatal("broken prefs.json loaded")
	}
	if c.Prefs().ToDisk() {
		t.Fatal("logs written to disk with unknown preferences")
	}
	if _, due := c.geoDue(); due {
		t.Fatal("databases replaced with the default source's")
	}
	if _, err := c.UpdateGeo(context.Background(), true); err == nil || !strings.Contains(err.Error(), "prefs.json не загружен") {
		t.Fatalf("manual update with unknown preferences: %v", err)
	}
	// A database a rule needs and none is there is still downloaded: no
	// file of the user's is replaced.
	geoRules(t, c, "geoip:ru", "geosite:google")
	src, due := c.geoDue()
	if !due || src.Site == "" || src.IP != "" {
		t.Fatalf("missing database: %v %+v", due, src)
	}
}

// The editor's address field takes "host:port" and "[IPv6]:port" too;
// what no host can be is refused rather than saved as a server that never
// connects.
func TestSaveProfileAddress(t *testing.T) {
	c, _ := newCtl(t)
	for _, tc := range []struct{ host, ports, wantHost, wantPorts string }{
		{" vpn.example.com ", "", "vpn.example.com", "443"},
		{"vpn.example.com:8443", "443", "vpn.example.com", "8443"},
		{"203.0.113.5:20000-50000", "", "203.0.113.5", "20000-50000"},
		{"[2001:db8::1]:8443", "443", "2001:db8::1", "8443"},
		{"[2001:db8::1]", "8443", "2001:db8::1", "8443"},
		{"2001:db8::1", "443", "2001:db8::1", "443"},
		{"fe80::1%12", "443", "fe80::1%12", "443"},
		{"[fe80::1%eth0]:8443", "", "fe80::1%eth0", "8443"},
		{"впн.пример.рф.", "", "впн.пример.рф.", "443"},
	} {
		sum, err := c.SaveProfile(hysteria.Profile{Host: tc.host, Ports: tc.ports})
		if err != nil {
			t.Fatalf("%q: %v", tc.host, err)
		}
		p, _ := c.Profile(sum.ID)
		if p.Host != tc.wantHost || p.Ports != tc.wantPorts {
			t.Fatalf("%q %q: saved %q %q", tc.host, tc.ports, p.Host, p.Ports)
		}
	}
	for _, host := range []string{
		"hysteria2://pw@vpn.example.com:443", "vpn.example.com/path", "user@vpn.example.com",
		"vpn example.com", "[2001:db8::1", "[vpn.example.com]:443", "2001:db8::zz", "[2001:db8::1]x",
		"a..b", ".vpn.example.com", "vpn%12.example.com", "203.0.113.5%12",
	} {
		if _, err := c.SaveProfile(hysteria.Profile{Host: host, Ports: "443"}); err == nil {
			t.Fatalf("%q saved", host)
		}
	}
	if _, err := c.SaveProfile(hysteria.Profile{Host: "vpn.example.com:8443", Ports: "9443"}); err == nil {
		t.Fatal("two ports saved")
	}
}

// settings.json or proxies.json did not load: which rules and proxies use
// a server is unknown, so none may go (the defaults in memory name none).
func TestProfileRefsUnknownWithUnloadedFiles(t *testing.T) {
	for _, file := range []string{"settings.json", "proxies.json"} {
		dir := t.TempDir()
		st, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := newCtlAt(t, st)
		if _, err := c.ImportURIs(link + "\n" + strings.Replace(link, "DE%20one", "NL", 1)); err != nil {
			t.Fatal(err)
		}
		s := c.Settings()
		s.Rules = []rules.Rule{{Name: "yt", Domains: []string{".youtube.com"}, Action: rules.Tunnel, Profile: c.Profiles()[1].ID}}
		if _, err := c.SaveSettings(s); err != nil {
			t.Fatal(err)
		}
		id := c.Profiles()[1].ID
		if err := os.WriteFile(filepath.Join(dir, file), []byte(`[{`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := c.Load(); err == nil {
			t.Fatalf("broken %s loaded", file)
		}
		if err := c.DeleteProfile(id); err == nil || !strings.Contains(err.Error(), file+" не загружен") {
			t.Fatalf("%s: deleted: %v", file, err)
		}
		c.mu.Lock()
		used := c.profileUsedLocked(id)
		c.mu.Unlock()
		if !used {
			t.Fatalf("%s: a subscription update would drop the server", file)
		}
	}
}

// A byte order mark encoded with a base64 subscription (or between lists
// joined together) does not hide the link after it.
func TestParseLinksBOMInsideBase64(t *testing.T) {
	body := "\ufeffhysteria2://pw@a.example:443/#A\nhysteria2://pw@b.example:443/#B\n\ufeffhy2://pw@c.example:443/#C\n"
	l := ParseLinks(base64.StdEncoding.EncodeToString([]byte(body)))
	if !l.Base64 || len(l.Profiles) != 3 || l.Profiles[0].Name != "A" || l.IgnoredTotal() != 0 || len(l.Errors) != 0 {
		t.Fatalf("%+v", l)
	}
}

// Hysteria's ACL stops at the first match: lines below an all catch
// nothing, and the first all is "everything else".
func TestConvertACLStopsAtAll(t *testing.T) {
	c := geoCtl(t)
	res, err := c.ConvertACL("proxy(all)\ndirect(geosite:ru)\ndirect(all)", "rules", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "geosite:ru") || !strings.HasSuffix(res.Text, "* -> vpn\n") || res.Count != 0 {
		t.Fatalf("%s", res.Text)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "строка 1") {
		t.Fatalf("%v", res.Warnings)
	}
}
