package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/rules"
)

func geoRules(t *testing.T, c *Controller, domains ...string) {
	t.Helper()
	s := c.Settings()
	s.Rules = []rules.Rule{{Name: "Списки", Domains: domains, Action: rules.Direct}}
	if _, err := c.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
}

func geoWriteState(t *testing.T, c *Controller, st geodata.State) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.geo.db.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.geo.db.Dir, "geo.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGeoDue(t *testing.T) {
	c, _ := newCtl(t)
	if err := c.SetGeoPrefs("v2fly", "", "", false, 12); err != nil {
		t.Fatal(err)
	}
	v2, _ := geodata.FindSource("v2fly")
	rf, _ := geodata.FindSource("runetfreedom")
	file := func(url string) *geodata.FileState { return &geodata.FileState{SHA256: "ab", URL: url} }
	due := func(want bool, site, ip string) {
		t.Helper()
		src, ok := c.geoDue()
		if ok != want || (ok && (src.Site != site || src.IP != ip)) {
			t.Fatalf("due %v %+v, want %v site %q ip %q", ok, src, want, site, ip)
		}
	}

	geoRules(t, c, "example.com", "geoip:private")
	due(false, "", "")

	// Only geoip: rules: geosite.dat is not downloaded.
	geoRules(t, c, "geoip:ru")
	due(true, "", v2.IP)
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: file(v2.IP), Checked: time.Now()})
	due(false, "", "")

	// A failed switch from runetfreedom recorded the new source, but the
	// file is still the old one.
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: file(rf.IP), Checked: time.Now()})
	due(true, "", v2.IP)
	// But a file of runetfreedom the user rolled back to is kept.
	held := file(rf.IP)
	held.HeldFor, held.RolledBackFrom = v2.IP, "cd"
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: held, Checked: time.Now()})
	due(false, "", "")

	// An unused file left from another source is replaced once.
	geoWriteState(t, c, geodata.State{Source: "v2fly", Site: file(rf.Site), IP: file(v2.IP), Checked: time.Now()})
	due(true, v2.Site, v2.IP)
	geoWriteState(t, c, geodata.State{Source: "v2fly", Site: file(v2.Site), IP: file(v2.IP), Checked: time.Now()})
	due(false, "", "")

	// Auto-update refreshes only the database the rules use.
	if err := c.SetGeoPrefs("v2fly", "", "", true, 12); err != nil {
		t.Fatal(err)
	}
	geoWriteState(t, c, geodata.State{Source: "v2fly", Site: file(v2.Site), IP: file(v2.IP), Checked: time.Now().Add(-13 * time.Hour)})
	due(true, "", v2.IP)
	// A failed update is retried before the interval (with back-off).
	geoWriteState(t, c, geodata.State{Source: "v2fly", Site: file(v2.Site), IP: file(v2.IP), Checked: time.Now(), LastError: "geoip.dat: 502"})
	due(true, "", v2.IP)

	// New custom links are downloaded although the source stays "custom".
	const site = "https://b.example/geosite.dat"
	if err := c.SetGeoPrefs("custom", site, "", false, 12); err != nil {
		t.Fatal(err)
	}
	geoRules(t, c, "geosite:youtube")
	geoWriteState(t, c, geodata.State{Source: "custom", Site: file("https://a.example/geosite.dat"), Checked: time.Now()})
	due(true, site, "")
	geoWriteState(t, c, geodata.State{Source: "custom", Site: file(site), Checked: time.Now()})
	due(false, "", "")
}

func TestGeoPopularFollowsFiles(t *testing.T) {
	c := geoCtl(t)
	if err := c.SetGeoPrefs("v2fly", "", "", false, 12); err != nil {
		t.Fatal(err)
	}
	v2, _ := geodata.FindSource("v2fly")
	// geoip.dat (with "telegram") is still the file of another source:
	// the preset list decides, and v2fly has no geoip:telegram.
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: &geodata.FileState{SHA256: "ab", URL: "https://other.example/geoip.dat"}})
	in := func() *bool {
		for _, p := range c.GeoInfo().Popular {
			if p.Kind == "ip" && p.Name == "telegram" {
				return p.InSource
			}
		}
		t.Fatal("geoip:telegram is not popular")
		return nil
	}
	if v := in(); v == nil || *v {
		t.Fatalf("file of another source counted: %v", v)
	}
	geoWriteState(t, c, geodata.State{Source: "v2fly", IP: &geodata.FileState{SHA256: "ab", URL: v2.IP}})
	if v := in(); v == nil || !*v {
		t.Fatalf("downloaded file ignored: %v", v)
	}
}

func TestGeoLinksHTTPS(t *testing.T) {
	c, _ := newCtl(t)
	if err := c.SetGeoPrefs("custom", "http://a.example/geosite.dat", "", true, 12); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("http accepted: %v", err)
	}
	// Links saved by an older version are not downloaded either, and the
	// settings say why.
	p := c.Prefs()
	p.GeoSource, p.GeoSiteURL = "custom", "http://a.example/geosite.dat"
	if err := c.SavePrefs(p); err != nil {
		t.Fatal(err)
	}
	geoRules(t, c, "geosite:youtube")
	if _, due := c.geoDue(); due {
		t.Fatal("http link scheduled")
	}
	if info := c.GeoInfo(); !strings.Contains(info.Error, "https://") {
		t.Fatalf("%+v", info)
	}
	if _, err := c.UpdateGeo(context.Background(), false); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("http downloaded: %v", err)
	}
	if info := c.GeoInfo(); info.Busy {
		t.Fatalf("%+v", info)
	}
}
