package app

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

func init() { backupIter = 1000 }

func TestBackupFullRoundTrip(t *testing.T) {
	a, _ := newCtl(t)
	res, err := a.ImportURIs(link + "\nhy2://secret2@h2.example:8443#NL")
	if err != nil || len(res.Added) != 2 {
		t.Fatal(res, err)
	}
	nl := res.Added[1].ID
	st := a.Settings()
	st.Rules = []rules.Rule{{Name: "ssh", Apps: []rules.AppMatch{{Pattern: "ssh.exe"}}, Ports: rules.PortList{"22"}, Action: rules.Tunnel, Profile: nl}}
	if _, err := a.SaveRulesIn(EditGuard{}, st.Config); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "bot", Enabled: true, Port: freePort(t), Username: "u"}, Password: "proxy-pass"}); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Backup(true, "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	b, err := a.Backup(true, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	// Nothing secret in the clear.
	for _, s := range []string{"secret2", "proxy-pass", "h2.example", "ssh.exe", "pass"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("%q in the backup:\n%s", s, b)
		}
	}

	c, _ := newCtl(t)
	info, err := c.InspectBackup(b)
	if err != nil || info.Kind != "full" || !info.Encrypted || info.Rules != -1 {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := c.RestoreBackup(b, "wrong password"); err == nil || !strings.Contains(err.Error(), "пароль") {
		t.Fatal(err)
	}
	if _, err := c.RestoreBackup(b, ""); err == nil {
		t.Fatal("restored without a password")
	}
	tampered := bytes.Replace(b, []byte(`"kind": "full"`), []byte(`"kind": "rules"`), 1)
	if _, err := c.RestoreBackup(tampered, "correct horse"); err == nil {
		t.Fatal("a changed header was accepted")
	}
	r, err := c.RestoreBackup(b, "correct horse")
	if err != nil || r.Profiles != 2 || r.Rules != 1 || r.Proxies != 1 || r.Remapped != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	ps := c.Profiles()
	if len(ps) != 2 || ps[1].ID != nl {
		t.Fatalf("%+v", ps)
	}
	c.mu.Lock()
	auth := c.profiles.List[1].Auth
	proxyPass := c.proxies[0].Password
	c.mu.Unlock()
	if auth != "secret2" || proxyPass != "proxy-pass" {
		t.Fatalf("secrets: %q %q", auth, proxyPass)
	}
	if got := c.Settings().Rules; len(got) != 1 || got[0].Profile != nl || !slices.Equal(got[0].Ports, rules.PortList{"22"}) {
		t.Fatalf("%+v", got)
	}

	// Restored files load again (sealed on this computer).
	c2, _ := newCtlAt(t, c.Store)
	if len(c2.Profiles()) != 2 {
		t.Fatal("not saved")
	}

	// Not while connected.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestoreBackup(b, "correct horse"); err == nil || !strings.Contains(err.Error(), "отключите") {
		t.Fatal(err)
	}
	c.Disconnect()
}

func TestBackupRulesOnly(t *testing.T) {
	a, _ := newCtl(t)
	res, err := a.ImportURIs(link)
	if err != nil || len(res.Added) != 1 {
		t.Fatal(res, err)
	}
	de := res.Added[0].ID
	st := a.Settings()
	st.DefaultAction, st.DefaultProfile = rules.Tunnel, de
	st.Rules = []rules.Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: rules.Tunnel, Profile: de, Fallback: []string{""}},
		{Name: "ru", Domains: []string{"geoip:ru"}, Action: rules.Direct},
	}
	if _, err := a.SaveRulesIn(EditGuard{}, st.Config); err != nil {
		t.Fatal(err)
	}
	b, err := a.Backup(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("user:pass")) || bytes.Contains(b, []byte("example.com:443")) {
		t.Fatalf("secrets in a rules backup:\n%s", b)
	}

	c, _ := newCtl(t)
	info, err := c.InspectBackup(b)
	if err != nil || info.Kind != "rules" || info.Encrypted || info.Rules != 2 {
		t.Fatalf("%+v %v", info, err)
	}
	r, err := c.RestoreBackup(b, "")
	if err != nil || r.Rules != 2 || r.Remapped != 2 || r.Profiles != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	got := c.Settings()
	if got.Rules[0].Profile != "" || len(got.Rules[0].Fallback) != 1 || got.DefaultProfile != "" || got.DefaultAction != rules.Tunnel {
		t.Fatalf("%+v", got)
	}

	for _, bad := range []string{"", "{}", `{"format":"hyroute-backup","version":99,"kind":"rules","data":{}}`, "not json"} {
		if _, err := c.InspectBackup([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// A rules-only copy made by v1.2.0 whose rule has a port list of
// separators only (its editor saved one) restores, the rule for any port
// as v1.2.0 ran it.
func TestBackupV120SeparatorPorts(t *testing.T) {
	b := []byte(`{"format":"hyroute-backup","version":1,"kind":"rules","created":"2026-09-20T10:00:00Z","app":"1.2.0","data":{"settings":
		{"defaultAction":"direct","rules":[{"name":"Sep","apps":[{"pattern":"chrome.exe"}],"ports":",","action":"block"}]}}}`)
	c, _ := newCtl(t)
	if info, err := c.InspectBackup(b); err != nil || info.Rules != 1 {
		t.Fatalf("%+v %v", info, err)
	}
	if r, err := c.RestoreBackup(b, ""); err != nil || r.Rules != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if got := c.Settings(); len(got.Rules) != 1 || got.Rules[0].Ports != nil {
		t.Fatalf("%+v", got.Rules)
	}
	if bytes.Contains(settingsBytes(t, c), []byte(`"ports"`)) {
		t.Fatal("ports written back")
	}
}
