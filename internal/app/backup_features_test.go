package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

// The backup sections of the features that landed with or after it: «Сети»
// (netmodes), «DNS», «Статистика» (stats), the cli prefs key, conn-rules'
// undo list and socks-udp's proxy field.

// A copy restores the prefs but never hyroutectl's access: a copy made with
// «Полный доступ» leaves this computer's choice (the default «Только
// просмотр», or «Выключено») as it is, and a broken prefs.json it repairs
// reads as off.
func TestBackupKeepsCLIMode(t *testing.T) {
	a, _ := newCtl(t)
	if err := a.UpdatePrefs(func(p *store.Prefs) error { p.CLI, p.UpdateCheck = "full", "manual"; return nil }); err != nil {
		t.Fatal(err)
	}
	if plain := exportAll(t, a, "", "settings"); bytes.Contains(plain, []byte(`"cli"`)) {
		t.Fatalf("cli in a copy:\n%s", plain)
	}
	b := exportAll(t, a, bkPass, "settings")
	for _, cur := range []string{"", "off"} {
		c, _ := newCtl(t)
		if err := c.UpdatePrefs(func(p *store.Prefs) error { p.CLI = cur; return nil }); err != nil {
			t.Fatal(err)
		}
		want, _ := c.CLIMode()
		pv := openBk(t, c, b, bkPass)
		restore(t, c, pv, replaceAll(pv))
		c2, _ := newCtlAt(t, c.Store)
		for _, x := range []*Controller{c, c2} {
			if mode, _ := x.CLIMode(); mode != want || x.Prefs().UpdateCheck != "manual" {
				t.Fatalf("%q: %q %+v", cur, mode, x.Prefs())
			}
		}
	}
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "prefs.json"), []byte(`{broken`), 0o600))
	st, _ := store.Open(dir)
	c, _ := newCtlAt2(t, st)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	if mode, err := c.CLIMode(); mode != "off" || err != nil || c.Prefs().UpdateCheck != "manual" {
		t.Fatalf("%q %v %+v", mode, err, c.Prefs())
	}
}

// TestBackupHoldsPrefsMu: the prefs write runs under prefsMu, so no
// UpdatePrefs (SetCLIMode, SkipAppVersion, SetGeoPrefs) is lost or undoes
// the restore.
func TestBackupHoldsPrefsMu(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "settings")
	c, _ := newCtl(t)
	var seen, held atomic.Bool
	c.restoreWriteHook = func(f string) error {
		if f == "prefs.json" {
			seen.Store(true)
			held.Store(!free(&c.prefsMu))
		}
		return nil
	}
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	if !seen.Load() || !held.Load() {
		t.Fatalf("prefs.json written: %v, under prefsMu: %v", seen.Load(), held.Load())
	}
	if !free(&c.prefsMu) {
		t.Fatal("prefsMu left locked")
	}
}

// TestBackupNetworksAndDNS: «Сети» and «DNS» travel (the custom DNS server
// only with a password), install as a fresh Load reads them, and the undo
// puts both files back.
func TestBackupNetworksAndDNS(t *testing.T) {
	const dnsURL = "https://dns.example/DNSSECRET42/dns-query"
	a, _ := newCtl(t)
	must(t, a.SaveDNS(dnspolicy.Config{ByRules: true, BlockBrowserDoH: true, Tunnel: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: dnsURL}}))
	if _, err := a.SaveNetModes(netCfg(netmode.Connect, netRule("Дом", netmode.Match{SSIDs: []string{"HomeWiFi"}}, netmode.Disconnect))); err != nil {
		t.Fatal(err)
	}
	for _, s := range a.BackupContents(false) {
		if s.Key == "dns" && (!s.Available || !strings.Contains(s.Detail, "свой DNS-сервер не сохранится")) {
			t.Fatalf("%+v", s)
		}
		if s.Key == "networks" && (s.Empty || s.Detail != "1 правило сетей, выключены") {
			t.Fatalf("%+v", s)
		}
	}
	plain := exportAll(t, a, "", "networks", "dns")
	if bytes.Contains(plain, []byte("DNSSECRET42")) || bytes.Contains(plain, []byte("dns.example")) || !bytes.Contains(plain, []byte("HomeWiFi")) {
		t.Fatalf("%s", plain)
	}
	b := exportAll(t, a, bkPass, "networks", "dns")

	c, _ := newCtl(t)
	files := dataFiles(t, c)
	pv := openBk(t, c, b, bkPass)
	plan, _ := restore(t, c, pv, replaceAll(pv))
	if tx := planTexts(plan); !strings.Contains(tx, "Сеть «Дом» (Wi-Fi «HomeWiFi»): отключиться (всё напрямую).") ||
		!strings.Contains(tx, "DNS по правилам: нет → да.") || strings.Contains(tx, "DNSSECRET42") {
		t.Fatal(tx)
	}
	want, _ := a.DNSConfig()
	fresh, _ := newCtlAt(t, c.Store)
	for _, x := range []*Controller{c, fresh} {
		if got, err := x.DNSConfig(); err != nil || got != want {
			t.Fatalf("%+v %v", got, err)
		}
		if v := x.NetModes(false); v.LoadError != "" || len(v.Config.Rules) != 1 || v.Config.Rules[0].Name != "Дом" || v.Config.Rules[0].Connect != netmode.Disconnect {
			t.Fatalf("%+v", v.Config)
		}
	}
	if got := c.Redactor.Redact("x " + dnsURL); strings.Contains(got, "DNSSECRET42") {
		t.Fatal(got)
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if !mapsEqual(files, dataFiles(t, c)) {
		t.Fatal("undo: files differ")
	}
	if got, _ := c.DNSConfig(); got != (dnspolicy.Config{}) || len(c.NetModes(false).Config.Rules) != 0 {
		t.Fatalf("%+v %+v", got, c.NetModes(false).Config)
	}
}

// TestBackupUndoBrokenNetworks: «Заменить» repairs a broken networks.json
// (a copy of it kept); the undo brings it back broken, with its error.
func TestBackupUndoBrokenNetworks(t *testing.T) {
	a, _ := newCtl(t)
	if _, err := a.SaveNetModes(netCfg(netmode.Connect, netRule("Кафе", netmode.Match{Names: []string{"cafe"}}, netmode.Connect))); err != nil {
		t.Fatal(err)
	}
	b := exportAll(t, a, bkPass, "networks")
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "networks.json"), []byte(`{broken`), 0o600))
	st, _ := store.Open(dir)
	c, _ := newCtlAt2(t, st)
	if c.NetModes(false).LoadError == "" {
		t.Fatal("not broken")
	}
	pv := openBk(t, c, b, bkPass)
	for _, s := range pv.Sections {
		if s.Key == "networks" && (s.Broken == "" || len(s.Modes) != 1) {
			t.Fatalf("%+v", s)
		}
	}
	restore(t, c, pv, replaceAll(pv))
	if v := c.NetModes(false); v.LoadError != "" || len(v.Config.Rules) != 1 {
		t.Fatalf("%+v", v)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "networks.json.broken-*")); len(m) != 1 {
		t.Fatal(m)
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if c.NetModes(false).LoadError == "" {
		t.Fatal("undo did not bring the broken file back")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "networks.json")); string(got) != "{broken" {
		t.Fatal(string(got))
	}
}

// TestBackupDNSConnected (dns): while connected, restored rules flush the
// Windows DNS cache once when «DNS по правилам» is on; restored DNS
// settings reach the session and flush it; a session that refuses them is
// a warning of the result, not a failure.
func TestBackupDNSConnected(t *testing.T) {
	a, _ := newCtl(t)
	if _, err := a.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{{Name: "x", Domains: []string{"x.example"}, Action: rules.Direct}}}); err != nil {
		t.Fatal(err)
	}
	must(t, a.SaveDNS(dnspolicy.Config{ByRules: true, BlockBrowserDoH: true}))
	b := exportAll(t, a, bkPass, "rules", "dns")

	d := newDNSCtl(t, nil)
	if _, err := d.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	must(t, d.SaveDNS(dnspolicy.Config{ByRules: true}))
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	defer d.Disconnect()
	d.waitFlushes(t, 1)
	pv := openBk(t, d.Controller, b, bkPass)
	restore(t, d.Controller, pv, BackupChoice{Sections: map[string]string{"rules": "replace"}})
	d.waitFlushes(t, 2)

	pv = openBk(t, d.Controller, b, bkPass)
	_, res := restore(t, d.Controller, pv, BackupChoice{Sections: map[string]string{"dns": "replace"}})
	if p := d.sess().lastPol(); p == nil || !p.Cfg.BlockBrowserDoH || len(res.Warnings) != 0 {
		t.Fatalf("not pushed: %+v %+v", p, res)
	}
	d.waitFlushes(t, 3)

	d.sess().setErr = errors.New("filter swap failed")
	res, err := d.UndoRestore()
	d.sess().setErr = nil
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Text, "Настройки DNS восстановлены, но не применены") {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := d.DNSConfig(); got.BlockBrowserDoH {
		t.Fatalf("%+v", got)
	}
	d.waitFlushes(t, 4)
}

// TestBackupStats (B1b): «Статистика» needs a password, is off by default,
// replaces the statistics after the restore (the stats functions run with
// no Controller lock held) and comes back with «Вернуть как было». A
// section the stats store refuses is a plan error: nothing is written.
func TestBackupStats(t *testing.T) {
	a, started, de := statsCtl(t)
	defer a.Disconnect()
	openFlow((*started)[0].reg, `C:\a.exe`, "tunnel", de, "relayed").Sent.Add(10)
	a.sampleStats(time.Now(), false)
	for _, s := range a.BackupContents(false) {
		if s.Key == "stats" && (s.Available || !strings.Contains(s.Reason, "нужен пароль")) {
			t.Fatalf("%+v", s)
		}
	}
	if _, err := a.ExportBackup(BackupExportOptions{Sections: []string{"stats"}}); !errors.Is(err, backup.ErrSecrets) {
		t.Fatal(err)
	}
	for _, s := range a.BackupContents(true) {
		if s.Key == "stats" && (!s.Available || s.Empty || s.Default) {
			t.Fatalf("%+v", s)
		}
	}
	b := exportAll(t, a, bkPass, "stats")

	c, _ := newCtl(t)
	var calls, locked atomic.Int32
	c.statsUnlocked = func() {
		calls.Add(1)
		for _, m := range []*sync.Mutex{&c.mu, &c.saveMu, &c.lifeMu, &c.prefsMu} {
			if !free(m) {
				locked.Add(1)
			}
		}
	}
	if _, empty := c.StatsBackupInfo(); !empty {
		t.Fatal("not empty before")
	}
	pv := openBk(t, c, b, bkPass)
	if s := pv.Sections[0]; s.Key != "stats" || s.Default || s.Error != "" || !strings.Contains(s.Detail, "сбор") {
		t.Fatalf("%+v", pv.Sections)
	}
	_, res := restore(t, c, pv, BackupChoice{Sections: map[string]string{"stats": "replace"}})
	if len(res.Warnings) != 0 || !res.Undo {
		t.Fatalf("%+v", res)
	}
	if _, empty := c.StatsBackupInfo(); empty {
		t.Fatal("not restored")
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if _, empty := c.StatsBackupInfo(); !empty {
		t.Fatal("undo did not bring the statistics back")
	}
	if calls.Load() == 0 || locked.Load() != 0 {
		t.Fatalf("calls %d, with a lock held %d", calls.Load(), locked.Load())
	}

	bad, err := backup.Encode(&backup.Payload{App: "1.3.0", Created: time.Now().UTC().Truncate(time.Second), Secrets: true,
		Sections: map[string]json.RawMessage{"stats": json.RawMessage(`"x"`)}}, bkPass)
	if err != nil {
		t.Fatal(err)
	}
	files := dataFiles(t, c)
	pv = openBk(t, c, bad, bkPass)
	if pv.Sections[0].Error == "" {
		t.Fatalf("%+v", pv.Sections)
	}
	ch := BackupChoice{Sections: map[string]string{"stats": "replace"}}
	if p, _ := c.PlanBackup(pv.Token, ch); !strings.Contains(p.Error, "«Статистика»") {
		t.Fatalf("%+v", p)
	}
	if _, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{}, "x"); err == nil {
		t.Fatal("applied")
	}
	if !mapsEqual(files, dataFiles(t, c)) || c.RestoreUndoInfo().Available {
		t.Fatal("written")
	}
}

// TestBackupClearsConnUndo (conn-rules): «Отменить» of a rule made from a
// connection before a restore of the rules no longer acts.
func TestBackupClearsConnUndo(t *testing.T) {
	c, s, _, _ := connCtl(t)
	b := exportAll(t, c, "", "rules")
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), appRule("x.exe", rules.Block)))
	if err != nil {
		t.Fatal(err)
	}
	pv := openBk(t, c, b, "")
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"rules": "replace"}})
	if err := c.UndoConnRule(res.Undo); !errors.Is(err, errUndoGone) {
		t.Fatal(err)
	}
}

// TestBackupLegacyProxyUDP (socks-udp, ADDENDUM rule 3): a LAN proxy of a
// HyRoute 1.2.0 copy keeps the UDP it had there.
func TestBackupLegacyProxyUDP(t *testing.T) {
	proxies := []map[string]any{{"id": "aaaaaaaa0001", "name": "LAN", "enabled": true, "profile": "", "port": 21080, "lan": true, "username": "u", "password": "p"},
		{"id": "aaaaaaaa0002", "name": "Local", "enabled": true, "profile": "", "port": 21081, "lan": false, "username": "", "password": ""}}
	full := legacyFile(t, "full", bkPass, map[string]any{"settings": json.RawMessage(`{"defaultAction":"direct","rules":[]}`), "proxies": proxies})
	c, _ := newCtl(t)
	pv := openBk(t, c, full, bkPass)
	restore(t, c, pv, replaceAll(pv))
	px := c.Proxies()
	if len(px) != 2 || px[0].UDP != "on" || !px[0].UDPOn() || px[0].Enabled || px[1].UDP != "" || !px[1].UDPOn() {
		t.Fatalf("%+v", px)
	}
}

// With rulesets.json not loaded only the active rules go into a copy:
// «Правила» says the other rule profiles stay out.
func TestBackupContentsBrokenRulesets(t *testing.T) {
	c, _ := newCtl(t)
	must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), []byte("{"), 0o600))
	c, _ = newCtlAt2(t, c.Store)
	found := false
	for _, s := range c.BackupContents(false) {
		if s.Key == "rules" {
			found = true
			if !strings.Contains(s.Detail, "rulesets.json не загружен") {
				t.Fatalf("%+v", s)
			}
		}
	}
	if !found {
		t.Fatal("no «Правила» section")
	}
}
