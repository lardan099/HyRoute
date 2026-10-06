package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

func init() {
	backup.DefaultKDF = backup.KDF{Name: "argon2id", Time: 1, MemoryKiB: 8 << 10, Threads: 1}
}

const bkPass = "correct horse"

func exportAll(t *testing.T, c *Controller, password string, keys ...string) []byte {
	t.Helper()
	if keys == nil {
		for _, s := range c.BackupContents(password != "") {
			if s.Available && !s.Empty {
				keys = append(keys, s.Key)
			}
		}
	}
	b, err := c.ExportBackup(BackupExportOptions{Sections: keys, Password: password, Appearance: &BackupAppearance{Theme: "dark", Accent: "violet"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openBk opens b in c and returns the preview.
func openBk(t *testing.T, c *Controller, b []byte, password string) BackupPreview {
	t.Helper()
	t.Cleanup(c.refreshWG.Wait)
	o, err := c.OpenBackup("HyRoute-2026-09-28.hyroute-backup", b)
	if err != nil {
		t.Fatal(err)
	}
	if o.Preview != nil {
		return *o.Preview
	}
	pv, err := c.UnlockBackup(o.Token, password)
	if err != nil {
		t.Fatal(err)
	}
	return pv
}

func replaceAll(pv BackupPreview) BackupChoice {
	ch := BackupChoice{Sections: map[string]string{}}
	for _, s := range pv.Sections {
		if s.Error == "" && len(s.Modes) > 0 {
			ch.Sections[s.Key] = "replace"
		}
	}
	return ch
}

// restore plans and applies ch.
func restore(t *testing.T, c *Controller, pv BackupPreview, ch BackupChoice) (BackupPlan, BackupApplyResult) {
	t.Helper()
	plan, err := c.PlanBackup(pv.Token, ch)
	if err != nil || plan.Error != "" {
		t.Fatalf("%+v %v", plan, err)
	}
	res, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{Theme: "system", Accent: "blue"}, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return plan, res
}

func planTexts(p BackupPlan) string {
	var b strings.Builder
	for _, m := range append(slices.Clone(p.Lines), p.Warnings...) {
		b.WriteString(m.Text + "\n")
	}
	return b.String()
}

func dataFiles(t *testing.T, c *Controller) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range restoreWrites {
		b, err := os.ReadFile(filepath.Join(c.Store.Dir, f))
		if err == nil {
			out[f] = string(b)
		}
	}
	return out
}

// richCtl: servers, a subscription, a group, rules naming them, a LAN
// proxy with a password, prefs.
func richCtl(t *testing.T) (*Controller, string) {
	t.Helper()
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\nhy2://s@sub2.example:443#S2\n"), UserInfo: "upload=1; download=2; total=3"}, nil
	}
	pv, err := c.PreviewSubscription(subURL)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := c.AddSubscription(SubInput{Token: pv.Token, Name: "Provider", Enabled: true, Interval: "12h"})
	if err != nil {
		t.Fatal(err)
	}
	var s1 string
	for _, p := range c.Profiles() {
		if p.Name == "S1" {
			s1 = p.ID
		}
	}
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	setRules(t, c, rules.Tunnel, g, curlRule(s1, de2))
	st := c.Settings()
	on := true
	st.KillSwitch = &on
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "LAN", Port: 21080, LAN: true, Enabled: true, Username: "u", Profile: de1}, Password: "PROXYSECRET77"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "Local", Port: 21081, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	must(t, c.SetGeoPrefs("custom", "https://geo.example/site.dat?token=GEOSECRET55", "https://geo.example/GEOPATHSECRET66/ip.dat", true, 24))
	p := c.Prefs()
	p.AutoConnect, p.SkipVersion = true, "9.9.9"
	must(t, c.SavePrefs(p))
	return c, sv.ID
}

func TestBackupSecretFreeHasNoSecrets(t *testing.T) {
	c, _ := richCtl(t)
	var subInfo BackupSectionInfo
	for _, s := range c.BackupContents(false) {
		if s.Key == "subscriptions" {
			subInfo = s
		}
	}
	if subInfo.Available || !strings.Contains(subInfo.Reason, "нужен пароль") {
		t.Fatalf("%+v", subInfo)
	}
	if _, err := c.ExportBackup(BackupExportOptions{Sections: []string{"subscriptions"}}); !errors.Is(err, backup.ErrSecrets) {
		t.Fatal(err)
	}
	b := exportAll(t, c, "")
	for _, secret := range []string{"SECRETTOKEN123", "anothersecret99", "PROXYSECRET77", "GEOSECRET55", "GEOPATHSECRET66", `"auth": "a"`} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("%s in a secret-free copy:\n%s", secret, b)
		}
	}
	var f struct {
		Payload backup.Payload `json:"payload"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Payload.Sections["subscriptions"]; ok {
		t.Fatal("subscriptions in a secret-free copy")
	}
	if !bytes.Contains(f.Payload.Sections["proxies"], []byte("Local")) || bytes.Contains(f.Payload.Sections["proxies"], []byte("LAN")) {
		t.Fatalf("%s", f.Payload.Sections["proxies"])
	}
	// The references carry names, hosts, ports and the subscription's name.
	found := false
	for _, tg := range f.Payload.Targets {
		if tg.Name == "S1" && tg.Host == "sub1.example" && tg.Sub == "Provider" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", f.Payload.Targets)
	}
}

func TestBackupFullRoundTrip(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass)
	c, _ := newCtl(t)
	var fetched atomic.Int32
	c.Fetch = func(_ context.Context, u string) (FetchResult, error) {
		fetched.Add(1)
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\nhy2://s@sub2.example:443#S2\n")}, nil
	}
	pv := openBk(t, c, b, bkPass)
	if !pv.Secrets || pv.FileName == "" || len(pv.Sections) < 7 {
		t.Fatalf("%+v", pv)
	}
	plan, res := restore(t, c, pv, replaceAll(pv))
	if !strings.Contains(planTexts(plan), "Kill switch: выключен → включён") {
		t.Fatal(planTexts(plan))
	}
	if res.Appearance == nil || res.Appearance.Theme != "dark" || !res.Undo {
		t.Fatalf("%+v", res)
	}
	pa, pc := a.Profiles(), c.Profiles()
	if len(pa) != len(pc) {
		t.Fatalf("%d != %d", len(pa), len(pc))
	}
	for i := range pa {
		x, _ := a.Profile(pa[i].ID)
		y, _ := c.Profile(pc[i].ID)
		if x.ID != y.ID || x.Auth != y.Auth || pa[i].Main != pc[i].Main {
			t.Fatalf("%+v\n%+v", x, y)
		}
	}
	sa, sc := a.Subscriptions(), c.Subscriptions()
	if len(sc) != 1 || sc[0].Name != sa[0].Name || sc[0].Interval != "12h" {
		t.Fatalf("%+v", sc)
	}
	c.mu.Lock()
	url := c.subs[0].URL
	c.mu.Unlock()
	if url != subURL {
		t.Fatal(url)
	}
	if !sameRules(a.Settings().Config, c.Settings().Config) || !settingsOf(c).KillSwitchOn() {
		t.Fatalf("%+v", c.Settings())
	}
	px := c.Proxies()
	if len(px) != 2 || px[0].Name != "LAN" || px[0].Enabled {
		t.Fatalf("LAN proxy must arrive disabled: %+v", px)
	}
	if p := c.Prefs(); !p.AutoConnect || p.SkipVersion != "" || p.GeoSource != "custom" {
		t.Fatalf("%+v", p)
	}
	if got := c.Redactor.Redact("x " + subURL + " PROXYSECRET77"); strings.Contains(got, "SECRETTOKEN123") || strings.Contains(got, "PROXYSECRET77") {
		t.Fatal(got)
	}
	if g := c.Groups(); len(g.Groups) != 1 || len(g.Groups[0].Members) != 2 {
		t.Fatalf("%+v", g)
	}
	waitFor(t, "backup", func() bool { return fetched.Load() == 1 })
}

func TestBackupPlanChanged(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "rules", "settings")
	c, _ := newCtl(t)
	pv := openBk(t, c, b, bkPass)
	ch := replaceAll(pv)
	plan, err := c.PlanBackup(pv.Token, ch)
	if err != nil {
		t.Fatal(err)
	}
	// The kill switch changes meanwhile: the plan reads differently.
	st := c.Settings()
	on := true
	st.KillSwitch = &on
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	files := dataFiles(t, c)
	if _, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{}, plan.Digest); !errors.Is(err, ErrPlanChanged) {
		t.Fatal(err)
	}
	if !mapsEqual(files, dataFiles(t, c)) || c.RestoreUndoInfo().Available {
		t.Fatal("written")
	}
	plan, _ = c.PlanBackup(pv.Token, ch)
	if _, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{}, plan.Digest); err != nil {
		t.Fatal(err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestCommitRestoreRefusedKeepsNoCopy: when the rules step refuses (the
// rules do not compile) nothing is written and no copy of a broken file
// is left behind.
func TestCommitRestoreRefusedKeepsNoCopy(t *testing.T) {
	c, _ := newCtl(t)
	pl := &restorePlan{writes: []string{"profiles.json", "settings.json"}, keepBroken: []string{"profiles.json"}}
	pl.next.Settings = *store.DefaultSettings()
	pl.next.Settings.Rules = []rules.Rule{{Domains: []string{"regexp:("}, Action: rules.Direct}}
	before := map[string]store.RawFile{"profiles.json": {Exists: true, Data: []byte("{broken")}, "settings.json": {}}
	c.mu.Lock()
	_, rbErr, err := c.commitRestoreLocked(pl, before)
	c.mu.Unlock()
	if err == nil || rbErr != nil {
		t.Fatal(err, rbErr)
	}
	ents, _ := os.ReadDir(c.Store.Dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".broken-") || e.Name() == "profiles.json" {
			t.Fatal(e.Name())
		}
	}
}

func TestBackupRollback(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass)
	c, _ := newCtl(t)
	c.Fetch = a.Fetch
	servers(t, c)
	// A previous restore's record stays as it was.
	must(t, c.Store.SaveRestoreUndo([]byte(`{"created":"2026-01-01T00:00:00Z","file":"old","sections":[],"files":{},"subs":[],"orphanSnaps":[]}`)))
	files := dataFiles(t, c)
	profiles := c.Profiles()
	c.restoreWriteHook = func(f string) error {
		if f == "settings.json" {
			return errors.New("disk full")
		}
		return nil
	}
	pv := openBk(t, c, b, bkPass)
	ch := replaceAll(pv)
	plan, _ := c.PlanBackup(pv.Token, ch)
	_, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{}, plan.Digest)
	if err == nil || !strings.Contains(err.Error(), "ничего не изменено") {
		t.Fatal(err)
	}
	if !mapsEqual(files, dataFiles(t, c)) {
		t.Fatal("files changed")
	}
	if got := c.Profiles(); len(got) != len(profiles) {
		t.Fatal("memory changed")
	}
	rec, err := c.Store.LoadRestoreUndo()
	if err != nil || !strings.Contains(string(rec), `"file":"old"`) {
		t.Fatalf("%s %v", rec, err)
	}
	ents, _ := os.ReadDir(c.Store.Dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".broken-") {
			t.Fatal(e.Name())
		}
	}
}

func TestBackupUndo(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "servers", "subscriptions", "rules")
	c, subID := richCtl(t)
	c.Fetch = func(context.Context, string) (FetchResult, error) { return FetchResult{}, errors.New("offline") }
	must(t, c.Store.PushSnapshot(subID, []byte("old body"), nil))
	c.mu.Lock()
	before := slices.Clone(c.subs)
	c.mu.Unlock()
	files := dataFiles(t, c)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	info := c.RestoreUndoInfo()
	if !info.Available || len(info.ChangedSince) != 0 || !slices.Contains(info.Sections, "Серверы") {
		t.Fatalf("%+v", info)
	}
	// An edit after the restore shows up.
	de, _ := c.Profile(c.Profiles()[0].ID)
	de.Name = "Renamed"
	if _, err := c.SaveProfile(de); err != nil {
		t.Fatal(err)
	}
	if info := c.RestoreUndoInfo(); !slices.Contains(info.ChangedSince, "Серверы") {
		t.Fatalf("%+v", info)
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if !mapsEqual(files, dataFiles(t, c)) {
		t.Fatal("files differ after the undo")
	}
	c.mu.Lock()
	after := slices.Clone(c.subs)
	c.mu.Unlock()
	if len(after) != len(before) || after[0].ID != before[0].ID || !after[0].LastUpdate.Equal(before[0].LastUpdate) || after[0].Count != before[0].Count {
		t.Fatalf("%+v\n%+v", before, after)
	}
	if _, err := c.Store.PreviousSnapshot(subID); err != nil && !c.Store.HasPrevious(subID) {
		// the snapshot of the kept subscription is still there
		if _, err := os.Stat(filepath.Join(c.Store.Dir, "subs", subID+".cur")); err != nil {
			t.Fatal("snapshot lost", err)
		}
	}
	if c.RestoreUndoInfo().Available {
		t.Fatal("undo record kept")
	}
	if _, err := c.UndoRestore(); !errors.Is(err, errNothingToUndo) {
		t.Fatal(err)
	}
}

func TestBackupBrokenSettings(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "rules", "settings")
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"defaultAction":"direct","rules":[],"future":1}`), 0o600))
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newCtlAt2(t, st)
	if c.SettingsError() == nil {
		t.Fatal("not broken")
	}
	pv := openBk(t, c, b, bkPass)
	for _, s := range pv.Sections {
		if s.Key == "rules" && (s.Broken == "" || slices.Contains(s.Modes, "add")) {
			t.Fatalf("%+v", s)
		}
	}
	if p, _ := c.PlanBackup(pv.Token, BackupChoice{Sections: map[string]string{"settings": "replace"}}); !strings.Contains(p.Error, "settings.json не загружен") {
		t.Fatalf("%+v", p)
	}
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"rules": "replace", "settings": "replace"}})
	if c.SettingsError() != nil {
		t.Fatal(c.SettingsError())
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "settings.json.broken-*"))
	if len(matches) != 1 {
		t.Fatal(matches)
	}
	if !settingsOf(c).KillSwitchOn() {
		t.Fatal("engine options not restored")
	}
}

func TestBackupSettingsPartial(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "prefs.json"), []byte(`{broken`), 0o600))
	st, _ := store.Open(dir)
	c, _ := newCtlAt2(t, st)
	for _, s := range c.BackupContents(true) {
		if s.Key == "settings" && (!s.Available || !strings.Contains(s.Detail, "prefs.json не загружен")) {
			t.Fatalf("%+v", s)
		}
		if s.Key == "geo" && s.Available {
			t.Fatalf("%+v", s)
		}
	}
	b := exportAll(t, c, "", "settings")
	if bytes.Contains(b, []byte(`"prefs": {`)) || !bytes.Contains(b, []byte(`"engine"`)) {
		t.Fatalf("%s", b)
	}
}

// TestBackupUndoBrokenPrefs: an undo brings a broken file back broken.
func TestBackupUndoBrokenPrefs(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "settings", "geo")
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "prefs.json"), []byte(`{broken`), 0o600))
	st, _ := store.Open(dir)
	c, _ := newCtlAt2(t, st)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	if c.prefsError() != nil {
		t.Fatal("still broken")
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if c.prefsError() == nil {
		t.Fatal("undo did not bring the broken file back")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "prefs.json")); string(got) != "{broken" {
		t.Fatal(string(got))
	}
}

func (c *Controller) prefsError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prefsBroken
}

// B8: a rules restore bumps the revision and moves rulesAt, and calls
// OnSettings once; an engine-only one does not move rulesAt.
func TestBackupRevisions(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "rules", "settings")
	c, _ := newCtl(t)
	servers(t, c)
	var calls atomic.Int32
	c.OnSettings = func(uint64) { calls.Add(1) }
	pv := openBk(t, c, b, bkPass)
	rev := c.SettingsRev()
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"settings": "replace"}})
	c.mu.Lock()
	at := c.rulesAt
	c.mu.Unlock()
	if c.SettingsRev() != rev+1 || at > rev || calls.Load() != 1 {
		t.Fatalf("rev %d→%d rulesAt %d calls %d", rev, c.SettingsRev(), at, calls.Load())
	}
	pv = openBk(t, c, b, bkPass)
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"rules": "replace"}})
	c.mu.Lock()
	at = c.rulesAt
	c.mu.Unlock()
	if at != c.SettingsRev() || calls.Load() != 2 {
		t.Fatalf("rulesAt %d rev %d calls %d", at, c.SettingsRev(), calls.Load())
	}
}

func TestBackupTokenExpiry(t *testing.T) {
	c, _ := newCtl(t)
	servers(t, c)
	b := exportAll(t, c, "", "servers")
	pv := openBk(t, c, b, "")
	c.backupMu.Lock()
	c.backupOpen.at = time.Now().Add(-time.Hour)
	c.backupMu.Unlock()
	if _, err := c.PlanBackup(pv.Token, replaceAll(pv)); !errors.Is(err, errBackupClosed) {
		t.Fatal(err)
	}
	if _, err := c.PlanBackup("nope", replaceAll(pv)); !errors.Is(err, errBackupClosed) {
		t.Fatal(err)
	}
}

func TestBackupRefreshNotChangedSince(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "servers", "subscriptions")
	c, _ := newCtl(t)
	var n atomic.Int32
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		n.Add(1)
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\nhy2://s@sub3.example:443#S3\n")}, nil
	}
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	waitFor(t, "backup", func() bool {
		ps := c.Profiles()
		return slices.ContainsFunc(ps, func(p ProfileSummary) bool { return p.Name == "S3" })
	})
	waitFor(t, "backup", func() bool { return len(c.RestoreUndoInfo().ChangedSince) == 0 })
	// The sealed record got the hashes too.
	rec, _, err := c.loadUndoRecord()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "backup", func() bool {
		rec, _, _ = c.loadUndoRecord()
		return rec.Files["profiles.json"].After == c.fileHash("profiles.json")
	})
	// A UI update afterwards is a change of the user's.
	if _, err := c.UpdateSubscription(c.Subscriptions()[0].ID); err != nil {
		t.Fatal(err)
	}
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://s@sub9.example:443#S9\n")}, nil
	}
	if _, err := c.UpdateSubscription(c.Subscriptions()[0].ID); err != nil {
		t.Fatal(err)
	}
	if info := c.RestoreUndoInfo(); !slices.Contains(info.ChangedSince, "Серверы") {
		t.Fatalf("%+v", info)
	}
}

// TestBackupConcurrentUpdate: a download in progress and a restore do not
// deadlock, and the result is consistent.
func TestBackupConcurrentUpdate(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "servers", "subscriptions", "rules")
	c, subID := richCtl(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\n")}, nil
	}
	var wg sync.WaitGroup
	wg.Go(func() { c.UpdateSubscription(subID) })
	<-started
	pv := openBk(t, c, b, bkPass)
	ch := replaceAll(pv)
	plan, _ := c.PlanBackup(pv.Token, ch)
	done := make(chan error, 1)
	go func() {
		_, err := c.ApplyBackup(pv.Token, ch, BackupAppearance{}, plan.Digest)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if err := <-done; err != nil && !errors.Is(err, ErrPlanChanged) {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.profiles.List {
		if p.Source != "" && !slices.ContainsFunc(c.subs, func(s store.Subscription) bool { return "sub:"+s.ID == p.Source }) {
			t.Fatalf("server %s of a missing subscription", p.Name)
		}
	}
}

// legacyFile writes a backup the way HyRoute 1.2.0 did.
func legacyFile(t *testing.T, kind, password string, payload any) []byte {
	t.Helper()
	data, _ := json.Marshal(payload)
	f := map[string]any{"format": "hyroute-backup", "version": 1, "kind": kind, "created": time.Now().UTC(), "app": "1.2.0"}
	if password == "" {
		f["data"] = json.RawMessage(data)
	} else {
		salt, nonce := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{3}, 12)
		key, _ := pbkdf2.Key(sha256.New, password, salt, 1000, 32)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		f["sealed"] = map[string]any{"kdf": "pbkdf2-sha256", "iter": 1000, "salt": salt, "nonce": nonce,
			"box": gcm.Seal(nil, nonce, data, fmt.Appendf(nil, "hyroute-backup/1/%s", kind))}
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return b
}

// ADDENDUM rule 3: HyRoute 1.2.0 .hyroute files restore as ours; a
// «Только правила» file never carries the kill switch (PITFALLS #3, #8).
func TestBackupLegacyImport(t *testing.T) {
	src, _ := richCtl(t)
	st := src.Settings()
	settingsJSON, _ := json.Marshal(st)
	// v1.2.0's port rule form ("ports": "443") must read too.
	settingsJSON = bytes.Replace(settingsJSON, []byte(`"rules":[`), []byte(`"rules":[{"name":"p","apps":[{"pattern":"x.exe"}],"action":"direct","ports":"80,443"},`), 1)
	src.mu.Lock()
	var subs []map[string]any
	for _, s := range src.subs {
		b, _ := json.Marshal(s)
		m := map[string]any{}
		json.Unmarshal(b, &m)
		m["url"] = s.URL
		subs = append(subs, m)
	}
	profiles := *src.profiles
	var proxies []map[string]any
	for _, p := range src.proxies {
		b, _ := json.Marshal(p)
		m := map[string]any{}
		json.Unmarshal(b, &m)
		m["password"] = p.Password
		proxies = append(proxies, m)
	}
	prefs := src.prefs
	src.mu.Unlock()
	full := legacyFile(t, "full", bkPass, map[string]any{"settings": json.RawMessage(settingsJSON), "profiles": profiles, "subscriptions": subs, "proxies": proxies, "prefs": prefs})

	c, _ := newCtl(t)
	c.Fetch = src.Fetch
	pv := openBk(t, c, full, bkPass)
	if !pv.Legacy || !pv.Secrets {
		t.Fatalf("%+v", pv)
	}
	restore(t, c, pv, replaceAll(pv))
	if len(c.Profiles()) != len(src.Profiles()) || !settingsOf(c).KillSwitchOn() || len(c.Subscriptions()) != 1 || len(c.Settings().Rules) != 2 {
		t.Fatalf("%+v %+v", c.Profiles(), c.Settings())
	}

	// «Только правила» from somebody else: the kill switch stays on here.
	rulesOnly := legacyFile(t, "rules", "", map[string]any{"settings": json.RawMessage(`{"defaultAction":"direct","rules":[],"killSwitch":false,"blockIPv6Tunnel":false}`)})
	pv = openBk(t, c, rulesOnly, "")
	if len(pv.Sections) != 1 || pv.Sections[0].Key != "rules" {
		t.Fatalf("%+v", pv.Sections)
	}
	restore(t, c, pv, replaceAll(pv))
	if s := c.Settings(); !s.KillSwitchOn() || !s.IPv6TunnelBlocked() || len(s.Rules) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestBackupLargestRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("10 000 servers")
	}
	c, _ := newCtl(t)
	name := strings.Repeat("я", importLimits.nameRunes)
	var list []hysteria.Profile
	for i := range 6000 {
		list = append(list, hysteria.Profile{ID: fmt.Sprintf("%012x", i+1), Name: name, Host: fmt.Sprintf("h%d.example", i), Ports: "443", Auth: "x"})
	}
	c.mu.Lock()
	c.profiles = &store.Profiles{Active: list[0].ID, List: list}
	for s := range 100 {
		id := fmt.Sprintf("a%011x", s+1)
		c.subs = append(c.subs, store.Subscription{ID: id, Name: fmt.Sprintf("S%d", s), URL: "https://p.example/" + id, Enabled: false, Interval: "manual"})
	}
	for i := range 4000 {
		sub := fmt.Sprintf("sub:a%011x", i%2+1)
		n := name
		if i == 0 {
			n = strings.Repeat("ж", 300)
		}
		c.profiles.List = append(c.profiles.List, hysteria.Profile{ID: fmt.Sprintf("b%011x", i+1), Name: n, Host: fmt.Sprintf("s%d.example", i), Ports: "443", Source: sub})
	}
	cfg := rules.Config{DefaultAction: rules.Direct}
	for i := range 10000 {
		cfg.Rules = append(cfg.Rules, rules.Rule{Name: name, Apps: []rules.AppMatch{{Pattern: fmt.Sprintf("a%d.exe", i)}}, Action: rules.Block})
	}
	c.settings.Config = cfg
	for i := range 64 {
		c.proxies = append(c.proxies, store.LocalProxy{ID: fmt.Sprintf("c%011x", i+1), Name: name, Port: 20000 + i})
	}
	c.mu.Unlock()
	keys := []string{"servers", "subscriptions", "rules", "proxies"}
	b, err := c.ExportBackup(BackupExportOptions{Sections: keys, Password: bkPass})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := newCtl(t)
	pv := openBk(t, d, b, bkPass)
	for _, s := range pv.Sections {
		if s.Error != "" {
			t.Fatalf("%s: %s", s.Key, s.Error)
		}
	}
	plan, _ := restore(t, d, pv, replaceAll(pv))
	if !strings.Contains(planTexts(plan), "Имена длиннее 200 символов сокращены: 1") {
		t.Fatal(planTexts(plan))
	}
	if len(d.Profiles()) != 10000 || len(d.Settings().Rules) != 10000 {
		t.Fatal(len(d.Profiles()))
	}
	// One more of anything: the export refuses and names the section.
	c.mu.Lock()
	c.profiles.List = append(c.profiles.List, hysteria.Profile{ID: "ffffffffffff", Name: "x", Host: "x.example", Ports: "443"})
	c.mu.Unlock()
	if _, err := c.ExportBackup(BackupExportOptions{Sections: keys, Password: bkPass}); err == nil || !strings.Contains(err.Error(), "Снимите «Подписки»") {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.profiles.List = c.profiles.List[:len(c.profiles.List)-1]
	c.proxies = append(c.proxies, store.LocalProxy{ID: "dddddddddddd", Name: "x", Port: 30000})
	c.mu.Unlock()
	if _, err := c.ExportBackup(BackupExportOptions{Sections: keys, Password: bkPass}); err == nil || !strings.Contains(err.Error(), "Снимите «Прокси»") {
		t.Fatal(err)
	}
}

func settingsOf(c *Controller) *settings.Settings {
	s := c.Settings()
	return &s
}

// Rule profiles and groups travel with «Правила» and «Группы серверов»;
// the result equals a fresh Load of the files written, and the undo puts
// both rules files back byte for byte.
func TestBackupRulesetsAndGroups(t *testing.T) {
	a, _ := newCtl(t)
	de1, de2, _ := servers(t, a)
	g := saveGroup(t, a, "Авто", groups.Latency, de1, de2)
	setRules(t, a, rules.Tunnel, g)
	games := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{curlRule(de2)}}
	rsCreate(t, a, RulesetInput{Name: "Игры", Config: &games})
	b := exportAll(t, a, bkPass, "servers", "groups", "rules")

	c, _ := newCtl(t)
	servers(t, c)
	setRules(t, c, rules.Block, "")
	files := dataFiles(t, c)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	v := c.Rulesets()
	if !v.Saved || len(v.List) != 2 || c.Settings().DefaultProfile != g || len(c.Groups().Groups) != 1 {
		t.Fatalf("%+v %+v", v, c.Settings())
	}
	fresh, _ := newCtlAt2(t, c.Store)
	fv := fresh.Rulesets()
	c.mu.Lock()
	h, lag, marker := c.settingsHash, c.settingsLag, c.rsMarker
	c.mu.Unlock()
	fresh.mu.Lock()
	fh, flag, fmarker := fresh.settingsHash, fresh.settingsLag, fresh.rsMarker
	fresh.mu.Unlock()
	if h != fh || lag != flag || marker != fmarker || fv.Active != v.Active || !sameRules(fresh.Settings().Config, c.Settings().Config) {
		t.Fatalf("install differs from a fresh Load: %v/%v %v/%v %v/%v", h, fh, lag, flag, marker, fmarker)
	}
	if _, err := c.UndoRestore(); err != nil {
		t.Fatal(err)
	}
	if !mapsEqual(files, dataFiles(t, c)) {
		t.Fatal("undo: files differ")
	}
	if c.Rulesets().Saved {
		t.Fatal("rulesets.json came back after the undo")
	}

	// Add: the file's profiles join as new ones, the active one stays.
	pv = openBk(t, c, b, bkPass)
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"servers": "add", "groups": "add", "rules": "add"}})
	v = c.Rulesets()
	if len(v.List) != 3 || c.Settings().DefaultAction != rules.Block {
		t.Fatalf("%+v", v)
	}
	names := []string{}
	for _, e := range v.List {
		names = append(names, e.Name)
	}
	if !slices.Contains(names, "Игры") || len(c.Groups().Groups) != 1 {
		t.Fatalf("%v %+v", names, c.Groups())
	}
}

// TestBackupConnected: a restore while connected acts like an edit: the
// session gets the new rules, and a changed engine option asks for a
// reconnect.
func TestBackupConnected(t *testing.T) {
	a, _ := richCtl(t)
	st := a.Settings()
	off := false
	st.BlockQUIC = &off
	if _, err := a.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	b := exportAll(t, a, bkPass, "servers", "rules", "settings")
	c, started := newCtl(t)
	servers(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	pv := openBk(t, c, b, bkPass)
	_, res := restore(t, c, pv, replaceAll(pv))
	f := (*started)[0]
	if !res.NeedsReconnect || f.set == nil || len(f.profiles) == 0 {
		t.Fatalf("%+v %+v", res, f.profiles)
	}
	c.mu.Lock()
	sameSet := f.set.Main == c.mainTargetLocked()
	c.mu.Unlock()
	if !sameSet {
		t.Fatal("session rules not pushed")
	}
}

// TestBackupRefreshFailedNotChangedSince: the refresh a restore started
// counts as part of it even when it fails (the error is written into
// subscriptions.json): offline, or an answer that does not parse.
func TestBackupRefreshFailedNotChangedSince(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "servers", "subscriptions")
	for name, fetch := range map[string]func(context.Context, string) (FetchResult, error){
		"offline": func(context.Context, string) (FetchResult, error) { return FetchResult{}, errors.New("offline") },
		"garbage": func(context.Context, string) (FetchResult, error) {
			return FetchResult{Body: []byte("<html>no</html>"), UserInfo: "upload=1; download=2; total=3"}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := newCtl(t)
			var n atomic.Int32
			c.Fetch = func(ctx context.Context, u string) (FetchResult, error) { n.Add(1); return fetch(ctx, u) }
			pv := openBk(t, c, b, bkPass)
			restore(t, c, pv, replaceAll(pv))
			c.refreshWG.Wait()
			if n.Load() == 0 || c.Subscriptions()[0].LastError == "" {
				t.Fatalf("no failed refresh: %d %+v", n.Load(), c.Subscriptions())
			}
			if info := c.RestoreUndoInfo(); !info.Available || len(info.ChangedSince) != 0 {
				t.Fatalf("%+v", info)
			}
			rec, _, err := c.loadUndoRecord()
			if err != nil || rec.Files["subscriptions.json"].After != c.fileHash("subscriptions.json") {
				t.Fatal("sealed record not moved", err)
			}
		})
	}
}

// TestBackupUndoInfoDuringRefresh (-race): «Вернуть как было» is read while
// the post-restore refresh moves the record's hashes.
func TestBackupUndoInfoDuringRefresh(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "servers", "subscriptions")
	c, _ := newCtl(t)
	var n atomic.Int32
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		if n.Add(1)%2 == 0 {
			return FetchResult{}, errors.New("offline")
		}
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\nhy2://s@sub4.example:443#S4\n")}, nil
	}
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	done := make(chan struct{})
	go func() {
		c.refreshWG.Wait()
		close(done)
	}()
	for {
		if info := c.RestoreUndoInfo(); len(info.ChangedSince) != 0 {
			t.Fatalf("%+v", info)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

// TestBackupSnapshotsKept: the snapshots of a subscription the restore
// kept survive; those of one it removed live as long as the undo.
func TestBackupSnapshotsKept(t *testing.T) {
	c, subID := richCtl(t)
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://s@sub1.example:443#S1\nhy2://s@sub5.example:443#S5\n")}, nil
	}
	if _, err := c.UpdateSubscription(subID); err != nil {
		t.Fatal(err)
	}
	c.Fetch = func(context.Context, string) (FetchResult, error) { return FetchResult{}, errors.New("offline") }
	if !c.Store.HasPrevious(subID) || !c.Subscriptions()[0].HasPrevious {
		t.Fatal("no previous snapshot to keep")
	}
	own := exportAll(t, c, bkPass, "servers", "subscriptions")
	pv := openBk(t, c, own, bkPass)
	restore(t, c, pv, replaceAll(pv))
	c.refreshWG.Wait()
	if !c.Store.HasPrevious(subID) || !c.Subscriptions()[0].HasPrevious {
		t.Fatalf("same ID and URL: snapshots lost: %v %+v", c.Store.HasPrevious(subID), c.Subscriptions())
	}
	must(t, c.ForgetRestoreUndo())

	// Another computer's subscription replaces this one.
	a, otherID := richCtl(t)
	other := exportAll(t, a, bkPass, "servers", "subscriptions")
	if otherID == subID {
		t.Skip("same random ID")
	}
	pv = openBk(t, c, other, bkPass)
	restore(t, c, pv, replaceAll(pv))
	c.refreshWG.Wait()
	cur := filepath.Join(c.Store.Dir, "subs", subID+".cur")
	if _, err := os.Stat(cur); err != nil || !c.Store.HasPrevious(subID) {
		t.Fatal("removed subscription's snapshots gone before the undo was forgotten", err)
	}
	// An update of the restored subscription meanwhile keeps its own.
	c.Fetch = a.Fetch
	if _, err := c.UpdateSubscription(otherID); err != nil {
		t.Fatal(err)
	}
	must(t, c.ForgetRestoreUndo())
	if _, err := os.Stat(cur); !errors.Is(err, os.ErrNotExist) || c.Store.HasPrevious(subID) {
		t.Fatal("removed subscription's snapshots kept after ForgetRestoreUndo", err)
	}
	if _, err := os.Stat(filepath.Join(c.Store.Dir, "subs", otherID+".cur")); err != nil {
		t.Fatal("restored subscription's snapshot deleted", err)
	}
	if c.RestoreUndoInfo().Available {
		t.Fatal("undo still available")
	}
	if err := c.ForgetRestoreUndo(); err != nil {
		t.Fatal("forget twice:", err)
	}
}

// TestBackupKillSwitch: a restored kill switch is armed at once while
// connected, as after the switch in the UI.
func TestBackupKillSwitch(t *testing.T) {
	a, _ := richCtl(t) // kill switch on
	b := exportAll(t, a, bkPass, "settings")
	c, _ := newCtl(t)
	servers(t, c)
	ks := &fakeKS{}
	c.KillSwitch = ks
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	if ks.blocks {
		t.Fatal("armed before the restore")
	}
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"settings": "replace"}})
	if !ks.blocks || !ks.pass || c.Status().KillSwitch != "armed" {
		t.Fatalf("%+v %q", ks, c.Status().KillSwitch)
	}
}

// TestBackupPokesGeo (PITFALLS #19): a restore of the rules alone wakes the
// geo scheduler (a restored rule may need a database).
func TestBackupPokesGeo(t *testing.T) {
	a, _ := richCtl(t)
	b := exportAll(t, a, bkPass, "rules")
	c, _ := newCtl(t)
	servers(t, c)
	c.geo.poke = make(chan struct{}, 1)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, BackupChoice{Sections: map[string]string{"rules": "replace"}})
	select {
	case <-c.geo.poke:
	default:
		t.Fatal("geo not poked")
	}
}

// TestBackupProbeURLSecretFree: a custom probe address may carry a key: a
// copy without a password drops it (the default is used).
func TestBackupProbeURLSecretFree(t *testing.T) {
	c, _ := richCtl(t)
	must(t, c.SetProbe(groups.Probe{URL: "https://probe.example/PROBESECRET88", IntervalSec: 60}))
	if b := exportAll(t, c, "", "groups"); bytes.Contains(b, []byte("PROBESECRET88")) {
		t.Fatalf("probe URL in a secret-free copy:\n%s", b)
	}
	if b := exportAll(t, c, bkPass, "groups"); len(b) == 0 {
		t.Fatal("empty")
	}
}

// TestBackupLegacyBadSettings: a 1.2.0 full copy whose settings do not
// read loses its rules and engine options only (ADDENDUM rule 3).
func TestBackupLegacyBadSettings(t *testing.T) {
	src, _ := newCtl(t)
	servers(t, src)
	src.mu.Lock()
	profiles := *src.profiles
	src.mu.Unlock()
	full := legacyFile(t, "full", bkPass, map[string]any{"settings": json.RawMessage(`{"defaultAction":"sideways","rules":[]}`), "profiles": profiles})
	c, _ := newCtl(t)
	pv := openBk(t, c, full, bkPass)
	byKey := map[string]BackupSectionPreview{}
	for _, s := range pv.Sections {
		byKey[s.Key] = s
	}
	if e := byKey["rules"].Error; !strings.Contains(e, "1.2.0 не читаются") {
		t.Fatalf("%+v", pv.Sections)
	}
	if e := byKey["settings"].Error; !strings.Contains(e, "1.2.0 не читаются") {
		t.Fatalf("%+v", pv.Sections)
	}
	if s, ok := byKey["servers"]; !ok || s.Error != "" {
		t.Fatalf("%+v", pv.Sections)
	}
	restore(t, c, pv, replaceAll(pv))
	if len(c.Profiles()) != len(src.Profiles()) {
		t.Fatalf("%+v", c.Profiles())
	}
}

// After restoring only «Настройки», a new rule profile (rulesets.json, a
// file of the record) is named: «Вернуть как было» would drop it.
func TestBackupUndoNamesRulesets(t *testing.T) {
	a, _ := richCtl(t)
	setKillSwitch(t, a, false) // the copy differs: the restore writes settings.json
	b := exportAll(t, a, bkPass, "settings")
	c, _ := richCtl(t)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	if info := c.RestoreUndoInfo(); !info.Available || len(info.ChangedSince) != 0 {
		t.Fatalf("%+v", info)
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Игры", From: "active"}, SourceUser); err != nil {
		t.Fatal(err)
	}
	if info := c.RestoreUndoInfo(); !slices.Contains(info.ChangedSince, "Правила") {
		t.Fatalf("%+v", info)
	}
}

// After restoring only «Правила» (settings.json and rulesets.json), the
// kill switch turned off is in settings.json too: «Вернуть как было» puts
// that file back whole, so the undo dialog names «Настройки» as well.
func TestBackupUndoNamesSharedFiles(t *testing.T) {
	a, _ := richCtl(t)
	if _, _, err := a.ApplyRulesText("x.example -> блок", false, EditGuard{}); err != nil {
		t.Fatal(err) // the copy's rules differ: the restore writes them
	}
	b := exportAll(t, a, bkPass, "rules")
	c, _ := richCtl(t)
	pv := openBk(t, c, b, bkPass)
	restore(t, c, pv, replaceAll(pv))
	if info := c.RestoreUndoInfo(); !info.Available || len(info.ChangedSince) != 0 {
		t.Fatalf("%+v", info)
	}
	setKillSwitch(t, c, false) // richCtl turns it on
	if info := c.RestoreUndoInfo(); !slices.Contains(info.ChangedSince, "Настройки") {
		t.Fatalf("%+v", info)
	}
}
