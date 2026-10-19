package events

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// The summary has every kind of item, the worst first, and no secret or
// address in any text.
func TestAttention(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{4}, 32)})
	f.red.Add("canary-attention-pass")
	now := f.clock.now()

	mk := func(name, host string, state model.ServerState) model.Server {
		s := f.server(t, name, host)
		f.db.SetServerState(ctx, s.ID, state, now)
		s.State = state
		return s
	}
	healthy := mk("Healthy", "198.51.100.1", model.StateHealthy)
	down := mk("Down", "198.51.100.2", model.StateOffline)
	sick := mk("Sick", "sick.example.com", model.StateDegraded)
	stuck := mk("Stuck", "198.51.100.4", model.StateNeedsAttention)
	fresh := mk("Fresh", "198.51.100.5", model.StateNew)
	exit := mk("Exit", "198.51.100.6", model.StateHealthy)

	f.db.AddHealth(ctx, model.Health{ServerID: down.ID, At: now, Status: model.StateOffline, Reason: "SSH не отвечает; UDP 443 тоже не отвечает."})
	f.db.AddHealth(ctx, model.Health{ServerID: sick.ID, At: now, Status: model.StateDegraded, Reason: "Проверка UDP 443 не удалась: dial udp 198.51.100.3:443: canary-attention-pass."})

	// Healthy: an old Hysteria, duplicate rules, old geo databases.
	f.db.SetInstallation(ctx, model.Installation{ServerID: healthy.ID, Binary: "/usr/local/bin/hysteria", Unit: "hysteria-server.service", Version: "v2.6.0", At: now})
	cfg := "listen: :443\nauth:\n  type: password\n  password: canary-attention-pass\nacl:\n  inline:\n    - direct(suffix:example.com)\n    - direct(suffix:example.com)\n"
	c := model.ServerConfig{ServerID: healthy.ID, SHA256: "x", Source: model.ConfigDeploy, At: now}
	if err := f.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(healthy.ID, rev)) }); err != nil {
		t.Fatal(err)
	}
	f.db.SetServerGeo(ctx, model.ServerGeo{ServerID: healthy.ID, Release: "202608010000", GeoIP: "a", GeoSite: "b", At: now})
	dir := t.TempDir()
	info, _ := json.Marshal(geo.Info{Release: "202609010000", At: now.Add(-30 * 24 * time.Hour), CheckedAt: now.Add(-30 * 24 * time.Hour)})
	os.WriteFile(filepath.Join(dir, "info.json"), info, 0o600)

	// Down: the newest job failed. Stuck: an older failed job, then one
	// that completed.
	job := func(srv int64, kind string, state model.JobState, msg string) {
		j := model.Job{Kind: kind, ServerID: srv, State: state, Params: []byte("{}"), ErrorMessage: msg, CreatedAt: now, FinishedAt: now}
		if err := f.db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	job(stuck.ID, "apply", model.JobFailed, "old")
	job(stuck.ID, "service", model.JobCompleted, "")
	job(down.ID, "deploy", model.JobFailed, "Не удалось скачать Hysteria с https://github.com/apernet/hysteria.")

	// A stale link and a link whose check found it offline.
	chain := func(name string, a, b int64, state model.LinkState) model.Chain {
		ch := &model.Chain{Name: name, Nodes: []int64{a, b}, Links: []model.ChainLink{{Params: []byte("{}")}}, CreatedAt: now, UpdatedAt: now}
		if err := f.db.CreateChain(ctx, ch, nil); err != nil {
			t.Fatal(err)
		}
		l := ch.Links[0]
		l.State = state
		if err := f.db.UpdateLink(ctx, l); err != nil {
			t.Fatal(err)
		}
		return *ch
	}
	chain("Старый", sick.ID, exit.ID, model.LinkStale)
	broken := chain("Сломан", healthy.ID, exit.ID, model.LinkActive)
	f.db.AddLinkCheck(ctx, model.LinkCheck{ChainID: broken.ID, Idx: 0, At: now, Status: model.StateOffline, Reason: "сервер выхода не открывает 198.51.100.6:22"})

	// Open events: a changed host key, a full disk, the network.
	w := &Watcher{Bus: f.bus}
	w.SSH(ctx, fresh.ID, nil)
	f.bus.Raise(ctx, model.Event{Kind: model.EventHostKey, Key: "host_key:5", Severity: model.SeverityCritical, Subject: model.SubjectServer, SubjectID: fresh.ID, Text: "Ключ сменился"})
	w.Disk(ctx, exit, 95, 100)
	w.Network(ctx, false)

	a := &Attention{Store: f.db, Keys: keys, Redact: f.red, Geo: &geo.Store{Dir: dir}, GeoInterval: 7 * 24 * time.Hour, Monitoring: true, Now: f.clock.now,
		Paused: func() map[int64]time.Time { return map[int64]time.Time{sick.ID: now.Add(time.Hour)} }}
	sum, err := a.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Network == nil || sum.Network.Kind != model.EventNetwork || !sum.Monitoring {
		t.Fatalf("network %+v", sum.Network)
	}
	want := map[string]bool{
		"server/Down": false, "server/Sick": false, "server/Stuck": false, "server/Fresh": false,
		"job/Down": false, "link/Старый": false, "link/Сломан": false, "lint/Healthy": false, "hysteria/Healthy": false,
		"geo/Healthy": false, "geo/": false, "monitor/Sick": false, "host_key/Fresh": false, "disk/Exit": false,
	}
	last := -1
	for _, it := range sum.Items {
		k := it.Kind + "/" + it.Name
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected item %+v", it)
		}
		want[k] = true
		if r := severityRank[it.Severity]; r < last {
			t.Errorf("not sorted by severity: %+v", sum.Items)
		} else {
			last = r
		}
		for _, bad := range []string{"198.51.100", "sick.example.com", "canary-attention-pass", "github.com"} {
			if strings.Contains(it.Text, bad) {
				t.Errorf("%q in %+v", bad, it)
			}
		}
		if it.Kind == "job" && it.Subject != model.SubjectJob {
			t.Errorf("job item %+v", it)
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("no item %s in %+v", k, sum.Items)
		}
	}
	if sum.Items[0].Severity != model.SeverityCritical {
		t.Errorf("first %+v", sum.Items[0])
	}

	// Monitoring off is an item; nothing paused then.
	a.Monitoring, a.Paused = false, nil
	sum, _ = a.Summary(ctx)
	found := false
	for _, it := range sum.Items {
		found = found || it.Kind == "monitor" && it.Subject == model.SubjectController
	}
	if !found {
		t.Fatalf("monitoring off: %+v", sum.Items)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{1: "1 ошибка", 2: "2 ошибки", 5: "5 ошибок", 11: "11 ошибок", 12: "12 ошибок", 21: "21 ошибка", 22: "22 ошибки", 111: "111 ошибок"} {
		if got := plural(n, "ошибка", "ошибки", "ошибок"); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

// Old Hysteria is old against the newest release the controller found
// (P4-07), or against the default version while it knows none newer.
func TestAttentionLatestRelease(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	now := f.clock.now()
	s := f.server(t, "A", "198.51.100.1")
	f.db.SetServerState(ctx, s.ID, model.StateHealthy, now)
	f.db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Unit: "hysteria-server.service", Version: hyrelease.DefaultVersion, At: now})
	latest := ""
	a := &Attention{Store: f.db, Redact: f.red, Monitoring: true, Now: f.clock.now, Latest: func() string { return latest }}
	hysteria := func() []Item {
		t.Helper()
		sum, err := a.Summary(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []Item
		for _, it := range sum.Items {
			if it.Kind == "hysteria" {
				out = append(out, it)
			}
		}
		return out
	}
	if got := hysteria(); len(got) != 0 {
		t.Fatalf("default version and nothing newer: %+v", got)
	}
	latest = "v2.0.0" // older than the default: not the measure
	if got := hysteria(); len(got) != 0 {
		t.Fatalf("older release: %+v", got)
	}
	latest = "v9.1.0"
	if got := hysteria(); len(got) != 1 || !strings.Contains(got[0].Text, "v9.1.0") || got[0].SubjectID != s.ID {
		t.Fatalf("newer release: %+v", got)
	}
}
