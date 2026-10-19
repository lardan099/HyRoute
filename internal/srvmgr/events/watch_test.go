package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// one returns the single notice the bus told, or fails.
func (f *fixture) one(t *testing.T, closed bool, has string) Notice {
	t.Helper()
	got := f.got.take()
	if len(got) != 1 || got[0].Closed != closed {
		t.Fatalf("notices %+v, want one (closed %v)", got, closed)
	}
	text := got[0].Event.Text
	if closed {
		text = got[0].Event.CloseText
	}
	if !strings.Contains(text, has) {
		t.Fatalf("text %q, want %q in it", text, has)
	}
	return got[0]
}

func (f *fixture) none(t *testing.T) {
	t.Helper()
	if got := f.got.take(); len(got) != 0 {
		t.Fatalf("notices %+v, want none", got)
	}
}

// A status counts after Threshold checks in a row, both ways; a new
// reason while it lasts updates the event without a notice.
func TestWatcherServerThreshold(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := f.server(t, "Alpha", "198.51.100.7")
	w := &Watcher{Bus: f.bus, Threshold: 3}
	check := func(st model.ServerState, reason string) {
		f.clock.add(time.Minute)
		w.Server(ctx, srv, st, reason)
	}
	// Flapping never reaches the threshold.
	for range 4 {
		check(model.StateOffline, "SSH не отвечает.")
		check(model.StateHealthy, "")
	}
	f.none(t)
	check(model.StateOffline, "SSH не отвечает.")
	check(model.StateOffline, "SSH не отвечает.")
	f.none(t)
	check(model.StateOffline, "SSH не отвечает.")
	n := f.one(t, false, "Сервер «Alpha» недоступен. SSH не отвечает.")
	if n.Event.Severity != model.SeverityCritical || n.Event.Subject != model.SubjectServer || n.Event.SubjectID != srv.ID {
		t.Fatalf("event %+v", n.Event)
	}
	check(model.StateOffline, "SSH не отвечает.")
	check(model.StateDegraded, "Служба hysteria-server.service: failed.")
	check(model.StateDegraded, "Служба hysteria-server.service: failed.")
	f.none(t)
	check(model.StateDegraded, "Служба hysteria-server.service: failed.")
	f.none(t) // glued into the open event
	open := f.open(t)
	if len(open) != 1 || open[0].Count != 2 || !strings.Contains(open[0].Text, "работает с проблемами. Служба") || open[0].Severity != model.SeverityWarning {
		t.Fatalf("open %+v", open)
	}
	check(model.StateHealthy, "")
	check(model.StateHealthy, "")
	f.none(t)
	check(model.StateHealthy, "")
	f.one(t, true, "Сервер «Alpha» снова работает.")
	check(model.StateHealthy, "")
	f.none(t)
	if len(f.open(t)) != 0 {
		t.Fatal("still open")
	}
}

// A link offline or degraded for Threshold checks opens its event, as
// many healthy ones close it.
func TestWatcherLink(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	entry, exit := f.server(t, "Entry", "entry.example.com"), f.server(t, "Exit", "203.0.113.9")
	chain := model.Chain{ID: 7, Name: "Через Exit"}
	l := model.ChainLink{ChainID: 7, Idx: 0, From: entry.ID, To: exit.ID}
	w := &Watcher{Bus: f.bus, Threshold: 2}
	w.Link(ctx, chain, l, entry, exit, model.LinkCheck{Status: model.StateOffline, Reason: "сервер выхода не открывает 203.0.113.9:22"})
	f.none(t)
	w.Link(ctx, chain, l, entry, exit, model.LinkCheck{Status: model.StateOffline, Reason: "сервер выхода не открывает 203.0.113.9:22"})
	n := f.one(t, false, "Каскад «Через Exit»: связь «Entry» → «Exit» не работает. Сервер выхода не открывает «Exit»:22.")
	if n.Event.Subject != model.SubjectChain || n.Event.SubjectID != 7 || strings.Contains(n.Event.Text, "203.0.113.9") {
		t.Fatalf("event %+v", n.Event)
	}
	w.Link(ctx, chain, l, entry, exit, model.LinkCheck{Status: model.StateHealthy})
	w.Link(ctx, chain, l, entry, exit, model.LinkCheck{Status: model.StateHealthy})
	f.one(t, true, "снова работает")
}

// Disk: above 90 % opens, below 85 % closes, in between nothing changes.
func TestWatcherDisk(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := f.server(t, "Alpha", "alpha.example.com")
	w := &Watcher{Bus: f.bus}
	const total = 10 << 20 // 10 GiB in KiB
	w.Disk(ctx, srv, total*80/100, total)
	f.none(t)
	w.Disk(ctx, srv, total*91/100, total)
	f.one(t, false, "Диск сервера «Alpha» заполнен на 91 %: свободно 921 МБ.")
	w.Disk(ctx, srv, total*95/100, total)
	w.Disk(ctx, srv, total*88/100, total)
	f.none(t)
	w.Disk(ctx, srv, total*84/100, total)
	f.one(t, true, "заполнен на 84 %")
	w.Disk(ctx, srv, 0, 0)
	f.none(t)
}

// The controller's network, the geo databases and drift: open and close.
func TestWatcherControllerEvents(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	w := &Watcher{Bus: f.bus}
	w.Network(ctx, true)
	f.none(t)
	w.Network(ctx, false)
	w.Network(ctx, false)
	n := f.one(t, false, "У controller нет сети")
	if n.Event.Subject != model.SubjectController || n.Event.Severity != model.SeverityCritical {
		t.Fatalf("network %+v", n.Event)
	}
	if open := f.open(t); len(open) != 1 || open[0].Count != 2 {
		t.Fatalf("open %+v", open)
	}
	w.Network(ctx, true)
	f.one(t, true, "Сеть у controller снова есть.")

	w.Geo(ctx, "", errors.New(`Get "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest": dial tcp 140.82.121.3:443: i/o timeout`))
	n = f.one(t, false, "Базы geo controller не обновились")
	if strings.Contains(n.Event.Text, "github") || strings.Contains(n.Event.Text, "140.82") {
		t.Fatalf("an address in %q", n.Event.Text)
	}
	w.Geo(ctx, "202609010000", nil)
	f.one(t, true, "релиз 202609010000")

	srv := f.server(t, "Alpha", "alpha.example.com")
	w.Drift(ctx, srv, "конфиг Hysteria изменён")
	f.one(t, false, "Сервер «Alpha» изменён вне HyRoute. конфиг Hysteria изменён")
	w.DriftGone(ctx, srv)
	f.one(t, true, "снова совпадает")
}

// SSH: another host key and a refused login open their events, a login
// that works closes both; a timeout is the status's business.
func TestWatcherSSH(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := f.server(t, "Alpha", "alpha.example.com")
	w := &Watcher{Bus: f.bus}
	w.SSH(ctx, srv.ID, &remote.UnreachableError{Err: errors.New("i/o timeout")})
	w.SSH(ctx, srv.ID, nil)
	f.none(t)
	w.SSH(ctx, srv.ID, &remote.HostKeyChangedError{KeyType: "ssh-ed25519", Fingerprint: "SHA256:new", OldKeyType: "ssh-ed25519", OldFingerprint: "SHA256:old"})
	n := f.one(t, false, "Сервер «Alpha» предъявил другой ключ SSH")
	if n.Event.Kind != model.EventHostKey || n.Event.Severity != model.SeverityCritical {
		t.Fatalf("host key %+v", n.Event)
	}
	w.SSH(ctx, srv.ID, fmt.Errorf("%w: ssh: handshake failed", remote.ErrAuthFailed))
	if n := f.one(t, false, "отклонил вход по SSH"); n.Event.Kind != model.EventSSHAuth {
		t.Fatalf("auth %+v", n.Event)
	}
	w.SSH(ctx, srv.ID, nil)
	got := f.got.take()
	if len(got) != 2 || !got[0].Closed || !got[1].Closed {
		t.Fatalf("closing %+v", got)
	}
}
