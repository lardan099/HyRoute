package events

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// clock is a fake time the tests move.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// notices collects what the bus tells its subscribers.
type notices struct {
	mu   sync.Mutex
	list []Notice
}

func (n *notices) add(x Notice) {
	n.mu.Lock()
	n.list = append(n.list, x)
	n.mu.Unlock()
}

func (n *notices) take() []Notice {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.list
	n.list = nil
	return out
}

type fixture struct {
	db    *sqlite.DB
	bus   *Bus
	clock *clock
	got   *notices
	red   *redact.Redactor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &fixture{db: db, clock: &clock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}, got: &notices{}, red: redact.New()}
	f.bus = &Bus{Store: db, Redact: f.red, Now: f.clock.now}
	f.bus.Subscribe(f.got.add)
	return f
}

// server adds a server named name at host.
func (f *fixture) server(t *testing.T, name, host string) model.Server {
	t.Helper()
	s := model.Server{Name: name, Host: host, SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
	if err := f.db.CreateServer(context.Background(), &s, nil); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) open(t *testing.T) []model.Event {
	t.Helper()
	evs, err := f.db.ListEvents(context.Background(), model.EventFilter{OpenOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// Repeats of an open event glue into it; closing tells the subscribers;
// the same key opens a new event after that.
func TestBusRaiseResolve(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := f.server(t, "Alpha", "alpha.example.com")
	e := model.Event{Kind: model.EventDisk, Key: "disk:1", Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: srv.ID, Text: "first"}
	if err := f.bus.Raise(ctx, e); err != nil {
		t.Fatal(err)
	}
	f.clock.add(time.Minute)
	e.Text = "second"
	f.bus.Raise(ctx, e)
	got := f.got.take()
	if len(got) != 1 || got[0].Closed || got[0].Event.Text != "first" {
		t.Fatalf("notices %+v", got)
	}
	open := f.open(t)
	if len(open) != 1 || open[0].Count != 2 || open[0].Text != "second" || !open[0].LastAt.After(open[0].OpenedAt) {
		t.Fatalf("open %+v", open)
	}
	if err := f.bus.Resolve(ctx, "disk:1", "over"); err != nil {
		t.Fatal(err)
	}
	got = f.got.take()
	if len(got) != 1 || !got[0].Closed || got[0].Event.CloseText != "over" || got[0].Event.Open() {
		t.Fatalf("close %+v", got)
	}
	f.bus.Resolve(ctx, "disk:1", "again")
	f.bus.Resolve(ctx, "nothing", "none")
	if got := f.got.take(); len(got) != 0 {
		t.Fatalf("closing nothing told %+v", got)
	}
	f.bus.Raise(ctx, e)
	all, _ := f.db.ListEvents(ctx, model.EventFilter{})
	if len(all) != 2 || all[0].Count != 1 || !all[0].Open() || all[1].Open() {
		t.Fatalf("after reopening %+v", all)
	}
	if err := f.bus.Raise(ctx, model.Event{Kind: "nonsense", Key: "x"}); err == nil {
		t.Fatal("an unknown kind was raised")
	}
}

// A bus that starts with open events in the database (a restarted
// controller) closes them.
func TestBusRestart(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.bus.Raise(ctx, model.Event{Kind: model.EventNetwork, Key: "network", Subject: model.SubjectController, Text: "down"})
	again := &Bus{Store: f.db, Now: f.clock.now}
	var got notices
	again.Subscribe(got.add)
	if !again.IsOpen(ctx, "network") {
		t.Fatal("the open event was not read")
	}
	again.Resolve(ctx, "network", "up")
	if n := got.take(); len(n) != 1 || !n[0].Closed {
		t.Fatalf("notices %+v", n)
	}
}

// Sweep drops events closed over 30 days ago and closes, quietly, the
// events of a server that is gone.
func TestBusSweep(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a, b := f.server(t, "A", "a.example.com"), f.server(t, "B", "b.example.com")
	f.bus.Raise(ctx, model.Event{Kind: model.EventDisk, Key: "disk:a", Subject: model.SubjectServer, SubjectID: a.ID, Text: "a"})
	f.bus.Resolve(ctx, "disk:a", "fine")
	f.clock.add(20 * 24 * time.Hour)
	f.bus.Raise(ctx, model.Event{Kind: model.EventDisk, Key: "disk:b", Subject: model.SubjectServer, SubjectID: b.ID, Text: "b"})
	f.bus.Raise(ctx, model.Event{Kind: model.EventServer, Key: "server:a", Subject: model.SubjectServer, SubjectID: a.ID, Text: "a down"})
	f.bus.Resolve(ctx, "server:a", "a up")
	// A failed job of b: the job outlives the server, the event does not.
	j := model.Job{Kind: "apply", ServerID: b.ID, State: model.JobFailed, Params: []byte("{}"), CreatedAt: f.clock.now()}
	if err := f.db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil); err != nil {
		t.Fatal(err)
	}
	f.bus.Raise(ctx, model.Event{Kind: model.EventJob, Key: "job:apply:b", Subject: model.SubjectJob, SubjectID: j.ID, Text: "b failed"})
	if err := f.db.DeleteServer(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.add(11 * 24 * time.Hour)
	f.got.take()
	if err := f.bus.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.got.take(); len(got) != 0 {
		t.Fatalf("the sweep told %+v", got)
	}
	all, _ := f.db.ListEvents(ctx, model.EventFilter{})
	if len(all) != 3 || all[0].Key != "job:apply:b" || all[0].Open() || all[1].Key != "server:a" || all[2].Key != "disk:b" || all[2].Open() || all[2].CloseText == "" {
		t.Fatalf("after the sweep %+v", all)
	}
	if f.bus.IsOpen(ctx, "disk:b") {
		t.Fatal("the cache still holds the swept event")
	}
}

// Texts lose secrets and addresses: a server's address becomes its name,
// any other address a mask; times and unit names stay.
func TestClean(t *testing.T) {
	red := redact.New()
	red.Add("canary-ssh-password-41")
	servers := []model.Server{
		{Name: "Alpha", Host: "198.51.100.77"},
		{Name: "Beta", Host: "beta.example.com"},
		{Name: "Gamma", Host: "2001:db8::77"},
	}
	in := "SSH 198.51.100.77:22 refused, password canary-ssh-password-41; dial udp 192.0.2.10:443; " +
		"beta.example.com and BETA.example.com timed out; [2001:db8::77]:22 and 2001:db8::99 down; " +
		"target example.org:443 closed; release at https://github.com/x/y/releases/latest; " +
		"link hysteria2://secret-auth@host:443 leaked; password: hunter2-canary; at 12:30:45 hysteria-server.service failed; " +
		"198.51.100.770 is not an address of Alpha"
	out := Clean(in, red, servers)
	for _, bad := range []string{"198.51.100.77:", "canary-ssh-password-41", "192.0.2.10", "beta.example.com", "BETA.example.com", "2001:db8",
		"example.org", "github.com", "secret-auth", "hunter2-canary"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q left in %q", bad, out)
		}
	}
	for _, good := range []string{"«Alpha»:22", "«Beta» and «Beta»", "«Gamma»:22", "12:30:45", "hysteria-server.service", "release at " + Address + "; link"} {
		if !strings.Contains(out, good) {
			t.Errorf("%q missing in %q", good, out)
		}
	}
}

// Bare domains of anyone but a public service and key fingerprints leave
// event texts; file and unit names stay.
func TestCleanDomainsAndFingerprints(t *testing.T) {
	red := redact.New()
	cases := map[string]string{
		"x509: certificate is valid for vpn.example.com, not exit.example.org":                     "x509: certificate is valid for [адрес], not [адрес]",
		"lookup acme.example.net: no such host":                                                    "lookup [адрес]: no such host",
		"host:vpn.example.com":                                                                     "host:[адрес]",
		"не удалось скачать с github.com":                                                          "не удалось скачать с github.com",
		"служба hysteria-server.service, файл config.yaml":                                         "служба hysteria-server.service, файл config.yaml",
		"host key changed: trusted ssh-ed25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG": "host key changed: trusted ssh-ed25519 SHA256:" + redact.Mask,
	}
	for in, want := range cases {
		if got := Clean(in, red, nil); got != want {
			t.Errorf("%q\n got %q\nwant %q", in, got, want)
		}
	}
}
