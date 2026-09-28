package flows

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	var closed []View
	g := NewRegistry(2)
	g.OnClose = func(v View) { closed = append(closed, v) }
	t0 := time.Unix(100, 0)
	var recs []*Record
	for i := 0; i < 3; i++ {
		r := g.Open(&Record{Proto: 17, Dst: netip.MustParseAddrPort("1.1.1.1:53"), Start: t0})
		r.Recv.Store(-1)
		r.Set(func(f *Fields) { f.Route = "direct" })
		r.Sent.Add(10)
		recs = append(recs, r)
	}
	if len(g.Active(t0)) != 3 || recs[2].ID != 3 {
		t.Fatal("open")
	}
	for _, r := range recs {
		g.Close(r, t0.Add(time.Second))
		g.Close(r, t0.Add(time.Hour)) // ignored
	}
	if len(closed) != 3 || len(g.Closed()) != 2 || len(g.Active(t0)) != 0 {
		t.Fatalf("closed=%d kept=%d", len(closed), len(g.Closed()))
	}
	v := closed[0]
	if v.Duration != time.Second || v.Proto != "udp" || v.Sent != 10 || v.Recv != -1 || v.Route != "direct" || !v.Closed {
		t.Fatalf("%+v", v)
	}
}

// TestExcludedJSON: the exclusion kind reaches the UI only when set.
func TestExcludedJSON(t *testing.T) {
	r := &Record{Proto: 6, Dst: netip.MustParseAddrPort("1.1.1.1:443")}
	b, _ := json.Marshal(r.View(time.Now()))
	if strings.Contains(string(b), `"excluded"`) {
		t.Fatalf("empty kind marshalled: %s", b)
	}
	r.Set(func(f *Fields) { f.Excluded = "system-dns" })
	b, _ = json.Marshal(r.View(time.Now()))
	if !strings.Contains(string(b), `"excluded":"system-dns"`) {
		t.Fatalf("%s", b)
	}
}

// TestTooBigView (bigudp): the counter reaches the UI only when set, and a
// tunneled flow of which nothing got through shows why.
func TestTooBigView(t *testing.T) {
	r := &Record{Proto: 17, Dst: netip.MustParseAddrPort("93.184.216.34:443")}
	r.Set(func(f *Fields) { f.Route, f.Outcome = "tunnel", "tunneled" })
	b, _ := json.Marshal(r.View(time.Now()))
	if strings.Contains(string(b), `"tooBig"`) {
		t.Fatalf("zero counter marshalled: %s", b)
	}
	r.TooBig.Add(2)
	v := r.View(time.Now())
	if v.TooBig != 2 || v.Outcome != OutcomeTooBig {
		t.Fatalf("%+v", v)
	}
	if b, _ = json.Marshal(v); !strings.Contains(string(b), `"tooBig":2`) {
		t.Fatalf("%s", b)
	}
	// Something went through: the stored outcome.
	r.Sent.Add(100)
	if v := r.View(time.Now()); v.Outcome != "tunneled" || v.TooBig != 2 {
		t.Fatalf("%+v", v)
	}
	// Only "tunneled" is replaced (the tunnel-down outcome stays).
	d := &Record{Proto: 17}
	d.Set(func(f *Fields) { f.Outcome = "dropped: tunnel unavailable" })
	d.TooBig.Add(1)
	if v := d.View(time.Now()); v.Outcome != "dropped: tunnel unavailable" {
		t.Fatalf("%+v", v)
	}
}

// ---- stats ----

// TestViewSettledFailed lists every outcome the engine and the relay
// produce: a new one must be added here (Settled and Failed are the only
// interpreters of outcome strings).
func TestViewSettledFailed(t *testing.T) {
	for _, c := range []struct {
		route, outcome  string
		closed          bool
		settled, failed bool
	}{
		{"pending", "", false, false, false},
		{"pending", "reflected: sniff", true, false, false},
		{"", "", true, false, false},
		{"tunnel", "reflected", false, false, false},
		{"tunnel", "reflected", true, false, false},
		{"tunnel", "reflected: sniff", false, false, false},
		{"tunnel", "reflected: sniff", true, false, false},
		{"tunnel", "aborted: stopping", true, false, false},
		{"direct", "aborted: stopping", true, false, false},
		{"tunnel", "relayed", false, true, false},
		{"direct", "relayed", true, true, false},
		{"direct", "passed", false, true, false},
		{"tunnel", "tunneled", false, true, false},
		{"tunnel", "proxied", true, true, false},
		{"tunnel", "rst: tunnel unavailable", true, true, true},
		{"tunnel", "rst: socks5 connect failed", true, true, true},
		{"direct", "rst: direct dial failed", true, true, true},
		{"tunnel", "rst: reflect key collision", true, true, true},
		{"tunnel", "dropped: tunnel unavailable", false, true, true},
		{"tunnel", OutcomeTooBig, false, true, true},
		{"block", "rst: blocked", true, true, false},
		{"block", "dropped: blocked", true, true, false},
		{"block", "dropped: QUIC blocked, domain unknown", true, true, false},
		{"block", "rst: IPv6 blocked for tunnel", true, true, false},
		{"block", "dropped: IPv6 blocked for tunnel", true, true, false},
	} {
		v := View{Fields: Fields{Route: c.route, Outcome: c.outcome}, Closed: c.closed}
		if v.Settled() != c.settled || v.Failed() != c.failed {
			t.Errorf("%s %q closed=%v: settled %v failed %v", c.route, c.outcome, c.closed, v.Settled(), v.Failed())
		}
	}
}

// TestTicks: every live record with its current counters; Rev moves with
// Set only; closed records are absent; dst is reused.
func TestTicks(t *testing.T) {
	g := NewRegistry(4)
	a := g.Open(&Record{Proto: 6})
	b := g.Open(&Record{Proto: 17})
	a.Sent.Add(10)
	b.Recv.Add(7)
	ticks := g.Ticks(nil)
	if len(ticks) != 2 {
		t.Fatalf("%+v", ticks)
	}
	by := map[uint64]Tick{}
	for _, k := range ticks {
		by[k.ID] = k
	}
	if by[a.ID].Sent != 10 || by[b.ID].Recv != 7 || by[a.ID].Rec != a {
		t.Fatalf("%+v", by)
	}
	rev := by[a.ID].Rev
	a.Sent.Add(5)
	if k := find(g.Ticks(ticks), a.ID); k.Rev != rev || k.Sent != 15 {
		t.Fatalf("counters moved the revision: %+v", k)
	}
	a.Set(func(f *Fields) { f.Route = "tunnel" })
	if k := find(g.Ticks(ticks), a.ID); k.Rev == rev {
		t.Fatal("Set kept the revision")
	}
	g.Close(b, time.Now())
	again := g.Ticks(ticks)
	if len(again) != 1 || again[0].ID != a.ID || &again[0] != &ticks[0] {
		t.Fatalf("closed record listed or dst not reused: %+v", again)
	}
}

func find(ticks []Tick, id uint64) Tick {
	for _, k := range ticks {
		if k.ID == id {
			return k
		}
	}
	return Tick{}
}
