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
