package flows

import (
	"net/netip"
	"testing"
	"time"
)

// DNS rows (dns) close into their own ring: they never push connections
// out and Closed merges both by close time. (That they are no traffic is
// the statistics sampler's, internal/stats.)
func TestDNSRing(t *testing.T) {
	g := NewRegistry(5)
	g.SetKeepDNS(3)
	var closedDNS int
	g.OnClose = func(v View) {
		if v.Stage == StageDNS {
			closedDNS++
		}
	}
	t0 := time.Unix(1000, 0)
	open := func(dns bool, i int) *Record {
		r := g.Open(&Record{Proto: 17, Dst: netip.MustParseAddrPort("1.1.1.1:53"), Start: t0.Add(time.Duration(i) * time.Second)})
		r.Sent.Store(40)
		r.Recv.Store(80)
		r.Set(func(f *Fields) {
			f.Route, f.Profile = "tunnel", "de"
			if dns {
				f.Stage, f.Count = StageDNS, 3
			}
		})
		return r
	}
	for i := range 10 {
		g.Close(open(true, i), t0.Add(time.Duration(2*i+1)*time.Second))
	}
	for i := range 5 {
		g.Close(open(false, i), t0.Add(time.Duration(2*i+2)*time.Second))
	}
	all := g.Closed()
	conns, dns := 0, 0
	for i, v := range all {
		if v.Stage == StageDNS {
			dns++
			if v.Count != 3 {
				t.Fatalf("count lost: %+v", v)
			}
		} else {
			conns++
		}
		if i > 0 && all[i-1].end().After(v.end()) {
			t.Fatalf("not merged by close time at %d", i)
		}
	}
	if conns != 5 || dns != 3 || closedDNS != 10 {
		t.Fatalf("kept %d connections, %d DNS rows (OnClose %d); want 5, 3, 10", conns, dns, closedDNS)
	}
	// Without DNS rows Closed is the connection ring as it was.
	g2 := NewRegistry(2)
	g2.Close(open(false, 0), t0)
	if len(g2.Closed()) != 1 {
		t.Fatal(g2.Closed())
	}
}
