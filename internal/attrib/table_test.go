package attrib

import (
	"net/netip"
	"testing"
	"time"
)

var (
	L  = netip.MustParseAddrPort("192.168.1.10:51000")
	R  = netip.MustParseAddrPort("93.184.216.34:443")
	R2 = netip.MustParseAddrPort("93.184.216.34:8443")
)

func TestExactAndMapped(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	tb.Connect(Key5{6, L, R}, 100, 1, now)
	if pid, ok := tb.Lookup(Key5{6, L, R}); !ok || pid != 100 {
		t.Fatal("exact")
	}
	mapped := Key5{6, netip.MustParseAddrPort("[::ffff:192.168.1.10]:51000"), netip.MustParseAddrPort("[::ffff:93.184.216.34]:443")}
	if pid, ok := tb.Lookup(mapped); !ok || pid != 100 {
		t.Fatal("mapped")
	}
	// Same local port to a different remote is not a match via exact/byPort.
	if _, ok := tb.Lookup(Key5{6, L, R2}); ok {
		t.Fatal("must not match another remote")
	}
	if _, ok := tb.Lookup(Key5{17, L, R}); ok {
		t.Fatal("must not match another protocol")
	}
}

func TestUnspecifiedLocalAndBind(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	// CONNECT event with unspecified local address.
	tb.Connect(Key5{6, netip.MustParseAddrPort("0.0.0.0:51000"), R}, 200, 2, now)
	if pid, ok := tb.Lookup(Key5{6, L, R}); !ok || pid != 200 {
		t.Fatal("port+remote fallback")
	}
	// Unconnected UDP socket: bind only.
	tb.Bind(17, 5353, 300, 3, now)
	if pid, ok := tb.Lookup(Key5{17, netip.MustParseAddrPort("192.168.1.10:5353"), netip.MustParseAddrPort("8.8.8.8:53")}); !ok || pid != 300 {
		t.Fatal("bind fallback")
	}
	tb.Close(3)
	if _, ok := tb.Lookup(Key5{17, netip.MustParseAddrPort("192.168.1.10:5353"), netip.MustParseAddrPort("8.8.8.8:53")}); ok {
		t.Fatal("close must remove bind")
	}
}

func TestCloseOnlyOwnEndpoint(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	tb.Connect(Key5{6, L, R}, 100, 1, now)
	// Port reused by a new socket before the old CLOSE arrives.
	tb.Connect(Key5{6, L, R}, 101, 2, now)
	tb.Close(1)
	if pid, ok := tb.Lookup(Key5{6, L, R}); !ok || pid != 101 {
		t.Fatalf("late close of old endpoint removed the new one: %d %v", pid, ok)
	}
}

func TestChangedAndSweep(t *testing.T) {
	tb := NewTable()
	ch := tb.Changed()
	go tb.Connect(Key5{6, L, R}, 1, 1, time.Now())
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no notification")
	}
	now := time.Now()
	tb.Sweep(now.Add(time.Minute), time.Hour)
	if tb.Len() == 0 {
		t.Fatal("fresh entry swept")
	}
	tb.Sweep(now.Add(2*time.Hour), time.Hour)
	if tb.Len() != 0 {
		t.Fatal("stale entry kept")
	}
}

// checkTable verifies the bookkeeping: every record is in its socket's key
// set and has exactly one live queue entry.
func checkTable(t *testing.T, tb *Table) {
	t.Helper()
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	keys := 0
	for id, ep := range tb.byEndpoint {
		if len(ep.keys) == 0 {
			t.Fatalf("endpoint %d kept without keys", id)
		}
		for k := range ep.keys {
			if r := tb.getLocked(k); r == nil || r.endpoint != id {
				t.Fatalf("endpoint %d lists %v it does not own", id, k)
			}
		}
		keys += len(ep.keys)
	}
	if keys != tb.lenLocked() {
		t.Fatalf("%d keys in endpoint sets, %d records", keys, tb.lenLocked())
	}
	live := map[*rec]bool{}
	for _, q := range tb.queue {
		if tb.getLocked(q.key) == q.r {
			if live[q.r] {
				t.Fatalf("record %v queued twice", q.key)
			}
			live[q.r] = true
		}
	}
	if len(live) != tb.lenLocked() || len(tb.queue)-tb.dead != len(live) {
		t.Fatalf("queue %d, dead %d, live %d, records %d", len(tb.queue), tb.dead, len(live), tb.lenLocked())
	}
}

func remote(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, byte(i >> 16), byte(i >> 8), byte(i)}), 6881)
}

// SOCKET_CONNECT and FLOW_ESTABLISHED repeat for the same remote (every
// re-created UDP ALE flow); they must not add records.
func TestRepeatedEventsDoNotGrow(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	tb.Bind(17, 6881, 7, 7, now)
	for i := range 1000 {
		tb.Connect(Key5{17, L, R}, 7, 7, now.Add(time.Duration(i)*time.Second))
	}
	if tb.Len() != 3 || len(tb.queue) != 3 || len(tb.byEndpoint[7].keys) != 3 {
		t.Fatalf("len %d, queue %d, endpoint keys %d", tb.Len(), len(tb.queue), len(tb.byEndpoint[7].keys))
	}
	checkTable(t, tb)
}

// A long-lived UDP socket (DHT, games) keeps producing events: its old
// remotes expire one by one, its bind stays while the socket is active.
func TestSweepExpiresRecordsOfLiveSocket(t *testing.T) {
	tb := NewTable()
	t0 := time.Now()
	local := netip.MustParseAddrPort("192.168.1.10:6881")
	tb.Bind(17, 6881, 7, 7, t0)
	for i := range 100 {
		tb.Connect(Key5{17, local, remote(i)}, 7, 7, t0.Add(time.Duration(i)*time.Minute))
	}
	now := t0.Add(99 * time.Minute)
	tb.Sweep(now, 30*time.Minute)
	// Remotes 0..69 are 30 minutes old or more; 70..99 stay, and the bind.
	if tb.Len() != 2*30+1 {
		t.Fatalf("len %d after sweep", tb.Len())
	}
	if _, ok := tb.exact[Key5{17, local, remote(69)}]; ok {
		t.Fatal("stale remote kept")
	}
	if _, ok := tb.exact[Key5{17, local, remote(70)}]; !ok {
		t.Fatal("fresh remote swept")
	}
	if pid, ok := tb.Lookup(Key5{17, local, remote(0)}); !ok || pid != 7 {
		t.Fatal("bind of an active socket swept")
	}
	checkTable(t, tb)
	// Nothing expired: the queue is not walked.
	head := tb.queue[0]
	tb.Sweep(now, 30*time.Minute)
	if tb.Len() != 61 || tb.queue[0] != head {
		t.Fatal("second sweep changed the table")
	}
	// The socket goes quiet (lost CLOSE): everything goes, bind included.
	tb.Sweep(now.Add(30*time.Minute), 30*time.Minute)
	if tb.Len() != 0 || len(tb.byEndpoint) != 0 {
		t.Fatalf("len %d, endpoints %d after the socket went quiet", tb.Len(), len(tb.byEndpoint))
	}
	checkTable(t, tb)
}

func TestCapEvictsLeastRecent(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	local := netip.MustParseAddrPort("192.168.1.10:6881")
	tb.Bind(17, 6881, 7, 7, now)
	n := maxRecords // 2 records each
	for i := range n {
		tb.Connect(Key5{17, local, remote(i)}, 7, 7, now.Add(time.Duration(i)*time.Millisecond))
	}
	if tb.Len() > maxRecords {
		t.Fatalf("len %d over the cap", tb.Len())
	}
	if _, ok := tb.exact[Key5{17, local, remote(0)}]; ok {
		t.Fatal("oldest remote kept")
	}
	if _, ok := tb.exact[Key5{17, local, remote(n - 1)}]; !ok {
		t.Fatal("newest remote evicted")
	}
	if _, ok := tb.bind[bindMarker{Proto: 17, Port: 6881}]; !ok {
		t.Fatal("bind of the active socket evicted")
	}
	checkTable(t, tb)
}

// Short-lived sockets leave dead queue entries behind; the queue must not
// keep them all until they expire.
func TestQueueCompaction(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	for i := range 20000 {
		tb.Connect(Key5{6, L, remote(i)}, 1, uint64(i), now)
		tb.Close(uint64(i))
	}
	if tb.Len() != 0 || len(tb.byEndpoint) != 0 {
		t.Fatalf("len %d, endpoints %d", tb.Len(), len(tb.byEndpoint))
	}
	if len(tb.queue) > 3000 {
		t.Fatalf("queue kept %d dead entries", len(tb.queue))
	}
	checkTable(t, tb)
}

// A port reused by a new socket moves the record: the old socket no longer
// lists it and its late CLOSE removes nothing.
func TestReusedKeyMovesToNewSocket(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	tb.Connect(Key5{6, L, R}, 100, 1, now)
	tb.Connect(Key5{6, L, R}, 101, 2, now)
	if _, ok := tb.byEndpoint[1]; ok {
		t.Fatal("old socket still lists the moved records")
	}
	checkTable(t, tb)
	tb.Close(1)
	if pid, ok := tb.Lookup(Key5{6, L, R}); !ok || pid != 101 {
		t.Fatalf("%d %v", pid, ok)
	}
	tb.Sweep(now.Add(time.Hour), 30*time.Minute)
	if tb.Len() != 0 {
		t.Fatalf("len %d", tb.Len())
	}
	checkTable(t, tb)
}
