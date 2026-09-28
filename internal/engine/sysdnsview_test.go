package engine

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/sysdns"
)

func TestSysDNSView(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	var fail atomic.Bool
	snap := func() (sysdns.Info, error) {
		n := calls.Add(1)
		if n > 1 {
			<-release
		}
		if fail.Load() {
			return sysdns.Info{}, errors.New("GetAdaptersAddresses failed")
		}
		return sysdns.Info{All: map[netip.Addr]bool{netip.AddrFrom4([4]byte{10, 0, 0, byte(n)}): true}, Suffixes: []string{"corp.example"}}, nil
	}
	v := NewSysDNSView(snap, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	v.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	done := make(chan struct{}, 4)
	v.done = func() { done <- struct{}{} }
	if v.Get() != nil || v.Local("wiki.corp.example") {
		t.Fatal("a snapshot before the first refresh")
	}
	v.Refresh()
	if i := v.Get(); i == nil || !i.All[netip.MustParseAddr("10.0.0.1")] || !v.Local("wiki.corp.example") || v.Local("example.com") {
		t.Fatalf("%+v", i)
	}
	// Within kickGap of the last refresh: nothing.
	v.Kick()
	if calls.Load() != 1 {
		t.Fatal("refreshed within the gap")
	}
	advance(kickGap)
	start := time.Now()
	v.Kick() // the fake blocks: Kick must return at once
	v.Kick() // one is running: no second
	if time.Since(start) > time.Second {
		t.Fatal("Kick blocked")
	}
	for calls.Load() != 2 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-done
	if calls.Load() != 2 || !v.Get().All[netip.MustParseAddr("10.0.0.2")] {
		t.Fatalf("calls %d, %+v", calls.Load(), v.Get())
	}
	// A failing snapshot keeps the old one.
	fail.Store(true)
	advance(kickGap)
	v.Kick()
	<-done
	if !v.Get().All[netip.MustParseAddr("10.0.0.2")] {
		t.Fatal("failed refresh replaced the snapshot")
	}
}
