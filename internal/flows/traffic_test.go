package flows

import (
	"testing"
	"time"
)

func TestOnTraffic(t *testing.T) {
	type got struct {
		profile, process string
		sent, recv       int64
	}
	var calls []got
	g := NewRegistry(10)
	g.OnTraffic = func(profile, process string, sent, recv int64) {
		calls = append(calls, got{profile, process, sent, recv})
	}
	tun := g.Open(&Record{Process: "chrome.exe"})
	tun.Set(func(f *Fields) { f.Route, f.Profile, f.Domain = "tunnel", "de", "example.com" })
	dir := g.Open(&Record{Process: "curl.exe"})
	dir.Set(func(f *Fields) { f.Route = "direct" })
	dir.Recv.Store(-1)

	tun.Sent.Add(100)
	tun.Recv.Add(1000)
	dir.Sent.Add(5)
	g.Sample()
	g.Sample() // nothing new
	tun.Sent.Add(1)
	tun.Recv.Add(2)
	g.Close(tun, time.Now())
	g.Close(dir, time.Now())
	g.Sample()

	want := []got{{"de", "chrome.exe", 100, 1000}, {"de", "chrome.exe", 1, 2}}
	if len(calls) != len(want) {
		t.Fatalf("%+v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("%d: %+v", i, calls[i])
		}
	}
}
