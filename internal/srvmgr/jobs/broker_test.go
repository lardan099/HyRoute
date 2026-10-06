package jobs

import (
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// A subscriber that falls behind gets the events before the first one it
// could not take, in order and without a gap, then a closed channel; the
// others go on.
func TestBrokerCutsOffSlowSubscriber(t *testing.T) {
	b := newBroker()
	slow, cancelSlow := b.subscribe(1)
	for seq := int64(1); seq <= 300; seq++ {
		b.publish(1, Event{Type: "log", Log: &model.JobLog{Seq: seq}})
	}
	fast, cancelFast := b.subscribe(1)
	defer cancelFast()
	b.publish(1, Event{Type: "log", Log: &model.JobLog{Seq: 301}})

	want := int64(1)
	for open := true; open; {
		select {
		case ev, ok := <-slow:
			if open = ok; !ok {
				break
			}
			if ev.Log.Seq != want {
				t.Fatalf("got %d, want %d", ev.Log.Seq, want)
			}
			want++
		case <-time.After(time.Second):
			t.Fatalf("not closed after %d events", want-1)
		}
	}
	if want != 257 {
		t.Fatalf("%d events before the channel closed, want 256", want-1)
	}
	cancelSlow() // after the cut-off: no double close
	if ev := <-fast; ev.Log.Seq != 301 {
		t.Fatalf("a new subscriber got %+v", ev)
	}
}
