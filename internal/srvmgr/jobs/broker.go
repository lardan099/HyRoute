package jobs

import (
	"sync"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Event is a change of a job: its state, a step, or a new log line.
type Event struct {
	Type string // job, step, log
	Job  *model.Job
	Step *model.JobStep
	Log  *model.JobLog
}

// broker fans job events out to subscribers. A slow subscriber is cut
// off rather than stalling the job: its channel closes after the events
// it got, never with a gap in them, and it catches up from the database.
type broker struct {
	mu   sync.Mutex
	subs map[int64]map[chan Event]struct{}
}

func newBroker() *broker { return &broker{subs: map[int64]map[chan Event]struct{}{}} }

func (b *broker) subscribe(jobID int64) (<-chan Event, func()) {
	ch := make(chan Event, 256)
	b.mu.Lock()
	if b.subs[jobID] == nil {
		b.subs[jobID] = map[chan Event]struct{}{}
	}
	b.subs[jobID][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[jobID][ch]; ok {
			b.drop(jobID, ch)
		}
	}
}

// drop ends a subscription; b.mu is held.
func (b *broker) drop(jobID int64, ch chan Event) {
	delete(b.subs[jobID], ch)
	if len(b.subs[jobID]) == 0 {
		delete(b.subs, jobID)
	}
	close(ch)
}

func (b *broker) publish(jobID int64, ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[jobID] {
		select {
		case ch <- ev:
		default:
			b.drop(jobID, ch)
		}
	}
}
