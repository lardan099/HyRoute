package events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// outcome is what the test kind does: fail its step, and leave the
// server needing attention (as a failed rollback does).
type outcome struct {
	Fail      bool `json:"fail"`
	Attention bool `json:"attention"`
}

// applyKind is a job of kind apply whose step fails when told to and
// whose Finished hook sets the server's state.
func applyKind(f *fixture) *jobs.Kind {
	return &jobs.Kind{
		Name: "apply",
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{{Name: "install", Phase: model.JobInstalling, Run: func(ctx context.Context, env *jobs.Env) error {
				var o outcome
				env.DecodeParams(&o)
				if o.Fail {
					return jobs.Fail("Новый конфиг не запустился на 198.51.100.7:443.", nil)
				}
				return nil
			}}}, nil
		},
		Finished: func(ctx context.Context, env *jobs.Env, j model.Job) {
			var o outcome
			env.DecodeParams(&o)
			state := model.StateHealthy
			if o.Attention {
				state = model.StateNeedsAttention
			}
			f.db.SetServerState(ctx, env.ServerID, state, time.Now())
		},
	}
}

// A failed job opens the event of its kind on its server, a later
// success of the kind closes it; a server left needing attention gets
// its event until a job leaves it healthy. Texts name the server, not
// its address.
func TestWatcherJobs(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := f.server(t, "Alpha", "198.51.100.7")
	w := &Watcher{Bus: f.bus}
	eng := jobs.New(f.db, nil, nil, nil, nil)
	eng.Poll = 10 * time.Millisecond
	ended := make(chan model.Job, 1)
	eng.OnEnd = func(ctx context.Context, j model.Job) {
		w.JobEnded(ctx, j)
		ended <- j
	}
	eng.Register(applyKind(f))
	rctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		eng.Run(rctx)
		close(done)
	}()
	t.Cleanup(func() { stop(); <-done })

	run := func(o outcome) {
		t.Helper()
		if _, err := eng.Submit(ctx, "apply", srv.ID, o, nil, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Fatal("the job did not end")
		}
	}

	run(outcome{Fail: true, Attention: true})
	got := f.got.take()
	if len(got) != 2 {
		t.Fatalf("notices %+v", got)
	}
	job, att := got[0].Event, got[1].Event
	if job.Kind != model.EventJob || job.Subject != model.SubjectJob || !strings.Contains(job.Text, "Задание «Применение конфига» на сервере «Alpha» не выполнено. Новый конфиг не запустился на «Alpha»:443.") {
		t.Fatalf("job event %+v", job)
	}
	if att.Kind != model.EventAttention || att.SubjectID != srv.ID || !strings.Contains(att.Text, "Сервер «Alpha» требует внимания") {
		t.Fatalf("attention event %+v", att)
	}
	for _, n := range got {
		if strings.Contains(n.Event.Text, "198.51.100.7") {
			t.Fatalf("an address in %q", n.Event.Text)
		}
	}
	run(outcome{Fail: true, Attention: true})
	f.none(t) // glued
	run(outcome{})
	got = f.got.take()
	if len(got) != 2 || !got[0].Closed || !got[1].Closed || !strings.Contains(got[0].Event.CloseText, "выполнено") || !strings.Contains(got[1].Event.CloseText, "больше не требует внимания") {
		t.Fatalf("closing %+v", got)
	}
	run(outcome{})
	f.none(t)
}
