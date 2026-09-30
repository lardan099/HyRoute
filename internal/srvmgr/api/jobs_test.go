package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// demoKind has a step that waits for release and fails while broken.
func demoKind(release <-chan struct{}, broken *atomic.Bool) *jobs.Kind {
	return &jobs.Kind{Name: "demo", Steps: func(json.RawMessage) ([]jobs.Step, error) {
		return []jobs.Step{
			{Name: "prepare", Phase: model.JobPreflight, Safe: true, Run: func(_ context.Context, env *jobs.Env) error {
				env.Logf("preparing")
				return nil
			}},
			{Name: "work", Phase: model.JobInstalling, Run: func(ctx context.Context, env *jobs.Env) error {
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				if broken.Load() {
					return jobs.Fail("Шаг не удался.", errors.New("boom"))
				}
				env.Logf("working")
				return nil
			}},
		}, nil
	}}
}

func (e *testEnv) runJobs() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.jobs.Run(ctx); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
}

func (e *testEnv) waitJob(id int64, want model.JobState) {
	e.t.Helper()
	for i := 0; i < 500; i++ {
		if j, _ := e.db.JobByID(context.Background(), id); j.State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("job %d never reached %s", id, want)
}

func TestJobsAPIAndRetry(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	close(release)
	var broken atomic.Bool
	broken.Store(true)
	e.jobs.Register(demoKind(release, &broken))
	owner := e.setupOwner()
	e.runJobs()
	j, err := e.jobs.Submit(context.Background(), "demo", 0, map[string]string{"version": "v2.12.3"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(j.ID, model.JobFailed)
	id := strconv.FormatInt(j.ID, 10)

	rec := owner.do("GET", "/api/v1/jobs", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"failed"`) || !strings.Contains(rec.Body.String(), `"version":"v2.12.3"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/jobs/"+id, nil, nil)
	var detail struct {
		jobJSON
		Steps []stepJSON
	}
	json.Unmarshal(rec.Body.Bytes(), &detail)
	if detail.ErrorMessage != "Шаг не удался." || len(detail.Steps) != 2 || detail.Steps[1].State != model.StepFailed {
		t.Fatalf("detail: %s", rec.Body)
	}
	rec = owner.do("GET", "/api/v1/jobs/"+id+"/logs", nil, nil)
	if !strings.Contains(rec.Body.String(), "preparing") {
		t.Fatalf("logs: %s", rec.Body)
	}

	// Read-only users see jobs but cannot retry.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(context.Background(), &u)
	ro := e.login("viewer")
	if rec := ro.do("GET", "/api/v1/jobs/"+id, nil, nil); rec.Code != 200 {
		t.Fatalf("read-only detail: %d", rec.Code)
	}
	code(t, ro.do("POST", "/api/v1/jobs/"+id+"/retry", nil, nil), http.StatusForbidden, "forbidden")

	broken.Store(false)
	if rec := owner.do("POST", "/api/v1/jobs/"+id+"/retry", nil, nil); rec.Code != 200 {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	e.waitJob(j.ID, model.JobCompleted)
	code(t, owner.do("POST", "/api/v1/jobs/"+id+"/retry", nil, nil), http.StatusConflict, "not_retryable")
	code(t, owner.do("GET", "/api/v1/jobs/999", nil, nil), http.StatusNotFound, "not_found")
}

// The event stream replays the stored log, then follows the job live and
// ends with it.
func TestJobEventsStream(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	var broken atomic.Bool
	e.jobs.Register(demoKind(release, &broken))
	owner := e.setupOwner()
	e.runJobs()
	j, _ := e.jobs.Submit(context.Background(), "demo", 0, nil, nil, 1)
	e.waitJob(j.ID, model.JobInstalling)

	ts := httptest.NewServer(e.h)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/jobs/"+strconv.FormatInt(j.ID, 10)+"/events", nil)
	req.AddCookie(owner.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	events := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(res.Body)
		var ev, data string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if ev != "" {
					events <- ev + " " + data
				}
				ev, data = "", ""
			}
		}
		close(events)
	}()
	var got []string
	timeout := time.After(5 * time.Second)
	sawPrep := false
	for !sawPrep {
		select {
		case ev := <-events:
			got = append(got, ev)
			sawPrep = sawPrep || strings.Contains(ev, "preparing")
		case <-timeout:
			t.Fatalf("no stored log replayed: %q", got)
		}
	}
	close(release) // the job goes on while we listen
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("stream closed without end: %q", got)
			}
			got = append(got, ev)
			if strings.HasPrefix(ev, "end") {
				all := strings.Join(got, "\n")
				if !strings.Contains(all, "working") || !strings.Contains(all, `"state":"completed"`) || !strings.Contains(all, "step ") {
					t.Fatalf("events: %s", all)
				}
				return
			}
		case <-timeout:
			t.Fatalf("stream did not end: %q", got)
		}
	}
}
