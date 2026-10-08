package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
)

type jobJSON struct {
	ID       int64  `json:"id"`
	Kind     string `json:"kind"`
	ServerID int64  `json:"serverId"`
	// Servers are the other servers the job changes (a cascade link).
	Servers     []int64         `json:"servers"`
	State       model.JobState  `json:"state"`
	CurrentStep string          `json:"currentStep"`
	Params      json.RawMessage `json:"params"`
	// Data are results steps stored (the preflight report); no secrets.
	Data         map[string]string `json:"data"`
	Attempt      int               `json:"attempt"`
	ErrorMessage string            `json:"errorMessage"`
	ErrorDetails string            `json:"errorDetails"`
	CreatedAt    time.Time         `json:"createdAt"`
	StartedAt    *time.Time        `json:"startedAt"`
	FinishedAt   *time.Time        `json:"finishedAt"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toJobJSON(j model.Job) jobJSON {
	params := j.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	data := j.Data
	if data == nil {
		data = map[string]string{}
	}
	servers := j.Servers
	if servers == nil {
		servers = []int64{}
	}
	return jobJSON{ID: j.ID, Kind: j.Kind, ServerID: j.ServerID, Servers: servers, State: j.State, CurrentStep: j.CurrentStep, Params: params, Data: data,
		Attempt: j.Attempt, ErrorMessage: j.ErrorMessage, ErrorDetails: j.ErrorDetails, CreatedAt: j.CreatedAt,
		StartedAt: optTime(j.StartedAt), FinishedAt: optTime(j.FinishedAt)}
}

type stepJSON struct {
	Idx        int             `json:"idx"`
	Name       string          `json:"name"`
	Phase      model.JobState  `json:"phase"`
	State      model.StepState `json:"state"`
	Attempt    int             `json:"attempt"`
	StartedAt  *time.Time      `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
	Error      string          `json:"error"`
}

func toStepJSON(s model.JobStep) stepJSON {
	return stepJSON{Idx: s.Idx, Name: s.Name, Phase: s.Phase, State: s.State, Attempt: s.Attempt, StartedAt: optTime(s.StartedAt), FinishedAt: optTime(s.FinishedAt), Error: s.Error}
}

type logJSON struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Step    string    `json:"step"`
	Message string    `json:"message"`
}

func toLogJSON(l model.JobLog) logJSON {
	return logJSON{Seq: l.Seq, Time: l.Time, Level: l.Level, Step: l.Step, Message: l.Message}
}

func queryInt(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

func jobError(err error) error {
	switch {
	case errors.Is(err, jobs.ErrBusy):
		return &Error{Status: http.StatusConflict, Code: "server_busy", Message: "На этом сервере уже выполняется задание. Дождитесь его окончания."}
	case errors.Is(err, jobs.ErrNotRetryable):
		return &Error{Status: http.StatusConflict, Code: "not_retryable", Message: "Повторить можно только задание, которое завершилось ошибкой."}
	case errors.Is(err, jobs.ErrStale):
		return &Error{Status: http.StatusConflict, Code: "job_stale", Message: "Это задание устарело: после него на сервере выполнялись другие задания или обновился controller, его параметры могли измениться. Повторить можно только последнее задание сервера — запустите задание заново."}
	}
	return mapError(err)
}

func (s *server) listJobs(w http.ResponseWriter, r *http.Request) {
	js, err := s.Store.ListJobs(r.Context(), model.JobFilter{ServerID: queryInt(r, "server"), BeforeID: queryInt(r, "before"), Limit: int(queryInt(r, "limit"))})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]jobJSON, 0, len(js))
	for _, j := range js {
		out = append(out, toJobJSON(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	j, err := s.Store.JobByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	steps, err := s.Store.JobSteps(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := struct {
		jobJSON
		Steps []stepJSON `json:"steps"`
	}{jobJSON: toJobJSON(j), Steps: make([]stepJSON, 0, len(steps))}
	for _, st := range steps {
		out.Steps = append(out.Steps, toStepJSON(st))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) jobLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Store.JobByID(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	ls, err := s.Store.JobLogs(r.Context(), id, queryInt(r, "after"), int(queryInt(r, "limit")))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]logJSON, 0, len(ls))
	for _, l := range ls {
		out = append(out, toLogJSON(l))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) retryJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	// A cascade deleted without its unreachable server is for owners and
	// admins, its retry too.
	if j, err := s.Store.JobByID(r.Context(), id); err == nil && cascade.Forced(j) && !principal(r).User.Role.CanForce() {
		writeError(w, errForbidden)
		return
	}
	j, err := s.Jobs.Retry(r.Context(), id, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusOK, toJobJSON(j))
}

// sseKeepalive is how often an idle stream gets a comment line, so proxies
// do not close it; the session of a stream is checked as often.
var sseKeepalive = 20 * time.Second

// streamContext is the context of a live event stream: r's, which also
// ends when the controller shuts down (Deps.Streams) and as soon as the
// session of the stream ends (see endWithSession).
func (s *server) streamContext(r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(r.Context())
	if s.Auth != nil {
		go s.endWithSession(ctx, cancel, r)
	}
	if s.Streams == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(s.Streams, cancel)
	return ctx, func() { stop(); cancel() }
}

// endWithSession cancels a stream once its session ends by a logout, a
// revocation, a changed password or a blocked or deleted user: the
// keepalive checks it only every sseKeepalive.
func (s *server) endWithSession(ctx context.Context, cancel context.CancelFunc, r *http.Request) {
	ended := s.Auth.Revocations()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ended:
			ended = s.Auth.Revocations()
			if !s.sessionHolds(r) {
				cancel()
				return
			}
		}
	}
}

// jobEvents streams a job as server-sent events: the stored log lines
// after Last-Event-ID (or ?after=), then live "log", "step" and "job"
// events until the job finishes.
func (s *server) jobEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	j, err := s.Store.JobByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, errors.New("streaming unsupported"))
		return
	}
	after := queryInt(r, "after")
	if v, err := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64); err == nil {
		after = v
	}
	// Subscribe before reading what is stored: nothing falls in between.
	events, cancel := s.Jobs.Subscribe(id)
	defer func() { cancel() }()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, id int64, v any) error {
		b, _ := json.Marshal(v)
		if id > 0 {
			if _, err := fmt.Fprintf(w, "id: %d\n", id); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	last := after
	// replay sends the stored lines after last.
	replay := func() bool {
		for {
			ls, err := s.Store.JobLogs(r.Context(), id, last, 1000)
			if err != nil || len(ls) == 0 {
				return true
			}
			for _, l := range ls {
				if send("log", l.Seq, toLogJSON(l)) != nil {
					return false
				}
				last = l.Seq
			}
		}
	}
	// catchUp sends the stored lines after last, the job and its steps as
	// they are now, and the end if the job has finished; it reports
	// whether live events follow. It runs once subscribed, and again when
	// the subscription fell behind and was closed: what it missed is
	// stored.
	catchUp := func() bool {
		if !replay() {
			return false
		}
		// The job as it is once subscribed: later changes come as events.
		if cur, err := s.Store.JobByID(r.Context(), id); err == nil {
			j = cur
		}
		if send("job", 0, toJobJSON(j)) != nil {
			return false
		}
		// The steps as they are now: step events sent before the
		// subscription are not replayed.
		if steps, err := s.Store.JobSteps(r.Context(), id); err == nil {
			for _, st := range steps {
				if send("step", 0, toStepJSON(st)) != nil {
					return false
				}
			}
		}
		if j.State.Terminal() {
			// Lines written while the replay ran are stored: send them
			// before the end.
			if replay() {
				send("end", 0, struct{}{})
			}
			return false
		}
		return true
	}
	if !catchUp() {
		return
	}

	ctx, stop := s.streamContext(r)
	defer stop()
	keep := time.NewTicker(sseKeepalive)
	defer keep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keep.C:
			if !s.sessionHolds(r) {
				return
			}
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				// Fallen behind: subscribe again and catch up.
				events, cancel = s.Jobs.Subscribe(id)
				if !catchUp() {
					return
				}
				continue
			}
			switch ev.Type {
			case "log":
				if ev.Log.Seq <= last {
					continue
				}
				last = ev.Log.Seq
				if send("log", ev.Log.Seq, toLogJSON(*ev.Log)) != nil {
					return
				}
			case "step":
				if send("step", 0, toStepJSON(*ev.Step)) != nil {
					return
				}
			case "job":
				// Whatever is stored and not sent yet goes before the end.
				if ev.Job.State.Terminal() && !replay() {
					return
				}
				if send("job", 0, toJobJSON(*ev.Job)) != nil {
					return
				}
				if ev.Job.State.Terminal() {
					send("end", 0, struct{}{})
					return
				}
			}
		}
	}
}

func (s *server) startPreflight(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var opt preflight.Options
	if r.ContentLength > 0 {
		if err := readJSON(r, &opt); err != nil {
			writeError(w, err)
			return
		}
	}
	if opt.UDPPort < 0 || opt.UDPPort > 65535 {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Порт: от 1 до 65535.", Details: "udpPort"})
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	j, err := s.Jobs.Submit(r.Context(), preflight.JobKind, id, opt, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
