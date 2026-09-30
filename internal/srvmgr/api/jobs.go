package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
)

type jobJSON struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	ServerID    int64           `json:"serverId"`
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
	return jobJSON{ID: j.ID, Kind: j.Kind, ServerID: j.ServerID, State: j.State, CurrentStep: j.CurrentStep, Params: params, Data: data,
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
	j, err := s.Jobs.Retry(r.Context(), id, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusOK, toJobJSON(j))
}

// sseKeepalive is how often an idle stream gets a comment line, so proxies
// do not close it.
var sseKeepalive = 20 * time.Second

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
	defer cancel()

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
	if !replay() {
		return
	}
	if send("job", 0, toJobJSON(j)) != nil {
		return
	}
	// The steps as they are now: step events sent before the subscription
	// are not replayed.
	if steps, err := s.Store.JobSteps(r.Context(), id); err == nil {
		for _, st := range steps {
			if send("step", 0, toStepJSON(st)) != nil {
				return
			}
		}
	}
	// The job may have ended between reading it and subscribing.
	if cur, err := s.Store.JobByID(r.Context(), id); err == nil {
		j = cur
	}
	if j.State.Terminal() {
		// Lines written while the replay ran are stored: send them before
		// the end.
		if !replay() {
			return
		}
		send("job", 0, toJobJSON(j))
		send("end", 0, struct{}{})
		return
	}

	keep := time.NewTicker(sseKeepalive)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
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
				// A line the subscription missed (a full buffer) is stored.
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
