package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

var errNoInstallation = &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где на этом сервере Hysteria: разверните её или импортируйте сервер."}

// statusTimeout bounds a status read (connect and a dozen commands).
var statusTimeout = 30 * time.Second

// installed is the server's recorded installation, for handlers that act
// on it; a server without a confirmed host key or an installation gets
// the error that says what to do.
func (s *server) installed(r *http.Request, id int64) (model.Installation, error) {
	srv, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		return model.Installation{}, mapError(err)
	}
	in, err := s.Store.Installation(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return in, errNoInstallation
	} else if err != nil {
		return in, err
	}
	if srv.HostKey == nil {
		return in, errHostKeyRequired
	}
	return in, nil
}

func (s *server) serviceStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	in, err := s.installed(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusTimeout)
	defer cancel()
	ex, err := s.Connect.Connect(ctx, id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	defer ex.Close()
	ro := remote.ReadOnly(ex)
	p, err := remote.RunProbe(ctx, ro)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	st, err := service.Read(ctx, ro, in, !p.Root, time.Now())
	var nie *service.NotInstalledError
	if errors.As(err, &nie) {
		writeError(w, &Error{Status: http.StatusConflict, Code: "service_missing", Message: nie.Error()})
		return
	} else if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) serviceAction(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	a := remote.ServiceAction(r.PathValue("action"))
	switch a {
	case remote.ServiceStart, remote.ServiceStop, remote.ServiceRestart:
	default:
		writeError(w, errNotFound)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Jobs.Submit(r.Context(), service.JobKind, id, service.Params{Action: a}, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// journalLines is how many past records the journal starts with.
const journalLines = 200

// journal is the Hysteria journal of a server, redacted: JSON with the
// last records, or with ?follow=1 server-sent "entry" events that go on
// until the client leaves ("end" with an error message if the stream
// breaks).
func (s *server) journal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	in, err := s.installed(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	lines := journalLines
	if n := queryInt(r, "lines"); n > 0 && n <= 2000 {
		lines = int(n)
	}
	red, err := service.Redactor(r.Context(), s.Store, s.Keys, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cctx, cancel := context.WithTimeout(r.Context(), statusTimeout)
	ex, err := s.Connect.Connect(cctx, id)
	cancel()
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	defer ex.Close()
	ro := remote.ReadOnly(ex)
	p, err := remote.RunProbe(r.Context(), ro)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	if r.URL.Query().Get("follow") != "1" {
		es, err := remote.JournalEntries(r.Context(), ro, in.Unit, lines, !p.Root)
		if err != nil {
			s.fail(w, r, mapError(err))
			return
		}
		out := make([]service.Entry, 0, len(es))
		for _, e := range es {
			out = append(out, service.MakeEntry(e, red))
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, errors.New("streaming unsupported"))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	entries := make(chan service.Entry, 256)
	done := make(chan error, 1)
	ctx, stop := context.WithCancel(r.Context())
	defer stop()
	go func() {
		done <- remote.JournalFollow(ctx, ro, in.Unit, lines, !p.Root, func(e remote.JournalEntry) {
			select {
			case entries <- service.MakeEntry(e, red):
			case <-ctx.Done():
			}
		})
	}()
	send := func(event string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	keep := time.NewTicker(sseKeepalive)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-entries:
			if !send("entry", e) {
				return
			}
		case <-keep.C:
			if !s.sessionHolds(r) {
				return
			}
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case err := <-done:
			// Whatever is still queued goes out first.
			for {
				select {
				case e := <-entries:
					if !send("entry", e) {
						return
					}
					continue
				default:
				}
				break
			}
			msg := "Журнал закрыт на стороне сервера."
			if err != nil {
				msg = "Чтение журнала прервалось: " + redact.String(err.Error())
			}
			send("end", map[string]string{"message": msg})
			return
		}
	}
}
