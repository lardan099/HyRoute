package api

import (
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

var errControllerLog = &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "Журнал controller — обо всех серверах: его видят пользователи со всеми серверами. Журналы заданий ваших серверов — на вкладке «Задания»."}

// logJSONEntry is a line of the Logs page, whatever its source.
type logEntryJSON struct {
	Time     time.Time `json:"time"`
	Level    string    `json:"level"`
	Message  string    `json:"message"`
	Attrs    string    `json:"attrs,omitempty"`
	ServerID int64     `json:"serverId,omitempty"`
	JobID    int64     `json:"jobId,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Step     string    `json:"step,omitempty"`
}

// logs is the Logs page: ?source=controller (the latest records of this
// process) or jobs (job logs of all servers, ?server=), with ?level= (and
// above), ?q= text and ?limit=. Both are redacted when written. The
// Hysteria journal of a server is /servers/{id}/journal. A user with a
// narrower scope gets the logs of their servers' jobs only: the
// controller's own records are about every server.
func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	level, text, limit := q.Get("level"), q.Get("q"), int(queryInt(r, "limit"))
	switch level {
	case "", "debug", "info", "warn", "error":
	default:
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Неизвестный уровень журнала.", Details: "level"})
		return
	}
	out := []logEntryJSON{}
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch q.Get("source") {
	case "controller", "":
		if !set.all {
			writeError(w, errControllerLog)
			return
		}
		if s.Logs != nil {
			for _, rec := range s.Logs.Records(logbuf.Filter{Level: level, Text: text, Limit: limit}) {
				out = append(out, logEntryJSON{Time: rec.Time, Level: rec.Level, Message: rec.Message, Attrs: rec.Attrs})
			}
		}
	case "jobs":
		hits, err := s.Store.SearchJobLogs(r.Context(), model.JobLogFilter{ServerID: queryInt(r, "server"), Level: level, Text: text, Limit: limit, Within: set.within()})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, h := range hits {
			out = append(out, logEntryJSON{Time: h.Time, Level: h.Level, Message: h.Message, ServerID: h.ServerID, JobID: h.JobID, Kind: h.Kind, Step: h.Step})
		}
	default:
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Неизвестный источник журнала.", Details: "source"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}
