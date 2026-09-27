package app

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
)

// hysteriaLine records one Hysteria log line in the profile's journal and
// in the merged one.
func (c *Controller) hysteriaLine(id string, l hysteria.LogLine) {
	msg := l.Msg
	if len(l.Fields) > 0 {
		keys := make([]string, 0, len(l.Fields))
		for k := range l.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString(msg)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%v", k, l.Fields[k])
		}
		msg = b.String()
	}
	if msg == "" {
		msg = l.Raw
	}
	t := l.Time
	if t.IsZero() {
		t = time.Now()
	}
	level := strings.ToLower(l.Level)
	if level == "" {
		level = "info"
	}
	msg = c.Redactor.Redact(msg)
	name := c.profileName(id)
	c.profileJournal(id).Add(t, level, msg)
	c.HysteriaLog.Add(t, level, "["+name+"] "+msg)
	if w := c.hysteriaFile(id, name); w != nil {
		fmt.Fprintf(w, "%s %-5s %s\n", t.Format("2006-01-02 15:04:05.000"), strings.ToUpper(level), msg)
	}
}

func (c *Controller) profileJournal(id string) *logx.Journal {
	c.hyMu.Lock()
	defer c.hyMu.Unlock()
	j := c.hyLogs[id]
	if j == nil {
		j = logx.NewJournal(3000)
		c.hyLogs[id] = j
	}
	return j
}

// Logs returns entries after seq of "engine", "hysteria" (every profile)
// or "hysteria:<profile id>".
func (c *Controller) Logs(kind string, after uint64) []logx.Entry {
	return c.journal(kind).Since(after, 2000)
}

// journal is the journal Logs names by kind.
func (c *Controller) journal(kind string) *logx.Journal {
	switch {
	case kind == "hysteria":
		return c.HysteriaLog
	case strings.HasPrefix(kind, "hysteria:"):
		return c.profileJournal(strings.TrimPrefix(kind, "hysteria:"))
	}
	return c.EngineLog
}

// NewFileHandler is a log handler that writes to the engine journal and
// to w (a log file).
func (c *Controller) NewFileHandler(level slog.Leveler, w io.Writer) slog.Handler {
	return logx.NewHandler(c.EngineLog, c.Redactor, level, w)
}
