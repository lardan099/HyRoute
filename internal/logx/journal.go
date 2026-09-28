package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one log line for the UI.
type Entry struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // debug | info | warn | error
	Msg   string    `json:"msg"`
}

// Journal is a numbered ring of log entries; the UI asks for everything
// after the last sequence number it has seen.
type Journal struct {
	// mu numbers an entry and stores it in one step: many goroutines log,
	// and an entry stored out of order would reach the UI twice or never
	// (Since relies on the ring being in Seq order).
	mu   sync.Mutex
	ring *Ring[Entry]
	seq  atomic.Uint64
}

func NewJournal(n int) *Journal { return &Journal{ring: NewRing[Entry](n)} }

func (j *Journal) Add(t time.Time, level, msg string) {
	j.mu.Lock()
	j.ring.Add(Entry{Seq: j.seq.Add(1), Time: t, Level: level, Msg: msg})
	j.mu.Unlock()
}

// Since returns entries with Seq > after, oldest first, at most limit
// (the newest ones) when limit > 0.
func (j *Journal) Since(after uint64, limit int) []Entry {
	all := j.ring.Snapshot()
	i := 0
	for i < len(all) && all[i].Seq <= after {
		i++
	}
	out := all[i:]
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	if out == nil {
		out = []Entry{} // JSON [] for the UI, not null
	}
	return out
}

// Tail returns the newest n entries (all when fewer), oldest first; never
// nil.
func (j *Journal) Tail(n int) []Entry {
	all := j.ring.Snapshot()
	if n >= 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	if all == nil {
		all = []Entry{}
	}
	return all
}

// Clear drops every entry (sequence numbers keep growing).
func (j *Journal) Clear() { j.ring.Clear() }

// Last is the newest sequence number.
func (j *Journal) Last() uint64 { return j.seq.Load() }

// Handler is a slog.Handler that formats records as "msg key=value ..."
// into a Journal (and optionally a text writer), redacting secrets.
type Handler struct {
	J        *Journal
	Redactor *Redactor
	Level    slog.Leveler
	Also     io.Writer

	attrs []slog.Attr
	group string
	mu    *sync.Mutex
}

func NewHandler(j *Journal, r *Redactor, level slog.Leveler, also io.Writer) *Handler {
	return &Handler{J: j, Redactor: r, Level: level, Also: also, mu: &sync.Mutex{}}
}

func (h *Handler) Enabled(_ context.Context, l slog.Level) bool {
	min := slog.LevelInfo
	if h.Level != nil {
		min = h.Level.Level()
	}
	return l >= min
}

func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		v := a.Value.String()
		if strings.ContainsAny(v, " \t\"") || v == "" {
			v = fmt.Sprintf("%q", v)
		}
		b.WriteString(" " + key + "=" + v)
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(func(a slog.Attr) bool { write(a); return true })
	msg := h.Redactor.Redact(b.String())
	level := strings.ToLower(r.Level.String())
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	h.J.Add(t, level, msg)
	if h.Also != nil {
		h.mu.Lock()
		fmt.Fprintf(h.Also, "%s %-5s %s\n", t.Format("2006-01-02 15:04:05.000"), strings.ToUpper(level), msg)
		h.mu.Unlock()
	}
	return nil
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), as...)
	return &c
}

func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	if c.group != "" {
		name = c.group + "." + name
	}
	c.group = name
	return &c
}
