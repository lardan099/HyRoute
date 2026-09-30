// Package logbuf keeps the controller's latest log records in memory for
// the admin's Logs page. It is a slog.Handler: put it behind the
// redacting handler, so it only ever holds redacted text.
package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Record is one log record as the Logs page shows it.
type Record struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // debug, info, warn, error
	Message string    `json:"message"`
	// Attrs are the record's fields, "key=value" separated by spaces.
	Attrs string `json:"attrs,omitempty"`
}

// Buffer is a ring of the latest records.
type Buffer struct {
	mu    sync.Mutex
	recs  []Record
	next  int
	full  bool
	seq   int64
	level slog.Leveler
}

// New keeps the latest n records at level and above.
func New(n int, level slog.Leveler) *Buffer {
	return &Buffer{recs: make([]Record, n), level: level}
}

// Filter selects records; zero fields select everything.
type Filter struct {
	Level string // this level and above
	Text  string // case-insensitive, in the message or the fields
	Limit int
}

var levelRank = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

// Records returns matching records, newest first.
func (b *Buffer) Records(f Filter) []Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f.Limit <= 0 || f.Limit > len(b.recs) {
		f.Limit = len(b.recs)
	}
	min := levelRank[f.Level]
	text := strings.ToLower(f.Text)
	out := []Record{}
	n := b.next
	if b.full {
		n = len(b.recs)
	}
	for i := 0; i < n && len(out) < f.Limit; i++ {
		r := b.recs[(b.next-1-i+len(b.recs))%len(b.recs)]
		if levelRank[r.Level] < min {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(r.Message+" "+r.Attrs), text) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (b *Buffer) add(r Record) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	r.Seq = b.seq
	b.recs[b.next] = r
	b.next = (b.next + 1) % len(b.recs)
	b.full = b.full || b.next == 0
}

// Handler is the slog side of the buffer.
func (b *Buffer) Handler() slog.Handler { return &handler{b: b} }

type handler struct {
	b     *Buffer
	attrs []string
	group string
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.b.level.Level() }

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	attrs := append([]string(nil), h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, h.format(a))
		return true
	})
	h.b.add(Record{Time: r.Time, Level: levelName(r.Level), Message: r.Message, Attrs: strings.Join(attrs, " ")})
	return nil
}

func (h *handler) format(a slog.Attr) string {
	k := a.Key
	if h.group != "" {
		k = h.group + "." + k
	}
	v := a.Value.Resolve().String()
	if strings.ContainsAny(v, " \t\n\"") {
		v = fmt.Sprintf("%q", v)
	}
	return k + "=" + v
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	n := &handler{b: h.b, group: h.group, attrs: append([]string(nil), h.attrs...)}
	for _, a := range as {
		n.attrs = append(n.attrs, h.format(a))
	}
	return n
}

func (h *handler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &handler{b: h.b, attrs: h.attrs, group: g}
}
