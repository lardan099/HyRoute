package redact

import (
	"context"
	"fmt"
	"log/slog"
)

// Handler wraps a slog handler: the message and every string, error or
// other value attribute pass through r before they are written.
func (r *Redactor) Handler(h slog.Handler) slog.Handler { return &handler{h: h, r: r} }

type handler struct {
	h slog.Handler
	r *Redactor
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.h.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.h.Handle(ctx, out)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(as))
	for i, a := range as {
		red[i] = h.attr(a)
	}
	return &handler{h: h.h.WithAttrs(red), r: h.r}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{h: h.h.WithGroup(name), r: h.r}
}

func (h *handler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	if IsSecretKey(a.Key) {
		return slog.String(a.Key, Mask)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.String(v.String()))
	case slog.KindGroup:
		gs := v.Group()
		red := make([]any, len(gs))
		for i, g := range gs {
			red[i] = h.attr(g)
		}
		return slog.Group(a.Key, red...)
	case slog.KindAny:
		return slog.String(a.Key, h.r.String(fmt.Sprint(v.Any())))
	}
	return slog.Attr{Key: a.Key, Value: v}
}
