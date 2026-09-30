package logbuf

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

func TestBuffer(t *testing.T) {
	b := New(3, slog.LevelInfo)
	// As main wires it: redaction first, then the buffer.
	log := slog.New(redact.New().Handler(b.Handler()))
	log.Debug("not kept")
	log.Info("started", "listen", "127.0.0.1:8080")
	log.With("server", 7).Warn("ssh failed", "err", "auth failed with password=fake-log-secret")
	log.WithGroup("http").Error("panic in handler", "path", "/api/v1/servers")
	log.Info("fourth")
	all := b.Records(Filter{})
	if len(all) != 3 || all[0].Message != "fourth" || all[2].Message != "ssh failed" || all[0].Seq != 4 {
		t.Fatalf("%+v", all)
	}
	if strings.Contains(all[2].Attrs, "fake-log-secret") || !strings.Contains(all[2].Attrs, "server=7") {
		t.Fatalf("attrs %q", all[2].Attrs)
	}
	if all[1].Attrs != "http.path=/api/v1/servers" || all[1].Level != "error" {
		t.Fatalf("%+v", all[1])
	}
	if got := b.Records(Filter{Level: "warn"}); len(got) != 2 {
		t.Fatalf("warn+: %d", len(got))
	}
	if got := b.Records(Filter{Text: "SSH"}); len(got) != 1 || got[0].Level != "warn" {
		t.Fatalf("text: %+v", got)
	}
	if got := b.Records(Filter{Limit: 1}); len(got) != 1 || got[0].Message != "fourth" {
		t.Fatalf("limit: %+v", got)
	}
}
