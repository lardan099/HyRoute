package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

func TestLogsAPI(t *testing.T) {
	e := newEnv(t)
	buf := logbuf.New(100, slog.LevelInfo)
	log := slog.New(redact.New().Handler(buf.Handler()))
	e.h = New(Deps{Store: e.db, Auth: e.auth, Servers: e.servers, Connect: e.connect, Jobs: e.jobs, Keys: e.keys, Logs: buf})
	owner := e.setupOwner()
	log.Info("controller started", "listen", "127.0.0.1:8080")
	log.Warn("ssh failed", "server", 3, "err", "password=fake-logs-secret rejected")

	rec := owner.do("GET", "/api/v1/logs?source=controller", nil, nil)
	var got []logEntryJSON
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || len(got) != 2 || got[0].Message != "ssh failed" || strings.Contains(rec.Body.String(), "fake-logs-secret") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/logs?source=controller&level=warn", nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 1 {
		t.Fatalf("%s", rec.Body)
	}
	rec = owner.do("GET", "/api/v1/logs?source=jobs&q=x", nil, nil)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/logs?source=hysteria", nil, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("GET", "/api/v1/logs?level=loud", nil, nil), http.StatusBadRequest, "invalid")
}
