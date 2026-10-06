package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
)

// statusExec answers the status commands of a server with Hysteria
// running; /proc files come from this machine over SFTP.
func statusExec(ctx context.Context, line string, in io.Reader, out, errw io.Writer) int {
	cmd := strings.TrimPrefix(strings.TrimPrefix(line, "sudo -n -- "), "env LC_ALL=C LANG=C ")
	switch {
	case strings.HasPrefix(cmd, "systemctl show"):
		fmt.Fprint(out, "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=0\nMemoryCurrent=20971520\nActiveEnterTimestampMonotonic=1000000\nUnitFileState=enabled\n")
	case cmd == "nproc":
		fmt.Fprintln(out, "2")
	case strings.HasPrefix(cmd, "df -Pk"):
		fmt.Fprint(out, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 20000000 5000000 15360000 25% /\n")
	case strings.HasSuffix(cmd, "hysteria version"):
		fmt.Fprintln(out, "Version:\tv2.12.3")
	case strings.HasPrefix(cmd, "readlink -f -- "):
		fmt.Fprintln(out, strings.TrimPrefix(cmd, "readlink -f -- "))
	case strings.HasPrefix(cmd, "stat -L -c '%u %g %a' -- "):
		// The binary and its directories are root's.
		fmt.Fprint(out, strings.Repeat("0 0 755\n", len(strings.Fields(strings.TrimPrefix(cmd, "stat -L -c '%u %g %a' -- ")))))
	case strings.HasPrefix(cmd, "journalctl -u hysteria-server.service"):
		fmt.Fprintln(out, `{"__REALTIME_TIMESTAMP":"1790000000000000","PRIORITY":"6","MESSAGE":"2026-09-21T10:13:20Z\tINFO\tserver up and running\t{\"listen\": \":443\"}"}`)
		fmt.Fprintln(out, `{"__REALTIME_TIMESTAMP":"1790000001000000","PRIORITY":"6","MESSAGE":"2026-09-21T10:13:21Z\tWARN\tclient rejected\t{\"got\": \"fake-journal-auth-pass\"}"}`)
		fmt.Fprintln(out, `{"__REALTIME_TIMESTAMP":"1790000002000000","PRIORITY":"6","MESSAGE":"obfs fake-journal-obfs-pass and hysteria2://anything@192.0.2.9:443"}`)
	case cmd == "ss -Hlntup":
		fmt.Fprintln(out, `udp UNCONN 0 0 *:443 *:* users:(("hysteria",pid=4242,fd=7))`)
	default:
		return probeExec(ctx, line, in, out, errw)
	}
	return 0
}

func TestServiceAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	srv := sshtest.Start(t, "root", fakeSSHPass)
	srv.SetExec(statusExec)
	// The status reads these over SFTP: fixed Linux files, so the test does
	// not depend on the machine it runs on (Windows has no /proc).
	srv.SetFiles(map[string]string{
		"/proc/meminfo": "MemTotal:        2048000 kB\nMemFree:          512000 kB\nMemAvailable:    1024000 kB\n",
		"/proc/uptime":  "12345.67 23456.78\n",
		"/proc/loadavg": "0.10 0.20 0.30 1/100 4242\n",
	})
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": srv.Host, "sshPort": srv.Port, "authType": "password", "password": fakeSSHPass}, nil)
	var created serverJSON
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := strconv.FormatInt(created.ID, 10)

	code(t, owner.do("GET", "/api/v1/servers/"+id+"/status", nil, nil), http.StatusConflict, "no_installation")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/service/restart", nil, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: created.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true, At: time.Now()})
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/status", nil, nil), http.StatusConflict, "host_key_required")

	// Trust the test server's key as the admin would.
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	fp := decodeError(t, rec).Data.(map[string]any)["fingerprint"].(string)
	owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": fp}, nil)

	rec = owner.do("GET", "/api/v1/servers/"+id+"/status", nil, nil)
	var st service.Status
	json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != 200 || !st.Active || st.PID != 4242 || st.MemoryMiB != 20 || st.Version != "v2.12.3" || len(st.Ports) != 1 || st.System.CPUs != 2 || st.System.MemTotalMiB == 0 || st.System.UptimeSec == 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, l := range srv.Lines() {
		for _, bad := range []string{"systemctl restart", "systemctl stop", "systemctl start"} {
			if strings.Contains(l, bad) {
				t.Fatalf("status ran %q", l)
			}
		}
	}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/service/reboot", nil, nil), http.StatusNotFound, "not_found")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/service/restart", nil, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "service" || !strings.Contains(string(j.Params), `"action":"restart"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/service/stop", nil, nil), http.StatusConflict, "server_busy")
}

func TestJournalAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	srv := sshtest.Start(t, "root", fakeSSHPass)
	srv.SetExec(statusExec)
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": srv.Host, "sshPort": srv.Port, "authType": "password", "password": fakeSSHPass}, nil)
	var created serverJSON
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := strconv.FormatInt(created.ID, 10)
	e.db.SetInstallation(ctx, model.Installation{ServerID: created.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true, At: time.Now()})
	cfg := []byte("auth:\n  type: password\n  password: fake-journal-auth-pass\nobfs:\n  type: salamander\n  salamander:\n    password: fake-journal-obfs-pass\n")
	c := model.ServerConfig{ServerID: created.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(created.ID, rev)) })
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	fp := decodeError(t, rec).Data.(map[string]any)["fingerprint"].(string)
	owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": fp}, nil)

	rec = owner.do("GET", "/api/v1/servers/"+id+"/journal?lines=50", nil, nil)
	var es []service.Entry
	json.Unmarshal(rec.Body.Bytes(), &es)
	body := rec.Body.String()
	if rec.Code != 200 || len(es) != 3 || es[1].Level != "warn" || es[0].Message != `server up and running  {"listen": ":443"}` {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for _, secret := range []string{"fake-journal-auth-pass", "fake-journal-obfs-pass", "anything@"} {
		if strings.Contains(body, secret) {
			t.Fatalf("%s in the journal: %s", secret, body)
		}
	}

	// Live: the test server prints the records and exits, so the stream
	// ends with "end".
	srvHTTP := httptest.NewServer(e.h)
	defer srvHTTP.Close()
	req, _ := http.NewRequest("GET", srvHTTP.URL+"/api/v1/servers/"+id+"/journal?follow=1", nil)
	req.AddCookie(owner.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	stream := string(b)
	if resp.Header.Get("Content-Type") != "text/event-stream" || strings.Count(stream, "event: entry") != 3 || !strings.Contains(stream, "event: end") {
		t.Fatalf("%s", stream)
	}
	if strings.Contains(stream, "fake-journal-auth-pass") || strings.Contains(stream, "fake-journal-obfs-pass") {
		t.Fatalf("secret in the stream: %s", stream)
	}
	if !strings.Contains(strings.Join(srv.Lines(), "\n"), "-o json --output-fields=MESSAGE,PRIORITY -f") {
		t.Fatalf("%q", srv.Lines())
	}
}
