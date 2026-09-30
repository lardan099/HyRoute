package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
