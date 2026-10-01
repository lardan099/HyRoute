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

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// tuningExec is a kernel with cubic loaded and the bbr module available.
func tuningExec(ctx context.Context, line string, in io.Reader, out, errw io.Writer) int {
	cmd := strings.TrimPrefix(strings.TrimPrefix(line, "sudo -n -- "), "env LC_ALL=C LANG=C ")
	switch {
	case strings.HasPrefix(cmd, "sysctl -e"):
		fmt.Fprint(out, "net.core.rmem_max = 212992\nnet.core.wmem_max = 212992\nnet.core.default_qdisc = fq_codel\nnet.ipv4.tcp_congestion_control = cubic\nnet.ipv4.tcp_available_congestion_control = reno cubic\n")
	case strings.HasPrefix(cmd, "modinfo -F name"):
		fmt.Fprintln(out, strings.Fields(cmd)[3])
	default:
		return probeExec(ctx, line, in, out, errw)
	}
	return 0
}

func TestTuningAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	srv := sshtest.Start(t, "root", fakeSSHPass)
	srv.SetExec(tuningExec)
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": srv.Host, "sshPort": srv.Port, "authType": "password", "password": fakeSSHPass}, nil)
	var created serverJSON
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := strconv.FormatInt(created.ID, 10)
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/tuning", nil, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: created.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true, At: time.Now()})
	cfg := "listen: :443\nauth:\n  type: password\n  password: fake-tuning-pass\ncongestion:\n  type: bbr\n  bbrProfile: aggressive\nbandwidth:\n  up: 500 mbps\n"
	c := model.ServerConfig{ServerID: created.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(created.ID, rev)) })
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	fp := decodeError(t, rec).Data.(map[string]any)["fingerprint"].(string)
	owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": fp}, nil)

	// Every role reads the state; nothing on the server changes.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	viewer := e.login("viewer")
	rec = viewer.do("GET", "/api/v1/servers/"+id+"/tuning", nil, nil)
	var st tuningJSON
	json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != http.StatusOK || !st.BBR || len(st.Settings) != 4 || st.QUIC.Type != "bbr" || st.QUIC.Profile != "aggressive" || st.Brutal.Up != "500 mbps" || strings.Contains(rec.Body.String(), "fake-tuning") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, l := range srv.Lines() {
		if strings.Contains(l, "sysctl -w") || strings.Contains(l, "sysctl -q") {
			t.Fatalf("read ran %q", l)
		}
	}
	code(t, viewer.do("POST", "/api/v1/servers/"+id+"/tuning", map[string]any{"keys": []string{"net.core.rmem_max"}}, nil), http.StatusForbidden, "forbidden")

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/tuning", map[string]any{"keys": []string{}}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/tuning", map[string]any{"keys": []string{"kernel.panic"}}, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/tuning", map[string]any{"keys": []string{"net.core.rmem_max", "net.ipv4.tcp_congestion_control"}}, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "tuning" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
