package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

const fakeStatsSecret = "fake-api-stats-secret"

func TestTrafficAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	srv := sshtest.Start(t, "root", fakeSSHPass)
	// The stats API behind curl: the request comes on stdin.
	var mu sync.Mutex
	var stdins []string
	srv.SetExec(func(ctx context.Context, line string, in io.Reader, out, errw io.Writer) int {
		cmd := strings.TrimPrefix(line, "env LC_ALL=C LANG=C ")
		if !strings.HasPrefix(cmd, "curl ") {
			return probeExec(ctx, line, in, out, errw)
		}
		b, _ := io.ReadAll(in)
		mu.Lock()
		stdins = append(stdins, string(b))
		mu.Unlock()
		req := string(b)
		switch {
		case !strings.Contains(req, "Authorization: "+fakeStatsSecret):
			fmt.Fprint(out, "unauthorized\n\n401")
		case strings.Contains(req, "/online\""):
			fmt.Fprint(out, `{"bob":1,"alice":2}`+"\n200")
		case strings.Contains(req, "/dump/streams\""):
			fmt.Fprint(out, `{"streams":[{"state":"estab","auth":"alice","connection":1,"stream":4,"req_addr":"example.com:443","hooked_req_addr":"example.com:443","tx":10,"rx":20,"initial_at":"2026-10-01T12:00:00Z","last_active_at":"2026-10-01T12:00:01Z"},{"state":"estab","auth":"bob","connection":2,"stream":8,"req_addr":"example.org:443","hooked_req_addr":"example.org:443","tx":1000,"rx":2000,"initial_at":"2026-10-01T12:00:00Z","last_active_at":"2026-10-01T12:00:01Z"}]}`+"\n200")
		default:
			fmt.Fprint(out, "\n404")
		}
		return 0
	})
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": srv.Host, "sshPort": srv.Port, "authType": "password", "password": fakeSSHPass}, nil)
	var created serverJSON
	json.Unmarshal(rec.Body.Bytes(), &created)
	sid := created.ID
	id := strconv.FormatInt(sid, 10)
	e.db.SetInstallation(ctx, model.Installation{ServerID: sid, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true, At: time.Now()})
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	fp := decodeError(t, rec).Data.(map[string]any)["fingerprint"].(string)
	owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": fp}, nil)
	addConfig := func(cfg string) {
		c := model.ServerConfig{ServerID: sid, SHA256: "x", Source: model.ConfigEdit, At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(sid, rev)) })
	}
	const base = "listen: :443\nauth:\n  type: password\n  password: fake-api-auth\n"

	// Stats off: the stored traffic is empty and the live views say why.
	addConfig(base)
	var tr trafficJSON
	rec = owner.do("GET", "/api/v1/servers/"+id+"/traffic", nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &tr)
	if rec.Code != 200 || tr.Enabled || tr.Period != "24h" || len(tr.Hours) != 0 || tr.Users == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/traffic/online", nil, nil), http.StatusConflict, "stats_off")
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/traffic?period=1y", nil, nil), http.StatusBadRequest, "bad_request")

	addConfig(base + "trafficStats:\n  listen: 127.0.0.1:25413\n  secret: " + fakeStatsSecret + "\n")
	hour := time.Now().UTC().Truncate(time.Hour)
	e.db.AddTraffic(ctx, sid, hour.Add(-2*time.Hour), map[string]model.TrafficHour{"alice": {Tx: 100, Rx: 1000}, "bob": {Tx: 5, Rx: 5}})
	e.db.AddTraffic(ctx, sid, hour, map[string]model.TrafficHour{"bob": {Tx: 3000, Rx: 1}})
	e.db.AddTraffic(ctx, sid, hour.Add(-48*time.Hour), map[string]model.TrafficHour{"alice": {Tx: 7, Rx: 7}})
	rec = owner.do("GET", "/api/v1/servers/"+id+"/traffic", nil, nil)
	tr = trafficJSON{}
	json.Unmarshal(rec.Body.Bytes(), &tr)
	if !tr.Enabled || len(tr.Hours) != 2 || tr.Hours[0].Tx != 105 || tr.Hours[1].Rx != 1 || len(tr.Users) != 2 || tr.Users[0].User != "bob" || tr.Users[0].Tx != 3005 || tr.Users[1].Rx != 1000 {
		t.Fatalf("%s", rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/traffic?period=7d", nil, nil)
	tr = trafficJSON{}
	json.Unmarshal(rec.Body.Bytes(), &tr)
	if len(tr.Hours) != 3 || tr.Users[1].Tx != 107 {
		t.Fatalf("7d: %s", rec.Body)
	}

	rec = owner.do("GET", "/api/v1/servers/"+id+"/traffic/online", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"users":[{"user":"alice","connections":2},{"user":"bob","connections":1}]`) {
		t.Fatalf("online: %d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/traffic/streams", nil, nil)
	var st struct {
		Total   int `json:"total"`
		Streams []struct {
			User string `json:"user"`
			Addr string `json:"addr"`
		} `json:"streams"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != 200 || st.Total != 2 || st.Streams[0].User != "bob" || st.Streams[1].Addr != "example.com:443" {
		t.Fatalf("streams: %d %s", rec.Code, rec.Body)
	}

	// Read-only users see the traffic and who is online, not where they go.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/traffic", nil, nil), http.StatusOK, "")
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/traffic/online", nil, nil), http.StatusOK, "")
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/traffic/streams", nil, nil), http.StatusForbidden, "forbidden")

	// The server's config has another secret than the panel's.
	addConfig(base + "trafficStats:\n  listen: 127.0.0.1:25413\n  secret: fake-other-secret\n")
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/traffic/online", nil, nil), http.StatusConflict, "stats_auth")
	// An API off loopback (an imported config) is never asked.
	addConfig(base + "trafficStats:\n  listen: 192.0.2.7:25413\n  secret: " + fakeStatsSecret + "\n")
	mu.Lock()
	n := len(stdins)
	mu.Unlock()
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/traffic/online", nil, nil), http.StatusConflict, "stats_exposed")
	mu.Lock()
	if len(stdins) != n {
		t.Fatal("request sent to an API off loopback")
	}
	mu.Unlock()

	// The secret went only on stdin, never in a command line.
	for _, l := range srv.Lines() {
		if strings.Contains(l, "secret") {
			t.Fatalf("secret in a command line: %s", l)
		}
	}
}
