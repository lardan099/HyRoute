package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestDeployAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL", "host": "nl.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	good := map[string]any{"tls": "self-signed", "port": 443, "masquerade": "https://www.example.com"}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/deploy", good, nil), http.StatusConflict, "host_key_required")
	code(t, owner.do("POST", "/api/v1/servers/999/deploy", good, nil), http.StatusNotFound, "not_found")
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/config", nil, nil), http.StatusNotFound, "no_config")

	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	rec = owner.do("POST", "/api/v1/servers/"+id+"/deploy", map[string]any{"tls": "acme"}, nil)
	code(t, rec, http.StatusBadRequest, "invalid")
	if msg := decodeError(t, rec).Message; !strings.HasPrefix(msg, "Для сертификата Let's Encrypt нужен домен") {
		t.Fatalf("message: %q", msg)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/deploy", map[string]any{"tls": "self-signed", "port": 70000}, nil), http.StatusBadRequest, "invalid")

	rec = owner.do("POST", "/api/v1/servers/"+id+"/deploy", good, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("deploy: %d %s", rec.Code, rec.Body)
	}
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if j.Kind != "deploy" || j.ServerID != srv.ID || !strings.Contains(string(j.Params), `"masquerade":"https://www.example.com"`) || !strings.Contains(string(j.Params), `"version":"v2.12.3"`) {
		t.Fatalf("job: %s", rec.Body)
	}
	// The passwords are sealed with the job, never in its params.
	if strings.Contains(string(j.Params), "auth") || strings.Contains(string(j.Params), "BEGIN") {
		t.Fatalf("secrets in params: %s", j.Params)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/deploy", good, nil), http.StatusConflict, "server_busy")

	// A deployed config: its summary, never the config.
	meta := model.ConfigMeta{Version: "v2.12.3", Listen: ":443", Ports: "443", TLS: "self-signed", PinSHA256: strings.Repeat("ab", 32), Auth: "password"}
	cfg := model.ServerConfig{ServerID: srv.ID, SHA256: strings.Repeat("0", 64), Meta: meta, Source: model.ConfigDeploy, JobID: j.ID, At: time.Now()}
	err := e.db.AddConfig(ctx, &cfg, func(rev int) ([]byte, error) {
		return e.keys.Seal([]byte("auth:\n  type: password\n  password: fake-auth-for-api-test\n"), model.ConfigContext(srv.ID, rev))
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/config", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"pinSHA256":"abab`) || !strings.Contains(rec.Body.String(), `"revision":1`) || strings.Contains(rec.Body.String(), "fake-auth") {
		t.Fatalf("config: %d %s", rec.Code, rec.Body)
	}
	// An upgrade since: the installed version beside the revision's.
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", Version: "v2.13.0", Managed: true, At: time.Now()})
	if rec = owner.do("GET", "/api/v1/servers/"+id+"/config", nil, nil); !strings.Contains(rec.Body.String(), `"installed":"v2.13.0"`) {
		t.Fatalf("config: %d %s", rec.Code, rec.Body)
	}

	// A config changed in the editor: the deploy, which would rebuild it
	// from the form, asks first; with the confirmation it goes on (and
	// meets the queued job).
	edited := model.ServerConfig{ServerID: srv.ID, SHA256: strings.Repeat("1", 64), Meta: meta, Source: model.ConfigEdit, At: time.Now()}
	err = e.db.AddConfig(ctx, &edited, func(rev int) ([]byte, error) {
		return e.keys.Seal([]byte("auth:\n  type: password\n  password: fake-auth-for-api-test\nacl:\n  inline: [reject(all)]\n"), model.ConfigContext(srv.ID, rev))
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = owner.do("POST", "/api/v1/servers/"+id+"/deploy", good, nil)
	code(t, rec, http.StatusConflict, "config_changed")
	if msg := decodeError(t, rec).Message; !strings.Contains(msg, "ACL") {
		t.Fatalf("message: %q", msg)
	}
	overwrite := map[string]any{"tls": "self-signed", "port": 443, "overwrite": true}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/deploy", overwrite, nil), http.StatusConflict, "server_busy")

	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	code(t, ro.do("POST", "/api/v1/servers/"+id+"/deploy", good, nil), http.StatusForbidden, "forbidden")
	if rec := ro.do("GET", "/api/v1/servers/"+id+"/config", nil, nil); rec.Code != 200 {
		t.Fatalf("read-only config: %d", rec.Code)
	}
}

func TestImportAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "Old", "host": "old.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/import", nil, nil), http.StatusConflict, "host_key_required")
	code(t, owner.do("POST", "/api/v1/servers/999/import", nil, nil), http.StatusNotFound, "not_found")
	e.db.SetHostKey(context.Background(), model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	rec = owner.do("POST", "/api/v1/servers/"+id+"/import", nil, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "import" || j.ServerID != srv.ID {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/import", nil, nil), http.StatusConflict, "server_busy")
}

func TestMaintainAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL", "host": "nl.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	upgrade := map[string]any{"op": "upgrade", "version": "v2.12.3"}
	reinstall := map[string]any{"op": "reinstall"}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", upgrade, nil), http.StatusConflict, "no_installation")
	in := model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", Version: "v2.11.0", At: time.Now()}
	e.db.SetInstallation(ctx, in)
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", upgrade, nil), http.StatusConflict, "host_key_required")
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})

	// An imported installation: upgraded, not reinstalled.
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", reinstall, nil), http.StatusConflict, "not_managed")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", map[string]any{"op": "upgrade", "version": "latest"}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", map[string]any{"op": "remove"}, nil), http.StatusBadRequest, "invalid")

	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	code(t, e.login("viewer").do("POST", "/api/v1/servers/"+id+"/maintain", upgrade, nil), http.StatusForbidden, "forbidden")

	in.Managed = true
	e.db.SetInstallation(ctx, in)
	rec = owner.do("POST", "/api/v1/servers/"+id+"/maintain", reinstall, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	// A reinstall keeps the installed version.
	if rec.Code != http.StatusAccepted || j.Kind != "maintain" || !strings.Contains(string(j.Params), `"version":"v2.11.0"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/maintain", upgrade, nil), http.StatusConflict, "server_busy")
}

// The secrets of a deploy travel beside its params and stay out of them;
// ones that do not fit the params are refused.
func TestDeployAPISecrets(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL", "host": "nl.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})

	const token, pass = "fake-dns-token-api-test", "fake-proxy-pass-api-test"
	p := map[string]any{"tls": "acme", "domain": "vpn.example.com", "challenge": "dns", "dnsProvider": "cloudflare",
		"outbound": map[string]any{"type": "socks5", "addr": "127.0.0.1:40000", "user": "warp"}}

	p["secrets"] = map[string]any{"dns": map[string]string{"vultr_api_token": token}}
	rec = owner.do("POST", "/api/v1/servers/"+id+"/deploy", p, nil)
	code(t, rec, http.StatusBadRequest, "invalid")
	if msg := decodeError(t, rec).Message; !strings.Contains(msg, "vultr_api_token") || strings.Contains(msg, token) {
		t.Fatalf("message: %q", msg)
	}
	p["secrets"] = map[string]any{"dns": map[string]string{"cloudflare_api_token": token}, "outPassword": pass}
	rec = owner.do("POST", "/api/v1/servers/"+id+"/deploy", p, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("deploy: %d %s", rec.Code, rec.Body)
	}
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if strings.Contains(string(j.Params), token) || strings.Contains(string(j.Params), pass) || strings.Contains(string(j.Params), "secrets") ||
		!strings.Contains(string(j.Params), `"dnsProvider":"cloudflare"`) || !strings.Contains(string(j.Params), `"user":"warp"`) {
		t.Fatalf("params: %s", j.Params)
	}
}
