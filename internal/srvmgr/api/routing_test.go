package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
)

func TestRoutingAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	base := "/api/v1/servers/" + id + "/routing"
	code(t, owner.do("GET", base, nil, nil), http.StatusNotFound, "no_config")

	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-routing-api-auth\n" +
		"resolver:\n  type: https\n  https:\n    addr: 1.1.1.1:443\n" +
		"acl:\n  inline:\n    - reject(geoip:private)\n    - nl(suffix:example.com)\n" +
		"outbounds:\n  - name: direct\n    type: direct\n  - name: nl\n    type: socks5\n    socks5:\n      addr: 203.0.113.5:1080\n      password: fake-routing-api-socks\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })

	rec = owner.do("GET", base, nil, nil)
	var v routing.View
	json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || v.Revision != 1 || len(v.ACL.Rules) != 2 || len(v.Outbounds) != 2 || strings.Contains(rec.Body.String(), "fake-routing-api") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	in := routing.Input{Base: 1, ACL: v.ACL, Outbounds: v.Outbounds, Resolver: v.Resolver}
	in.ACL.Rules = append(in.ACL.Rules, acl.Rule{Outbound: "direct", Address: "geoip:ru"})
	rec = owner.do("POST", base+"/preview", in, nil)
	var p routing.Preview
	json.Unmarshal(rec.Body.Bytes(), &p)
	if rec.Code != 200 || !p.OK || strings.Contains(rec.Body.String(), "fake-routing-api") || !strings.Contains(p.YAML, "direct(geoip:ru)") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	bad := in
	bad.Base = 9
	code(t, owner.do("POST", base+"/preview", bad, nil), http.StatusConflict, "config_changed")

	rec = owner.do("POST", base+"/check", map[string]any{"acl": in.ACL, "outbounds": []string{"direct", "nl"}, "request": acl.Request{Host: "www.example.com", Port: 443}}, nil)
	var verdict acl.Verdict
	json.Unmarshal(rec.Body.Bytes(), &verdict)
	if rec.Code != 200 || verdict.Rule != 1 || verdict.Outbound != "nl" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", base+"/check", map[string]any{"acl": in.ACL, "request": acl.Request{Host: "x.com"}}, nil), http.StatusBadRequest, "invalid")

	rec = owner.do("GET", base+"/export", nil, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "fake-routing-api") || !strings.Contains(rec.Header().Get("Content-Disposition"), "routing-"+id+".json") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	exported := rec.Body.String()
	rec = owner.do("GET", base+"/export?format=text", nil, nil)
	if rec.Code != 200 || rec.Body.String() != "reject(geoip:private)\nnl(suffix:example.com)" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", base+"/export?format=xml", nil, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", "/api/v1/routing/import", map[string]string{"data": exported}, nil)
	var x routing.Export
	json.Unmarshal(rec.Body.Bytes(), &x)
	if rec.Code != 200 || len(x.ACL.Rules) != 2 || len(x.Outbounds) != 2 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/routing/import", map[string]string{"data": `{"format":"x"}`}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("GET", base+"/file", nil, nil), http.StatusBadRequest, "invalid")

	code(t, owner.do("POST", base+"/apply", in, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	unchanged := routing.Input{Base: 1, ACL: v.ACL, Outbounds: v.Outbounds, Resolver: v.Resolver}
	code(t, owner.do("POST", base+"/apply", unchanged, nil), http.StatusBadRequest, "invalid")
	broken := in
	broken.ACL.Rules = append(broken.ACL.Rules, acl.Rule{Outbound: "gone", Address: "all"})
	code(t, owner.do("POST", base+"/apply", broken, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", base+"/apply", in, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "apply" || strings.Contains(rec.Body.String(), "fake-routing-api") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	rec = owner.do("GET", "/api/v1/routing/templates", nil, nil)
	var tps []routing.Template
	json.Unmarshal(rec.Body.Bytes(), &tps)
	if rec.Code != 200 || len(tps) != 3 || tps[0].ID != "builtin:local" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// Read-only users see neither the routing nor the editor's checks.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	code(t, ro.do("GET", base, nil, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("POST", base+"/preview", in, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("GET", base+"/export", nil, nil), http.StatusForbidden, "forbidden")
}

func TestChainTemplatesAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	rec := owner.do("GET", "/api/v1/chain-templates", nil, nil)
	var ts []routing.ChainTemplate
	json.Unmarshal(rec.Body.Bytes(), &ts)
	if rec.Code != 200 || len(ts) != 2 || ts[1].Entry == nil || ts[1].Entry.Resolver.Type != "https" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	b, _ := json.Marshal(ts[1])
	rec = owner.do("POST", "/api/v1/chain-templates/import", map[string]string{"data": string(b)}, nil)
	var back routing.ChainTemplate
	json.Unmarshal(rec.Body.Bytes(), &back)
	if rec.Code != 200 || back.Builtin || back.ID != "" || back.Name != ts[1].Name || len(back.Entry.ACL.Rules) != len(ts[1].Entry.ACL.Rules) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/chain-templates/import", map[string]string{"data": `{"format":"x"}`}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("GET", "/api/v1/chains/999/template", nil, nil), http.StatusNotFound, "not_found")
}
