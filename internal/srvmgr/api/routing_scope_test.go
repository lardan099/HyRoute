package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// config stores cfg as the deployed config of server.
func (s *scoped) config(server int64, cfg string) {
	s.t.Helper()
	c := model.ServerConfig{ServerID: server, SHA256: "x", Meta: model.ConfigMeta{Auth: "password"}, Source: model.ConfigDeploy, At: time.Now()}
	if err := s.db.AddConfig(context.Background(), &c, func(rev int) ([]byte, error) { return s.keys.Seal([]byte(cfg), model.ConfigContext(server, rev)) }); err != nil {
		s.t.Fatal(err)
	}
}

// deployed marks the link of chain deployed.
func (s *scoped) deployed(chain int64) {
	s.t.Helper()
	ch, err := s.db.ChainByID(context.Background(), chain)
	if err != nil {
		s.t.Fatal(err)
	}
	l := ch.Links[0]
	l.State = model.LinkActive
	if err := s.db.UpdateLink(context.Background(), l); err != nil {
		s.t.Fatal(err)
	}
}

// «Проверить правило» follows the cascade only while every server of it
// is in the caller's scope: the trace names the next servers, their roles
// and what their rules do.
func TestRoutingCheckStaysInScope(t *testing.T) {
	s := newScoped(t)
	s.config(s.b, "listen: :443\nauth:\n  type: password\n  password: fake-scope-b\nacl:\n  inline:\n    - reject(suffix:secret-of-b.example)\n    - direct(all)\n")
	s.deployed(s.ab)
	s.deployed(s.ac)
	check := func(c *client, server int64) string {
		t.Helper()
		rec := c.do("POST", "/api/v1/servers/"+id(server)+"/routing/check", map[string]any{
			"acl": acl.ParseInline(nil), "outbounds": []string{"cascade"},
			"request": acl.Request{Host: "x.secret-of-b.example", Port: 443},
		}, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"outbound":"cascade"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	// a → b: b is out of the operator's scope.
	if b := check(s.op, s.a); strings.Contains(b, `"chain"`) || strings.Contains(b, "«b»") || strings.Contains(b, `"name":"b"`) {
		t.Fatalf("the trace goes out of scope: %s", b)
	}
	if b := check(s.owner, s.a); !strings.Contains(b, `"chain":{`) || !strings.Contains(b, "Соединение отклонит «b».") {
		t.Fatalf("owner: %s", b)
	}
	// c → a: the whole cascade is in scope.
	if b := check(s.op, s.c); !strings.Contains(b, `"chain":{`) || !strings.Contains(b, `"name":"a"`) {
		t.Fatalf("in scope: %s", b)
	}
}

// A cascade not wholly in the caller's scope is named only as out of it:
// the routing view and «По сервисам» of its entry, the message about its
// outbound and the refusal of a new cascade through its servers.
func TestHiddenCascadeNotNamed(t *testing.T) {
	s := newScoped(t)
	s.config(s.a, "listen: :443\nauth:\n  type: password\n  password: fake-scope-a\nacl:\n  inline:\n    - cascade(all)\noutbounds:\n  - name: cascade\n    type: socks5\n    socks5:\n      addr: 127.0.0.1:40001\n")
	s.config(s.c, "listen: :443\nauth:\n  type: password\n  password: fake-scope-c\n")
	s.deployed(s.ab)
	hidden := `"cascade":{"name":"каскад вне вашей области","hidden":true}`
	named := `"cascade":{"id":` + id(s.ab) + `,"name":"ab"}`
	leaks := func(b string) bool { return strings.Contains(b, `"name":"ab"`) || strings.Contains(b, "«ab»") }
	for _, x := range []struct {
		c    *client
		want string
	}{{s.op, hidden}, {s.owner, named}} {
		for _, rq := range []struct{ method, path string }{{"GET", "/routing"}, {"POST", "/routing/services"}} {
			rec := x.c.do(rq.method, "/api/v1/servers/"+id(s.a)+rq.path, map[string]any{}, nil)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), x.want) || x.c == s.op && leaks(rec.Body.String()) {
				t.Fatalf("%s %s: %d %s", rq.method, rq.path, rec.Code, rec.Body)
			}
		}
	}
	// The outbound of the cascade stays: the refusal does not name it.
	rec := s.op.do("POST", "/api/v1/servers/"+id(s.a)+"/routing/preview", map[string]any{"base": 1, "acl": acl.ParseInline([]string{"direct(all)"}), "outbounds": []any{}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ведёт в каскад вне вашей области") || leaks(rec.Body.String()) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	// A new cascade through a: a is the entry of ab already.
	for _, x := range []struct {
		c    *client
		want string
	}{{s.op, "«a» уже вход каскада вне вашей области"}, {s.owner, "«a» уже вход каскада «ab»"}} {
		rec := x.c.do("POST", "/api/v1/chains", map[string]any{"name": "x", "nodes": []int64{s.a, s.c}}, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), x.want) {
			t.Fatalf("create: %d %s", rec.Code, rec.Body)
		}
	}
}
