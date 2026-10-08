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
