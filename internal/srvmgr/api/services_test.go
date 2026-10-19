package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// putServiceGeo gives the controller geo databases with geosite youtube
// and telegram and geoip telegram, without downloading them.
func (e *testEnv) putServiceGeo() {
	e.t.Helper()
	ip, _ := proto.Marshal(&v2geo.GeoIPList{Entry: []*v2geo.GeoIP{{CountryCode: "TELEGRAM", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(198, 51, 100, 0).To4(), Prefix: 24}}}}})
	site, _ := proto.Marshal(&v2geo.GeoSiteList{Entry: []*v2geo.GeoSite{
		{CountryCode: "YOUTUBE", Domain: []*v2geo.Domain{{Type: v2geo.Domain_RootDomain, Value: "youtube.com"}}},
		{CountryCode: "TELEGRAM", Domain: []*v2geo.Domain{{Type: v2geo.Domain_RootDomain, Value: "telegram.org"}}},
	}})
	dir := filepath.Join(e.geo.Dir, "202610010000")
	os.MkdirAll(dir, 0o700)
	i := geo.Info{Release: "202610010000", At: time.Now()}
	for name, b := range map[string][]byte{geo.GeoIP: ip, geo.GeoSite: site} {
		os.WriteFile(filepath.Join(dir, name), b, 0o600)
		s := sha256.Sum256(b)
		i.Files = append(i.Files, geo.File{Name: name, SHA256: hex.EncodeToString(s[:]), Size: int64(len(b))})
	}
	b, _ := json.Marshal(i)
	os.WriteFile(filepath.Join(e.geo.Dir, "info.json"), b, 0o600)
}

// The «По сервисам» tab: the services the controller's databases have,
// the group built into the draft and read back; "through the exit" off a
// cascade entry, a hidden service and an edited group without overwrite
// are refused.
func TestRoutingServicesAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	base := "/api/v1/servers/" + strconv.FormatInt(srv.ID, 10) + "/routing"
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-services-api-auth\n" +
		"acl:\n  inline:\n    - reject(geoip:private)\n    - nl(all)\n" +
		"outbounds:\n  - name: nl\n    type: socks5\n    socks5:\n      addr: 203.0.113.5:1080\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })
	draft := acl.Parse("reject(geoip:private)\nnl(all)")

	// No databases at the controller: no service.
	rec = owner.do("POST", base+"/services", map[string]any{"acl": draft}, nil)
	var v routing.ServicesView
	json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || !v.NoGeo || len(v.Sections) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	e.putServiceGeo()
	rec = owner.do("POST", base+"/services", map[string]any{"acl": draft}, nil)
	v = routing.ServicesView{}
	json.Unmarshal(rec.Body.Bytes(), &v)
	var shown []string
	for _, s := range v.Sections {
		for _, c := range s.Services {
			shown = append(shown, c.ID)
		}
	}
	if rec.Code != 200 || v.NoGeo || v.Cascade != nil || v.State.Found || strings.Join(shown, ",") != "youtube,telegram" || v.Version != routing.ServicesVersion {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	build := func(choices map[string]string, overwrite bool, doc acl.Document) *routing.ServicesResult {
		rec := owner.do("POST", base+"/services/build", routing.ServicesInput{ACL: doc, Outbounds: []string{"nl"}, Choices: choices, Overwrite: overwrite}, nil)
		if rec.Code != 200 {
			return nil
		}
		var res routing.ServicesResult
		json.Unmarshal(rec.Body.Bytes(), &res)
		return &res
	}
	code(t, owner.do("POST", base+"/services/build", routing.ServicesInput{ACL: draft, Choices: map[string]string{"youtube": "cascade"}}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", base+"/services/build", routing.ServicesInput{ACL: draft, Choices: map[string]string{"netflix": "direct"}}, nil), http.StatusBadRequest, "invalid")
	res := build(map[string]string{"youtube": "nl", "telegram": "direct"}, false, draft)
	if res == nil || !strings.Contains(res.ACL.Text(), "reject(geoip:private)\n#~group По сервисам\n") ||
		!strings.Contains(res.ACL.Text(), "nl(geosite:youtube) # YouTube\ndirect(geosite:telegram) # Telegram\ndirect(geoip:telegram) # Telegram\n#~group\nnl(all)") ||
		res.State.Edited || res.State.Choices["youtube"] != "nl" {
		t.Fatalf("%+v", res)
	}

	// Reopening the tab reads the group back.
	rec = owner.do("POST", base+"/services", map[string]any{"acl": res.ACL}, nil)
	v = routing.ServicesView{}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || !v.State.Found || v.State.Edited || v.State.Choices["telegram"] != "direct" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// A rule of the admin's own in the group: told before it is overwritten.
	edited := acl.Parse(strings.Replace(res.ACL.Text(), "direct(geoip:telegram) # Telegram", "direct(geoip:telegram) # Telegram\ndirect(suffix:example.org)", 1))
	rec = owner.do("POST", base+"/services/build", routing.ServicesInput{ACL: edited, Outbounds: []string{"nl"}, Choices: map[string]string{"youtube": "direct"}}, nil)
	code(t, rec, http.StatusConflict, "services_edited")
	if !strings.Contains(decodeError(t, rec).Message, "direct(suffix:example.org)") {
		t.Fatalf("%s", rec.Body)
	}
	if res := build(map[string]string{"youtube": "direct"}, true, edited); res == nil || strings.Contains(res.ACL.Text(), "example.org") || res.State.Edited {
		t.Fatalf("%+v", res)
	}

	// Read-only users do not use the editor.
	var u model.User
	u.Username, u.Role, u.Scope = "viewer", model.RoleReadOnly, model.ScopeAll
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	code(t, ro.do("POST", base+"/services", map[string]any{"acl": draft}, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("POST", base+"/services/build", routing.ServicesInput{ACL: draft}, nil), http.StatusForbidden, "forbidden")
}
