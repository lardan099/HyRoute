package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// putGeo gives the controller small geo databases (geoip ru, geosite
// google) without downloading them.
func (e *testEnv) putGeo() {
	e.t.Helper()
	ip, _ := proto.Marshal(&v2geo.GeoIPList{Entry: []*v2geo.GeoIP{{CountryCode: "RU", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(5, 0, 0, 0).To4(), Prefix: 8}}}}})
	site, _ := proto.Marshal(&v2geo.GeoSiteList{Entry: []*v2geo.GeoSite{{CountryCode: "GOOGLE", Domain: []*v2geo.Domain{{Type: v2geo.Domain_RootDomain, Value: "google.com"}}}}})
	os.MkdirAll(filepath.Join(e.geo.Dir, "202610010000"), 0o700)
	i := geo.Info{Release: "202610010000", At: time.Now()}
	for name, b := range map[string][]byte{geo.GeoIP: ip, geo.GeoSite: site} {
		os.WriteFile(filepath.Join(e.geo.Dir, "202610010000", name), b, 0o600)
		s := sha256.Sum256(b)
		i.Files = append(i.Files, geo.File{Name: name, SHA256: hex.EncodeToString(s[:]), Size: int64(len(b))})
	}
	b, _ := json.Marshal(i)
	os.WriteFile(filepath.Join(e.geo.Dir, "info.json"), b, 0o600)
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A second update while one runs is 409 geo_busy at once.
func TestGeoUpdateBusy(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.geo.HTTP = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		once.Do(func() { close(entered) })
		<-release
		return nil, errors.New("no network in tests")
	})}
	done := make(chan struct{})
	go func() { e.geo.Update(t.Context()); close(done) }()
	<-entered
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	busy := make(chan *httptest.ResponseRecorder, 1)
	go func() { busy <- owner.do("POST", "/api/v1/geo/update", nil, nil) }()
	select {
	case rec := <-busy:
		code(t, rec, http.StatusConflict, "geo_busy")
	case <-time.After(5 * time.Second):
		t.Fatal("the second update waits for the first")
	}
	close(release)
	<-done
	code(t, owner.do("POST", "/api/v1/geo/update", nil, nil), http.StatusBadGateway, "geo_download")
	// The controller's own files are not a download: 500.
	os.MkdirAll(e.geo.Dir, 0o700)
	os.WriteFile(filepath.Join(e.geo.Dir, "info.json"), []byte("{"), 0o600)
	code(t, owner.do("POST", "/api/v1/geo/update", nil, nil), http.StatusInternalServerError, "internal")
}

func TestGeoAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	rec := owner.do("GET", "/api/v1/geo", nil, nil)
	var i geo.Info
	json.Unmarshal(rec.Body.Bytes(), &i)
	if rec.Code != 200 || i.Release != "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/geo/categories?kind=geosite", nil, nil), http.StatusNotFound, "no_geo")
	code(t, owner.do("GET", "/api/v1/geo/categories?kind=asn", nil, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/geo/update", nil, nil), http.StatusBadGateway, "geo_download")

	e.putGeo()
	rec = owner.do("GET", "/api/v1/geo/categories?kind=geosite&q=goo", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"names":["google"]`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// The rule check uses them.
	rec = owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	doc := acl.Parse("direct(geosite:google)\nproxy(geoip:ru)")
	rec = owner.do("POST", "/api/v1/servers/"+strconv.FormatInt(srv.ID, 10)+"/routing/check", map[string]any{"acl": doc, "outbounds": []string{"proxy"}, "request": acl.Request{Host: "mail.google.com", Port: 443}}, nil)
	var v acl.Verdict
	json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || v.Rule != 0 || len(v.Unknown) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// A server: its databases, then the job that puts them there.
	id := strconv.FormatInt(srv.ID, 10)
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-geo-api-auth\nacl:\n  inline:\n    - direct(geoip:ru)\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
	e.db.AddConfig(t.Context(), &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })
	rec = owner.do("GET", "/api/v1/servers/"+id+"/geo", nil, nil)
	if rec.Code != 200 || rec.Body.String() != `{"release":"","latest":false,"paths":false,"rules":true}`+"\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/geo", map[string]any{"source": "auto"}, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(t.Context(), model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(t.Context(), model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/geo", map[string]any{"source": "ftp"}, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/geo", map[string]any{"source": "relay"}, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "geo" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	var u model.User
	u.Username, u.Role, u.Scope = "viewer", model.RoleReadOnly, model.ScopeAll
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(t.Context(), &u)
	ro := e.login("viewer")
	code(t, ro.do("POST", "/api/v1/geo/update", nil, nil), http.StatusForbidden, "forbidden")
	if rec := ro.do("GET", "/api/v1/geo", nil, nil); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
}
