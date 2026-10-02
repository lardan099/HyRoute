package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// testDB are small databases: geoip ru and private, geosite google and
// google-ads.
func testDB(t *testing.T, extra string) map[string][]byte {
	t.Helper()
	ip, err := proto.Marshal(&v2geo.GeoIPList{Entry: []*v2geo.GeoIP{
		{CountryCode: "RU", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(5, 0, 0, 0).To4(), Prefix: 8}}},
		{CountryCode: "PRIVATE", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(10, 0, 0, 0).To4(), Prefix: 8}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	site, err := proto.Marshal(&v2geo.GeoSiteList{Entry: []*v2geo.GeoSite{
		{CountryCode: "GOOGLE", Domain: []*v2geo.Domain{{Type: v2geo.Domain_RootDomain, Value: "google.com"}}},
		{CountryCode: "GOOGLE-ADS", Domain: []*v2geo.Domain{{Type: v2geo.Domain_Full, Value: "ads.google.com"}}},
		{CountryCode: strings.ToUpper(extra), Domain: []*v2geo.Domain{{Type: v2geo.Domain_Full, Value: "x.example"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{GeoIP: ip, GeoSite: site}
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// releases is a fake releases page: tag → files, with .sha256sum.
type releases struct {
	mu     sync.Mutex
	latest string
	files  map[string]map[string][]byte
	sums   map[string]string // name → a wrong hash to serve
	gets   []string
}

func (r *releases) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.gets = append(r.gets, q.URL.Path)
		p := strings.TrimPrefix(q.URL.Path, "/releases/")
		if p == "latest" {
			if r.latest == "" {
				http.NotFound(w, q)
				return
			}
			http.Redirect(w, q, "/releases/tag/"+r.latest, http.StatusFound)
			return
		}
		parts := strings.Split(p, "/") // download/<tag>/<name>
		if len(parts) != 3 || parts[0] != "download" {
			http.NotFound(w, q)
			return
		}
		name, sum := strings.CutSuffix(parts[2], ".sha256sum")
		b, ok := r.files[parts[1]][name]
		if !ok {
			http.NotFound(w, q)
			return
		}
		if sum {
			h := hash(b)
			if bad := r.sums[name]; bad != "" {
				h = bad
			}
			w.Write([]byte(h + "  " + name + "\n"))
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()
	r := &releases{latest: "202610010000", files: map[string]map[string][]byte{"202610010000": testDB(t, "one")}, sums: map[string]string{}}
	srv := r.serve(t)
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	s := &Store{Dir: filepath.Join(t.TempDir(), "geo"), Base: srv.URL + "/releases", HTTP: srv.Client(), Now: func() time.Time { return now }}

	if s.Loader() != nil {
		t.Fatal("a loader without databases")
	}
	if _, _, err := s.Open(GeoIP); err != ErrNone {
		t.Fatalf("open: %v", err)
	}
	i, changed, err := s.Update(ctx)
	if err != nil || !changed || i.Release != "202610010000" || len(i.Files) != 2 || !i.At.Equal(now) {
		t.Fatalf("%v %v %+v", err, changed, i)
	}
	if f, _ := i.File(GeoSite); f.SHA256 != hash(r.files["202610010000"][GeoSite]) || f.URL != srv.URL+"/releases/download/202610010000/geosite.dat" {
		t.Fatalf("%+v", f)
	}
	b, f, err := s.Open(GeoIP)
	if err != nil || hash(b) != f.SHA256 {
		t.Fatalf("%v", err)
	}
	l := s.Loader()
	ip, err := l.LoadGeoIP()
	if err != nil || ip["ru"] == nil || ip["private"] == nil {
		t.Fatalf("%v %v", err, ip)
	}
	if c, err := s.Categories("geosite", "GOO"); err != nil || !slices.Equal(c, []string{"google", "google-ads"}) {
		t.Fatalf("%v %v", c, err)
	}
	if c, _ := s.Categories("geoip", ""); !slices.Equal(c, []string{"private", "ru"}) {
		t.Fatalf("%v", c)
	}

	// The same release: nothing downloaded, the check is recorded.
	now = now.Add(time.Hour)
	r.gets = nil
	i, changed, err = s.Update(ctx)
	if err != nil || changed || !i.CheckedAt.Equal(now) || len(r.gets) != 1 {
		t.Fatalf("%v %v %+v %v", err, changed, i, r.gets)
	}

	// A newer release whose file does not match its hash, then one that
	// is not a database: the old files stay.
	for _, bad := range []func(){
		func() { r.sums[GeoSite] = strings.Repeat("0", 64) },
		func() { r.sums = map[string]string{}; r.files["202610030000"][GeoIP] = []byte("not a database") },
	} {
		r.latest = "202610030000"
		r.files["202610030000"] = testDB(t, "two")
		bad()
		if _, _, err := s.Update(ctx); err == nil {
			t.Fatal("a bad release passed")
		}
		if i, _ := s.Info(); i.Release != "202610010000" {
			t.Fatalf("replaced: %+v", i)
		}
		if _, _, err := s.Open(GeoSite); err != nil {
			t.Fatal(err)
		}
	}

	// A good newer release replaces them; the parsed databases follow.
	r.files["202610030000"] = testDB(t, "two")
	if i, changed, err = s.Update(ctx); err != nil || !changed || i.Release != "202610030000" {
		t.Fatalf("%v %v %+v", err, changed, i)
	}
	if c, _ := s.Categories("geosite", "two"); !slices.Equal(c, []string{"two"}) {
		t.Fatalf("%v", c)
	}

	// A file changed on the controller's disk is refused.
	os.WriteFile(filepath.Join(s.Dir, GeoIP), []byte("x"), 0o600)
	if _, _, err := s.Open(GeoIP); err == nil || !strings.Contains(err.Error(), "повреждён") {
		t.Fatalf("%v", err)
	}
}

func TestLatestRefused(t *testing.T) {
	r := &releases{files: map[string]map[string][]byte{}}
	srv := r.serve(t)
	s := &Store{Dir: t.TempDir(), Base: srv.URL + "/releases", HTTP: srv.Client()}
	if _, _, err := s.Update(context.Background()); err == nil {
		t.Fatal("no release passed")
	}
	r.latest = "../../etc"
	if _, _, err := s.Update(context.Background()); err == nil {
		t.Fatal("a bad tag passed")
	}
	var nilStore *Store
	if nilStore.Loader() != nil {
		t.Fatal("nil store")
	}
}
