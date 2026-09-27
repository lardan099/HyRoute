package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fakeRelease struct {
	mu    sync.Mutex
	files map[string][]byte
	sums  map[string]string // override checksum
	hits  map[string]int
}

func (f *fakeRelease) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[r.URL.Path]++
	name := strings.TrimPrefix(r.URL.Path, "/")
	if base, ok := strings.CutSuffix(name, ".sha256sum"); ok {
		b, ok := f.files[base]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		if s, ok := f.sums[base]; ok {
			h = s
		}
		w.Write([]byte(h + "  " + base + "\n"))
		return
	}
	b, ok := f.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

func listBytes(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = pbytes(b, 1, e)
	}
	return b
}

func TestUpdater(t *testing.T) {
	rel := &fakeRelease{
		files: map[string][]byte{
			"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil})),
			"geoip.dat":   listBytes(ipEntry("RU", false, "77.88.0.0/18")),
		},
		sums: map[string]string{},
		hits: map[string]int{},
	}
	srv := httptest.NewServer(rel)
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat", IP: srv.URL + "/geoip.dat"}
	db := &DB{Dir: filepath.Join(t.TempDir(), "geo")}
	u := &Updater{DB: db}
	ctx := context.Background()

	res, err := u.Update(ctx, src, false)
	if err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if d, err := db.Site("youtube"); err != nil || !d.Match("youtube.com") {
		t.Fatal(err)
	}
	st := u.State()
	if st.Site == nil || !st.Site.Verified || st.Site.Categories != 1 || st.Source != "test" {
		t.Fatalf("%+v", st)
	}

	// Same checksum: nothing is downloaded again.
	res, err = u.Update(ctx, src, false)
	if err != nil || res.Changed || rel.hits["/geosite.dat"] != 1 {
		t.Fatalf("%v %+v hits %v", err, res, rel.hits)
	}

	// New version with a wrong checksum is refused, the old file stays.
	rel.mu.Lock()
	rel.files["geosite.dat"] = listBytes(siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil}))
	rel.sums["geosite.dat"] = strings.Repeat("ab", 32)
	rel.mu.Unlock()
	if _, err := u.Update(ctx, src, false); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
	if _, err := db.Site("youtube"); err != nil {
		t.Fatal("old database lost after a failed update")
	}

	// An HTML error page with a matching checksum is still refused.
	rel.mu.Lock()
	rel.files["geosite.dat"] = []byte("<html>rate limited</html>")
	delete(rel.sums, "geosite.dat")
	rel.mu.Unlock()
	if _, err := u.Update(ctx, src, false); err == nil || !strings.Contains(err.Error(), "не похож") {
		t.Fatalf("html accepted: %v", err)
	}

	// A good new version installs; rollback returns the old one and back.
	rel.mu.Lock()
	rel.files["geosite.dat"] = listBytes(siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil}))
	rel.mu.Unlock()
	if res, err := u.Update(ctx, src, false); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := db.Site("telegram"); err != nil {
		t.Fatal(err)
	}
	if !u.HasPrevious() {
		t.Fatal("no previous version kept")
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Site("youtube"); err != nil {
		t.Fatal("rollback did not restore the old database")
	}
	if u.State().Site == nil || u.State().Site.Categories != 1 {
		t.Fatalf("state after rollback: %+v", u.State().Site)
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Site("telegram"); err != nil {
		t.Fatal("second rollback must return to the newer database")
	}
	for _, n := range []string{"geosite.dat.new", "geoip.dat.new", "geosite.dat.swap"} {
		if _, err := os.Stat(filepath.Join(db.Dir, n)); err == nil {
			t.Fatalf("leftover %s", n)
		}
	}
}

func TestUpdaterMissingFile(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	u := &Updater{DB: &DB{Dir: t.TempDir()}}
	_, err := u.Update(context.Background(), Source{ID: "x", Site: srv.URL + "/geosite.dat"}, false)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatal(err)
	}
	if u.State().LastError == "" {
		t.Fatal("error not recorded")
	}
}

func newRelease(files map[string][]byte) (*fakeRelease, *httptest.Server) {
	rel := &fakeRelease{files: files, sums: map[string]string{}, hits: map[string]int{}}
	return rel, httptest.NewServer(rel)
}

func (f *fakeRelease) set(name string, b []byte) {
	f.mu.Lock()
	f.files[name] = b
	f.mu.Unlock()
}

func (f *fakeRelease) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// A failed switch to another source leaves the old files marked as files
// of the old source, so the switch is retried; a file that did arrive is
// not downloaded twice.
func TestUpdaterSourceSwitchFails(t *testing.T) {
	_, srvA := newRelease(map[string][]byte{
		"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil})),
		"geoip.dat":   listBytes(ipEntry("RU", false, "77.88.0.0/18")),
	})
	defer srvA.Close()
	relB, srvB := newRelease(map[string][]byte{
		"geosite.dat": listBytes(siteEntry("WHITELIST", dom{typeDomain, "ya.ru", nil})),
	})
	defer srvB.Close()
	a := Source{ID: "a", Site: srvA.URL + "/geosite.dat", IP: srvA.URL + "/geoip.dat"}
	b := Source{ID: "b", Site: srvB.URL + "/geosite.dat", IP: srvB.URL + "/geoip.dat"}
	u := &Updater{DB: &DB{Dir: t.TempDir()}}
	ctx := context.Background()
	if _, err := u.Update(ctx, a, false); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(ctx, b, false); err == nil {
		t.Fatal("missing geoip.dat not reported")
	}
	st := u.State()
	if st.Source != "a" || !st.From(Site, b.Site) || st.From(IP, b.IP) || !st.From(IP, a.IP) || st.Checked.IsZero() {
		t.Fatalf("%+v", st)
	}
	relB.set("geoip.dat", listBytes(ipEntry("DIRECT", false, "5.255.255.0/24")))
	if res, err := u.Update(ctx, b, false); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	st = u.State()
	if st.Source != "b" || !st.From(Site, b.Site) || !st.From(IP, b.IP) || relB.count("/geosite.dat") != 1 {
		t.Fatalf("%+v hits %d", st, relB.count("/geosite.dat"))
	}
}

// New custom links are downloaded although the source is still "custom",
// even when the file there is the same.
func TestUpdaterCustomLinksChange(t *testing.T) {
	file := listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))
	rel, srv := newRelease(map[string][]byte{"a/geosite.dat": file, "b/geosite.dat": file})
	defer srv.Close()
	u := &Updater{DB: &DB{Dir: t.TempDir()}}
	ctx := context.Background()
	a := Source{ID: "custom", Site: srv.URL + "/a/geosite.dat"}
	if _, err := u.Update(ctx, a, false); err != nil {
		t.Fatal(err)
	}
	b := Source{ID: "custom", Site: srv.URL + "/b/geosite.dat"}
	res, err := u.Update(ctx, b, false)
	st := u.State()
	if err != nil || res.Changed || rel.count("/b/geosite.dat") != 1 || !st.From(Site, b.Site) || !st.Site.Verified {
		t.Fatalf("%v %+v %+v", err, res, st.Site)
	}
}

func TestSumURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://h.example/r/geosite.dat":                       "https://h.example/r/geosite.dat.sha256sum",
		"https://github.com/u/r/blob/main/geosite.dat?raw=true": "https://github.com/u/r/blob/main/geosite.dat.sha256sum?raw=true",
		"https://h.example/a%20b/geo%2Fip.dat#top":              "https://h.example/a%20b/geo%2Fip.dat.sha256sum",
	} {
		if got := sumURL(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// The checksum of a link with a query is looked up next to the file.
func TestUpdaterQueryLink(t *testing.T) {
	_, srv := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))})
	defer srv.Close()
	u := &Updater{DB: &DB{Dir: t.TempDir()}}
	if _, err := u.Update(context.Background(), Source{ID: "custom", Site: srv.URL + "/geosite.dat?raw=true"}, false); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Site == nil || !st.Site.Verified {
		t.Fatalf("%+v", st.Site)
	}
}

// A host that refuses the checksum file or answers with a page instead
// has not published one: the file is installed unverified. A server error
// still blocks it.
func TestUpdaterSumNotPublished(t *testing.T) {
	file := listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))
	for _, tc := range []struct {
		status int
		body   string
		ok     bool
	}{
		{http.StatusForbidden, "<Error>AccessDenied</Error>", true},
		{http.StatusUnauthorized, "", true},
		{http.StatusGone, "", true},
		{http.StatusOK, "<!DOCTYPE html><html>blob</html>", true},
		{http.StatusOK, "", true},
		{http.StatusInternalServerError, "", false},
		{http.StatusTooManyRequests, "", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sha256sum") {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
				return
			}
			w.Write(file)
		}))
		u := &Updater{DB: &DB{Dir: t.TempDir()}}
		_, err := u.Update(context.Background(), Source{ID: "x", Site: srv.URL + "/geosite.dat"}, false)
		st := u.State()
		srv.Close()
		if tc.ok && (err != nil || st.Site == nil || st.Site.Verified) {
			t.Errorf("%d %q: %v %+v", tc.status, tc.body, err, st.Site)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "контрольную сумму") || st.Site != nil) {
			t.Errorf("%d: installed without a checksum: %v", tc.status, err)
		}
	}
}

// installTwice installs two versions of both databases, so both have a
// .prev: YOUTUBE and RU, then TELEGRAM and NL.
func installTwice(t *testing.T) (*Updater, *DB) {
	t.Helper()
	rel, srv := newRelease(map[string][]byte{
		"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil})),
		"geoip.dat":   listBytes(ipEntry("RU", false, "77.88.0.0/18")),
	})
	t.Cleanup(srv.Close)
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat", IP: srv.URL + "/geoip.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	if _, err := u.Update(context.Background(), src, false); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", listBytes(siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil})))
	rel.set("geoip.dat", listBytes(ipEntry("NL", false, "5.255.255.0/24")))
	if _, err := u.Update(context.Background(), src, false); err != nil {
		t.Fatal(err)
	}
	return u, db
}

// Rollback is all or nothing: when one file cannot be swapped, the other
// is swapped back, and the state describes the files on disk.
func TestRollbackAllOrNothing(t *testing.T) {
	u, db := installTwice(t)
	before := u.State()
	// geoip.dat cannot be moved aside: a directory is in the way.
	block := filepath.Join(db.Dir, "geoip.dat.swap")
	if err := os.MkdirAll(filepath.Join(block, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := u.Rollback(); err == nil {
		t.Fatal("rollback reported success")
	}
	if _, err := db.Site("telegram"); err != nil {
		t.Fatal("geosite.dat left rolled back alone")
	}
	if st := u.State(); st.Site.SHA256 != before.Site.SHA256 || st.IP.SHA256 != before.IP.SHA256 {
		t.Fatalf("state changed: %+v", st)
	}
	if err := os.RemoveAll(block); err != nil {
		t.Fatal(err)
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Site("youtube"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.IP("ru"); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Site.SHA256 == before.Site.SHA256 || st.IP.SHA256 == before.IP.SHA256 {
		t.Fatalf("state not rolled back: %+v", st)
	}
}

// On Windows a database open in another program (without delete sharing)
// cannot be renamed: the update fails, but the previous version is kept.
func TestUpdateBusyKeepsPrevious(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("an open file blocks a rename only on Windows")
	}
	rel, srv := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	for _, cat := range []string{"TELEGRAM", "DISCORD"} {
		if _, err := u.Update(ctx, src, false); err != nil {
			t.Fatal(err)
		}
		rel.set("geosite.dat", listBytes(siteEntry(cat, dom{typeDomain, "x.com", nil})))
	}
	prev, err := os.ReadFile(filepath.Join(db.Dir, "geosite.dat.prev"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(db.Dir, "geosite.dat"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.Update(ctx, src, false)
	f.Close()
	if err == nil {
		t.Fatal("replaced an open file")
	}
	if b, err := os.ReadFile(filepath.Join(db.Dir, "geosite.dat.prev")); err != nil || string(b) != string(prev) {
		t.Fatalf("previous version lost: %v", err)
	}
}
