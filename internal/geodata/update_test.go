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
	"time"
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
	for _, pat := range []string{"*.new", "*.tmp", "*.swap"} {
		if m, _ := filepath.Glob(filepath.Join(db.Dir, pat)); len(m) > 0 {
			t.Fatalf("leftover %v", m)
		}
	}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A damaged file is replaced by the same version: geo.json describing the
// right version does not make the file on disk right.
func TestUpdaterRepairsDamagedFile(t *testing.T) {
	file := listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))
	_, srv := newRelease(map[string][]byte{"geosite.dat": file})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	for _, force := range []bool{false, true} {
		// A power cut after the update left zeros in the file.
		if err := os.WriteFile(db.path(Site), make([]byte, len(file)), 0o600); err != nil {
			t.Fatal(err)
		}
		db.Forget()
		if _, err := db.Site("youtube"); err == nil {
			t.Fatal("damaged file read")
		}
		if res, err := u.Update(ctx, src, force); err != nil || !res.Changed {
			t.Fatalf("force %v: %v %+v", force, err, res)
		}
		if d, err := db.Site("youtube"); err != nil || !d.Match("youtube.com") {
			t.Fatalf("force %v: not repaired: %v", force, err)
		}
		// The damaged file is not kept for a rollback.
		if u.HasPrevious() {
			t.Fatalf("force %v: damaged file kept as .prev", force)
		}
	}
}

// A damaged previous version is not rolled back to.
func TestRollbackDamagedPrevious(t *testing.T) {
	rel, srv := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("V1", dom{typeDomain, "a.com", nil}))})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", listBytes(siteEntry("V2", dom{typeDomain, "b.com", nil})))
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(db.path(Site) + ".prev")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db.path(Site)+".prev", make([]byte, fi.Size()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := u.Rollback(); err == nil || !strings.Contains(err.Error(), "повреждена") {
		t.Fatalf("rolled back to a damaged file: %v", err)
	}
	if _, err := db.Site("v2"); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Site == nil || st.Site.HeldFor != "" || !st.From(Site, src.Site) {
		t.Fatalf("%+v", st.Site)
	}
}

// Temporary files an interrupted update left behind are removed, planted
// links without touching their targets.
func TestUpdaterRemovesLeftovers(t *testing.T) {
	_, srv := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("V1", dom{typeDomain, "a.com", nil}))})
	defer srv.Close()
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := []string{"geosite.dat.123.new", "geoip.dat.45.new", "geo.json.6.tmp", "geosite.dat.prev.json.7.tmp", "geosite.dat.new", "geoip.dat.new", "geo.json.tmp"}
	for _, n := range junk {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linked := os.Link(victim, filepath.Join(dir, "geoip.dat.8.new")) == nil
	keep := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &Updater{DB: &DB{Dir: dir}}
	if _, err := u.Update(context.Background(), Source{ID: "test", Site: srv.URL + "/geosite.dat"}, false); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if want := "geo.json geosite.dat notes.txt"; strings.Join(names, " ") != want {
		t.Fatalf("%v, want %s", names, want)
	}
	if b, err := os.ReadFile(victim); linked && (err != nil || string(b) != "keep") {
		t.Fatalf("link target touched: %v %q", err, b)
	}
}

// HyRoute runs elevated and the folder is the user's: links planted under
// the names of its temporary and state files must not make it write to
// (or read) the files they point to.
func TestUpdaterNoWriteThroughLinks(t *testing.T) {
	rel, srv := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"geosite.dat.new", "geo.json.tmp", "geosite.dat.prev.json", "geo.json"} {
		if err := os.Link(victim, filepath.Join(dir, n)); err != nil {
			t.Skipf("no hard links here: %v", err)
		}
	}
	u := &Updater{DB: &DB{Dir: dir}}
	ctx := context.Background()
	for _, cat := range []string{"TELEGRAM", ""} {
		if _, err := u.Update(ctx, src, false); err != nil {
			t.Fatal(err)
		}
		if cat != "" {
			rel.set("geosite.dat", listBytes(siteEntry(cat, dom{typeDomain, "t.me", nil})))
		}
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Fatalf("written through a link: %v %q", err, b)
	}
	if st := u.State(); st.Site == nil || st.Site.Categories != 1 {
		t.Fatalf("%+v", st.Site)
	}
}

// A redirect from https to http is refused: the checksum would come over
// the same unprotected way as the file.
func TestNoDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "/geosite.dat", http.StatusFound)
			return
		}
		w.Write([]byte("data"))
	}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/self" {
			http.Redirect(w, r, "/geosite.dat", http.StatusFound)
			return
		}
		if r.URL.Path == "/geosite.dat" {
			w.Write([]byte("data"))
			return
		}
		http.Redirect(w, r, plain.URL+"/geosite.dat", http.StatusFound)
	}))
	defer tls.Close()
	cl := tls.Client()
	cl.CheckRedirect = NoDowngrade
	if resp, err := cl.Get(tls.URL + "/down"); err == nil || !strings.Contains(err.Error(), "https://") {
		if err == nil {
			resp.Body.Close()
		}
		t.Fatalf("https → http followed: %v", err)
	}
	for _, url := range []string{tls.URL + "/self", plain.URL + "/hop"} {
		resp, err := cl.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		resp.Body.Close()
	}
}

// After Rollback the scheduled update keeps the restored file instead of
// putting back the version rolled back from; a new version, or the user's
// own update, replaces it.
func TestRollbackKeptBySchedule(t *testing.T) {
	yt := listBytes(siteEntry("YOUTUBE", dom{typeDomain, "youtube.com", nil}))
	_, srvA := newRelease(map[string][]byte{"geosite.dat": yt})
	defer srvA.Close()
	relB, srvB := newRelease(map[string][]byte{"geosite.dat": listBytes(siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil}))})
	defer srvB.Close()
	a := Source{ID: "a", Site: srvA.URL + "/geosite.dat"}
	b := Source{ID: "b", Site: srvB.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	for _, src := range []Source{a, b} {
		if _, err := u.Update(ctx, src, false); err != nil {
			t.Fatal(err)
		}
	}
	// Back to the file of source a while b is chosen.
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); !st.Held(Site, b.Site) || st.From(Site, b.Site) || st.Site.SHA256 != sha(yt) {
		t.Fatalf("%+v", st.Site)
	}
	if res, err := u.UpdateScheduled(ctx, b); err != nil || res.Changed || relB.count("/geosite.dat") != 1 {
		t.Fatalf("rollback undone: %v %+v", err, res)
	}
	if _, err := db.Site("youtube"); err != nil {
		t.Fatal(err)
	}
	// A new version of b is installed by the schedule too.
	relB.set("geosite.dat", listBytes(siteEntry("DISCORD", dom{typeDomain, "discord.com", nil})))
	if res, err := u.UpdateScheduled(ctx, b); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if st := u.State(); st.Held(Site, b.Site) || !st.From(Site, b.Site) {
		t.Fatalf("%+v", st.Site)
	}
	// Rolled back again (to the file of a, restored while b was chosen),
	// the user's update ends the hold.
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if res, err := u.UpdateScheduled(ctx, b); err != nil || res.Changed {
		t.Fatalf("rollback undone: %v %+v", err, res)
	}
	if res, err := u.Update(ctx, b, false); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := db.Site("discord"); err != nil {
		t.Fatal(err)
	}
}

// Within one source, the scheduled check after a rollback keeps V1 while
// the source still publishes V2; the user's update installs V2 again.
func TestRollbackKeptWithinSource(t *testing.T) {
	v1 := listBytes(siteEntry("V1", dom{typeDomain, "a.com", nil}))
	v2 := listBytes(siteEntry("V2", dom{typeDomain, "b.com", nil}))
	rel, srv := newRelease(map[string][]byte{"geosite.dat": v1})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", v2)
	if res, err := u.UpdateScheduled(ctx, src); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); !st.Held(Site, src.Site) || st.Site.SHA256 != sha(v1) || st.Site.RolledBackFrom != sha(v2) {
		t.Fatalf("%+v", st.Site)
	}
	if res, err := u.UpdateScheduled(ctx, src); err != nil || res.Changed {
		t.Fatalf("rollback undone: %v %+v", err, res)
	}
	if b, err := os.ReadFile(db.path(Site)); err != nil || sha(b) != sha(v1) {
		t.Fatalf("V1 replaced: %v", err)
	}
	if res, err := u.Update(ctx, src, false); err != nil || !res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if st := u.State(); st.Held(Site, src.Site) || st.Site.SHA256 != sha(v2) {
		t.Fatalf("%+v", st.Site)
	}
}

// A .prev.json that describes another file does not lend its URL to the
// file restored: its origin is unknown.
func TestRollbackStalePrevState(t *testing.T) {
	v1 := listBytes(siteEntry("V1", dom{typeDomain, "a.com", nil}))
	rel, srv := newRelease(map[string][]byte{"geosite.dat": v1})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", listBytes(siteEntry("V2", dom{typeDomain, "b.com", nil})))
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	stale := `{"sha256":"` + strings.Repeat("ab", 32) + `","url":"` + src.Site + `"}`
	if err := os.WriteFile(db.path(Site)+".prev.json", []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Site == nil || st.Site.SHA256 != sha(v1) || st.Site.URL != "" || st.From(Site, src.Site) || !st.Held(Site, src.Site) {
		t.Fatalf("%+v", st.Site)
	}
}

// .prev.json describes the file in .prev: after an install over a deleted
// file and a rollback, the state is that of the file on disk.
func TestRollbackStateFollowsFile(t *testing.T) {
	v1 := listBytes(siteEntry("V1", dom{typeDomain, "a.com", nil}))
	rel, srv := newRelease(map[string][]byte{"geosite.dat": v1})
	defer srv.Close()
	src := Source{ID: "test", Site: srv.URL + "/geosite.dat"}
	db := &DB{Dir: t.TempDir()}
	u := &Updater{DB: db}
	ctx := context.Background()
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", listBytes(siteEntry("V2", dom{typeDomain, "b.com", nil})))
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(db.path(Site)); err != nil {
		t.Fatal(err)
	}
	rel.set("geosite.dat", listBytes(siteEntry("V3", dom{typeDomain, "c.com", nil})))
	if _, err := u.Update(ctx, src, false); err != nil {
		t.Fatal(err)
	}
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Site == nil || st.Site.SHA256 != sha(v1) || st.Site.Size != int64(len(v1)) || st.Site.Categories != 1 {
		t.Fatalf("state describes another file: %+v", st.Site)
	}
}

// The state is saved although another program reads geo.json for a
// moment (an antivirus, without delete sharing).
func TestSaveStateWhileRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("an open file blocks a rename only on Windows")
	}
	u := &Updater{DB: &DB{Dir: t.TempDir()}}
	if err := u.saveState(State{Source: "a"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(u.statePath())
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(20*time.Millisecond, func() { f.Close() })
	if err := u.saveState(State{Source: "b"}); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Source != "b" {
		t.Fatalf("%+v", st)
	}
	// State reads it all the time (the settings page polls it): a reader
	// that shares delete access does not block the save however long it
	// keeps the file open.
	r, err := openRead(u.statePath())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := u.saveState(State{Source: "c"}); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); st.Source != "c" {
		t.Fatalf("%+v", st)
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
