package update

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/release"
)

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func buildZip(t *testing.T, version string, files map[string]string, extra map[string]string) []byte {
	t.Helper()
	m := Manifest{Version: version, Files: map[string]string{}}
	for n, c := range files {
		m.Files[n] = sum([]byte(c))
	}
	mb, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "p.zip")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	add := func(n, c string) { w, _ := zw.Create(n); w.Write([]byte(c)) }
	for n, c := range files {
		add(n, c)
	}
	for n, c := range extra {
		add(n, c)
	}
	add(ManifestName, string(mb))
	zw.Close()
	f.Close()
	b, _ := os.ReadFile(path)
	return b
}

func TestCheckStageApplyUndo(t *testing.T) {
	files := map[string]string{MainExe: "new main", UpdaterExe: "new updater", "WinDivert.dll": "same dll"}
	pkg := buildZip(t, "v0.6.0", files, nil)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases":
			json.NewEncoder(w).Encode([]release.Release{
				{Tag: "v0.7.0-beta.1", Prerelease: true},
				{Tag: "v0.6.0", Body: "notes", Assets: []release.Asset{
					{Name: ZipName("v0.6.0"), URL: srv.URL + "/zip", Size: int64(len(pkg))},
					{Name: SumsName, URL: srv.URL + "/sums"},
				}},
			})
		case "/zip":
			w.Write(pkg)
		case "/sums":
			w.Write([]byte(sum(pkg) + "  " + ZipName("v0.6.0") + "\n"))
		}
	}))
	defer srv.Close()
	c := &release.Client{API: srv.URL}
	a, ok, err := Check(context.Background(), c, "o/r", "v0.5.0", "stable")
	if err != nil || !ok || a.Version != "v0.6.0" || a.Notes != "notes" {
		t.Fatalf("%+v %v %v", a, ok, err)
	}
	if _, ok, _ := Check(context.Background(), c, "o/r", "v0.6.0", "stable"); ok {
		t.Fatal("same version offered")
	}
	staging, err := Stage(context.Background(), c, a, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	os.WriteFile(filepath.Join(target, MainExe), []byte("old main"), 0o755)
	os.WriteFile(filepath.Join(target, "WinDivert.dll"), []byte("same dll"), 0o755)
	sw, err := Apply(staging, target)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(target, MainExe)); string(b) != "new main" || len(sw.Replaced) != 1 || len(sw.Added) != 1 {
		t.Fatalf("%s %+v", b, sw)
	}
	if err := sw.Undo(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(target, MainExe)); string(b) != "old main" {
		t.Fatal("undo")
	}
	if _, err := os.Stat(filepath.Join(target, UpdaterExe)); err == nil {
		t.Fatal("added file left after undo")
	}
	// A corrupted staging file stops Apply before anything changes.
	os.WriteFile(filepath.Join(staging, MainExe), []byte("tampered"), 0o755)
	if _, err := Apply(staging, target); err == nil {
		t.Fatal("tampered staging applied")
	}
}

func TestStageRejectsTraversalAndBadSums(t *testing.T) {
	pkg := buildZip(t, "v0.6.0", map[string]string{MainExe: "m", UpdaterExe: "u"}, map[string]string{"../evil.exe": "x"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(pkg) }))
	defer srv.Close()
	c := &release.Client{}
	a := Available{Version: "v0.6.0", zipURL: srv.URL, sums: []string{sum(pkg)}}
	if _, err := Stage(context.Background(), c, a, t.TempDir(), nil); err == nil {
		t.Fatal("path traversal accepted")
	}
	a.sums = []string{sum([]byte("other"))}
	if _, err := Stage(context.Background(), c, a, t.TempDir(), nil); err == nil {
		t.Fatal("bad checksum accepted")
	}
}
