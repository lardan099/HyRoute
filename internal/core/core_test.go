package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/update"
)

// Fake binaries contain their version as text.
func fakeVersion(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

func TestCheckInstallRollback(t *testing.T) {
	bin := []byte("v2.99.0")
	sum := sha256.Sum256(bin)
	hexSum := hex.EncodeToString(sum[:])
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/apernet/hysteria/releases":
			json.NewEncoder(w).Encode([]release.Release{
				{Tag: "app/v3.0.0", Assets: []release.Asset{{Name: AssetName, URL: srv.URL + "/bin"}}},
				{Tag: "app/v2.99.1", Prerelease: true},
				{Tag: "app/v2.99.0", Body: "changes", Assets: []release.Asset{
					{Name: AssetName, URL: srv.URL + "/bin", Digest: "sha256:" + hexSum},
					{Name: "hashes.txt", URL: srv.URL + "/hashes"},
				}},
			})
		case "/bin":
			w.Write(bin)
		case "/hashes":
			w.Write([]byte(hexSum + "  build/" + AssetName + "\n"))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	m := &Manager{Dir: filepath.Join(dir, "core"), Bundled: bundled, Client: &release.Client{API: srv.URL}, Version: fakeVersion}

	u, ok, err := m.Check(context.Background())
	if err != nil || !ok || u.Version != "v2.99.0" || u.Notes != "changes" || len(u.sha256) != 2 {
		t.Fatalf("%+v %v %v", u, ok, err)
	}
	if err := m.Install(context.Background(), u, nil); err != nil {
		t.Fatal(err)
	}
	if in := m.Info(); !in.Updated || in.Version != "v2.99.0" || in.Previous != "встроенное v2.12.3" {
		t.Fatalf("%+v", in)
	}
	if _, ok, _ := m.Check(context.Background()); ok {
		t.Fatal("up to date must not offer an update")
	}
	// A replaced file is not started.
	os.WriteFile(m.Path(), []byte("v2.99.0 evil"), 0o755)
	if m.Path() != bundled || m.Info().Error == "" {
		t.Fatal("tampered core used")
	}
	os.WriteFile(filepath.Join(m.Dir, "v2.99.0", "hysteria.exe"), bin, 0o755)
	if err := m.Rollback(); err != nil || m.Path() != bundled {
		t.Fatalf("rollback: %v %s", err, m.Path())
	}
	// A new core that does not start is not activated.
	bin = []byte("garbage")
	u.sha256 = []string{hex.EncodeToString(func() []byte { s := sha256.Sum256(bin); return s[:] }())}
	if err := m.Install(context.Background(), u, nil); err == nil || !strings.Contains(err.Error(), "не запускается") {
		t.Fatalf("broken core installed: %v", err)
	}
	if m.Path() != bundled {
		t.Fatal("broken core activated")
	}
}

// installed writes a downloaded core and core.json as Install leaves them.
func installed(t *testing.T, dir string, cur, prev string) {
	t.Helper()
	var st state
	for _, v := range []string{cur, prev} {
		if v == "" {
			continue
		}
		p := filepath.Join(dir, v, "hysteria.exe")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, []byte(v), 0o755)
		s := sha256.Sum256([]byte(v))
		e := &entry{Version: v, SHA256: hex.EncodeToString(s[:])}
		if v == cur {
			st.Current = e
		} else {
			st.Previous = e
		}
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, "core.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A HyRoute update may bring a bundled core newer than the one downloaded
// earlier: the newer one runs.
func TestNewerBundledCoreWins(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	installed(t, coreDir, "v2.12.2", "v2.12.0")

	// The download is newer than the bundled core: it runs, and the
	// bundled one and the previous one stay allowed.
	os.WriteFile(bundled, []byte("v2.12.1"), 0o755)
	m := &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	cur := filepath.Join(coreDir, "v2.12.2", "hysteria.exe")
	if m.Path() != cur {
		t.Fatalf("path %s", m.Path())
	}
	if p := m.Paths(); len(p) != 3 || p[0] != cur || p[1] != bundled || p[2] != filepath.Join(coreDir, "v2.12.0", "hysteria.exe") {
		t.Fatalf("paths %v", p)
	}
	if in := m.Info(); !in.Updated || in.Previous != "встроенное v2.12.1" || in.Error != "" {
		t.Fatalf("%+v", in)
	}

	// The next HyRoute brings v2.13.0: the downloads are retired.
	os.WriteFile(bundled, []byte("v2.13.0"), 0o755)
	m = &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if m.Path() != bundled {
		t.Fatalf("older download used: %s", m.Path())
	}
	if in := m.Info(); in.Updated || in.Previous != "" || in.Error != "" || in.Version != "v2.13.0" {
		t.Fatalf("%+v", in)
	}
	if _, err := os.Stat(filepath.Join(coreDir, "v2.12.2")); err == nil {
		t.Fatal("retired core kept")
	}
	m = &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if m.Path() != bundled || m.Rollback() == nil {
		t.Fatal("retirement not saved")
	}

	// A bundled core that does not run never replaces a working download.
	installed(t, coreDir, "v2.99.0", "")
	os.WriteFile(bundled, []byte("garbage"), 0o755)
	m = &Manager{Dir: coreDir, Bundled: bundled, Version: func(p string) (string, error) {
		v, err := fakeVersion(p)
		if v == "garbage" {
			return "", os.ErrInvalid
		}
		return v, err
	}}
	if m.Path() != filepath.Join(coreDir, "v2.99.0", "hysteria.exe") {
		t.Fatalf("path %s", m.Path())
	}
}

// While a HyRoute update is on trial the updater may still restore the
// previous HyRoute with its older bundled core: the downloads stay.
func TestRetireWaitsForHyRouteUpdate(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	installed(t, coreDir, "v2.12.5", "v2.12.4")
	os.WriteFile(bundled, []byte("v2.12.5"), 0o755)
	journal := filepath.Join(dir, update.JournalName)
	os.WriteFile(journal, []byte("{}"), 0o600)

	m := &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if m.Path() != bundled {
		t.Fatalf("path %s", m.Path())
	}
	if in := m.Info(); in.Updated || in.Previous != "" || in.Error != "" {
		t.Fatalf("%+v", in)
	}
	for _, v := range []string{"v2.12.5", "v2.12.4"} {
		if _, err := os.Stat(filepath.Join(coreDir, v, "hysteria.exe")); err != nil {
			t.Fatalf("core %s removed during the trial: %v", v, err)
		}
	}
	// The previous HyRoute (bundled v2.12.3) still finds its download.
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	old := &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if want := filepath.Join(coreDir, "v2.12.5", "hysteria.exe"); old.Path() != want {
		t.Fatalf("rolled-back HyRoute: path %s", old.Path())
	}

	// Confirmed (no journal): the next start retires them for good.
	os.Remove(journal)
	os.WriteFile(bundled, []byte("v2.12.5"), 0o755)
	m = &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if m.Path() != bundled {
		t.Fatalf("path %s", m.Path())
	}
	if _, err := os.Stat(filepath.Join(coreDir, "v2.12.5")); err == nil {
		t.Fatal("retired core kept")
	}
}

// After a rollback to the bundled core there is nothing to roll back to,
// so no rollback is offered.
func TestNoRollbackOfferedOnBundledCore(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	installed(t, coreDir, "v2.12.4", "")
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	m := &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if in := m.Info(); in.Previous != "встроенное v2.12.3" {
		t.Fatalf("%+v", in)
	}
	if err := m.Rollback(); err != nil || m.Path() != bundled {
		t.Fatalf("rollback: %v %s", err, m.Path())
	}
	if in := m.Info(); in.Updated || in.Previous != "" {
		t.Fatalf("rollback offered on the bundled core: %+v", in)
	}
}

// A failing "hysteria version" is tried again later, and until then no
// release is offered as an update over a core of unknown version.
func TestVersionFailureNotKept(t *testing.T) {
	old := verRetry
	verRetry = 0
	t.Cleanup(func() { verRetry = old })
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	fail := true
	m := &Manager{Dir: filepath.Join(dir, "core"), Bundled: bundled, Version: func(p string) (string, error) {
		if fail {
			return "", context.DeadlineExceeded
		}
		return fakeVersion(p)
	}}
	if v := m.Info().Version; !strings.HasPrefix(v, "не запускается") {
		t.Fatalf("version %q", v)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]release.Release{{Tag: "app/v2.12.3", Assets: []release.Asset{
			{Name: AssetName, URL: "http://127.0.0.1/bin", Digest: "sha256:" + strings.Repeat("0", 64)},
		}}})
	}))
	defer srv.Close()
	m.Client = &release.Client{API: srv.URL}
	if _, ok, err := m.Check(context.Background()); ok || err == nil {
		t.Fatalf("offered over an unknown version: %v %v", ok, err)
	}
	fail = false
	if v := m.Info().Version; v != "v2.12.3" {
		t.Fatalf("failure kept: %q", v)
	}
	if _, ok, err := m.Check(context.Background()); ok || err != nil {
		t.Fatalf("the core in use offered: %v %v", ok, err)
	}
}

// A core.json that cannot be saved leaves the state as it was: the
// rollback target stays.
func TestSaveFailureKeepsState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Install protects the folder: without elevation it is then read-only")
	}
	bin := []byte("v2.12.6")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(bin) }))
	defer srv.Close()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	installed(t, coreDir, "v2.12.5", "v2.12.4")
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	m := &Manager{Dir: coreDir, Bundled: bundled, Client: &release.Client{}, Version: fakeVersion}
	// core.json.tmp cannot be written.
	if err := os.Mkdir(filepath.Join(coreDir, "core.json.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(bin)
	u := Update{Version: "v2.12.6", url: srv.URL, sha256: []string{hex.EncodeToString(s[:])}}
	if err := m.Install(context.Background(), u, nil); err == nil {
		t.Fatal("install without a saved core.json")
	}
	if in := m.Info(); in.Version != "v2.12.5" || in.Previous != "v2.12.4" {
		t.Fatalf("state after a failed install: %+v", in)
	}
	if _, err := os.Stat(filepath.Join(coreDir, "v2.12.6")); err == nil {
		t.Fatal("the new core's folder kept")
	}
	if err := m.Rollback(); err == nil {
		t.Fatal("rollback without a saved core.json")
	}
	if in := m.Info(); in.Version != "v2.12.5" || in.Previous != "v2.12.4" {
		t.Fatalf("state after a failed rollback: %+v", in)
	}
}

// A core folder a normal process may have made (see CheckOwner) is not
// trusted: its core.json could name any hysteria.exe.
func TestForeignCoreFolderIgnored(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	installed(t, coreDir, "v2.99.0", "")
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	ownerOK = func(p string) error {
		if p == coreDir {
			return errors.New("not an administrator's")
		}
		return nil
	}
	t.Cleanup(func() { ownerOK = CheckOwner })
	m := &Manager{Dir: coreDir, Bundled: bundled, Version: fakeVersion}
	if m.Path() != bundled {
		t.Fatalf("started from a foreign folder: %s", m.Path())
	}
	if p := m.Paths(); len(p) != 2 {
		t.Fatalf("paths %v", p)
	}
	if in := m.Info(); in.Updated || in.Error == "" {
		t.Fatalf("%+v", in)
	}
}
