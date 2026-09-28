package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/update"
)

// coreUpdated is a core manager with an installed update (v2.99.0) over
// the bundled core (v2.12.3). Fake binaries contain their version.
func coreUpdated(t *testing.T) *core.Manager {
	t.Helper()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	bin := []byte("v2.99.0")
	if err := os.MkdirAll(filepath.Join(coreDir, "v2.99.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	os.WriteFile(filepath.Join(coreDir, "v2.99.0", "hysteria.exe"), bin, 0o755)
	s := sha256.Sum256(bin)
	os.WriteFile(filepath.Join(coreDir, "core.json"), []byte(`{"current":{"version":"v2.99.0","sha256":"`+hex.EncodeToString(s[:])+`"}}`), 0o644)
	return &core.Manager{Dir: coreDir, Bundled: bundled, Version: func(p string) (string, error) {
		b, err := os.ReadFile(p)
		return string(b), err
	}}
}

// "Ядро обновлено, переподключитесь" lasts only while the session that
// ran during the core change does.
func TestCoreReconnectNoticeClears(t *testing.T) {
	c, _ := newCtl(t)
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if !c.Updates().CoreNeedsReconn {
		t.Fatal("connected during the core change: a reconnect is needed")
	}
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("still asks for a reconnect after it")
	}
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("the notice came back with the next connection")
	}

	// A disconnect ends it as well.
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil || !c.Updates().CoreNeedsReconn {
		t.Fatalf("%v %+v", err, c.Updates())
	}
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("notice kept after a disconnect")
	}
}

// refreshKS is a kill switch that can renew its program exceptions.
type refreshKS struct {
	fakeKS
	refreshed int
}

func (k *refreshKS) RefreshApps() error { k.refreshed++; return nil }

// A core update or rollback moves hysteria.exe: an installed block lets
// the new path through at once.
func TestCoreChangeRefreshesKillSwitch(t *testing.T) {
	c, _ := newCtl(t)
	ks := &refreshKS{}
	c.KillSwitch = ks
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 0 {
		t.Fatal("refreshed without a block")
	}
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 1 {
		t.Fatalf("refreshed %d times", ks.refreshed)
	}
	// Routing stopped without a Disconnect: the internet is closed, and a
	// server check must still reach the server through the new core.
	c.Shutdown()
	if c.Status().KillSwitch != "blocking" {
		t.Fatalf("kill switch %q", c.Status().KillSwitch)
	}
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 2 {
		t.Fatalf("refreshed %d times while blocking", ks.refreshed)
	}
}

// appPackage is a release zip of HyRoute version v.
func appPackage(t *testing.T, v string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	m := update.Manifest{Version: v, Files: map[string]string{}}
	for _, n := range []string{update.MainExe, update.UpdaterExe} {
		w, _ := zw.Create(n)
		w.Write([]byte(n + " " + v))
		s := sha256.Sum256([]byte(n + " " + v))
		m.Files[n] = hex.EncodeToString(s[:])
	}
	w, _ := zw.Create(update.ManifestName)
	json.NewEncoder(w).Encode(m)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A check during a download may offer another version: the finished
// download is then not presented as that version, and no second download
// starts meanwhile.
func TestAppUpdateOfferChangesDuringDownload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DownloadAppUpdate protects its folder: without elevation it is then read-only")
	}
	pkg := appPackage(t, "v1.0.1")
	var mu sync.Mutex
	tag := "v1.0.1"
	started, finish := make(chan struct{}), make(chan struct{})
	var once, finished sync.Once
	unblock := func() { finished.Do(func() { close(finish) }) }
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases":
			mu.Lock()
			v := tag
			mu.Unlock()
			digest := strings.Repeat("0", 64)
			if v == "v1.0.1" {
				s := sha256.Sum256(pkg)
				digest = hex.EncodeToString(s[:])
			}
			json.NewEncoder(w).Encode([]release.Release{{Tag: v, Assets: []release.Asset{
				{Name: update.ZipName(v), URL: srv.URL + "/zip", Size: int64(len(pkg)), Digest: "sha256:" + digest},
			}}})
		case "/zip":
			once.Do(func() { close(started) })
			<-finish
			w.Write(pkg)
		}
	}))
	defer srv.Close()
	defer unblock() // before srv.Close: the download handler waits for it
	c, _ := newCtl(t)
	c.Version = "v1.0.0"
	c.Updater = &Updater{Repo: "o/r", Dir: filepath.Join(t.TempDir(), "updates"), Client: &release.Client{API: srv.URL}}
	if st := c.CheckUpdates(); st.App == nil || st.App.Version != "v1.0.1" {
		t.Fatalf("%+v", st)
	}
	errc := make(chan error, 1)
	go func() { errc <- c.DownloadAppUpdate() }()
	<-started
	mu.Lock()
	tag = "v1.0.2"
	mu.Unlock()
	if st := c.CheckUpdates(); st.App == nil || st.App.Version != "v1.0.2" || st.AppStage != "downloading" {
		t.Fatalf("%+v", st)
	}
	if err := c.DownloadAppUpdate(); err == nil {
		t.Fatal("a second download started")
	}
	unblock()
	if err := <-errc; err == nil {
		t.Fatal("v1.0.1 downloaded as v1.0.2")
	}
	if st := c.Updates(); st.AppStage != "" {
		t.Fatalf("stage %q", st.AppStage)
	}
	if _, _, err := c.ReadyUpdate(); err == nil {
		t.Fatal("the v1.0.1 package offered for v1.0.2")
	}
}
