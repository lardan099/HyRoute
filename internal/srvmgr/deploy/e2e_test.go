package deploy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/srvmgr/api"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

type simConn struct{ s *deploy.SimVPS }

func (c simConn) Connect(context.Context, int64) (remote.Executor, error) { return c.s, nil }

// browser is the admin in a browser: cookies and the CSRF token.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (b *browser) do(method, path string, body any, out any) int {
	b.t.Helper()
	var r io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		r = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, b.base+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.csrf != "" {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			b.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, data)
		}
	}
	return resp.StatusCode
}

// TestQuickDeployToClientLink is the goal of Phase 1: a clean VPS (here
// simulated) → Quick Deploy from the admin API → a working server → a
// share link the HyRoute client takes, without SSH by hand.
func TestQuickDeployToClientLink(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{8}, 32)})
	red := redact.New()
	vps := deploy.NewSimVPS()

	// The Hysteria release, as GitHub would serve it.
	const version = "v2.99.0"
	bin := []byte("#!fake hysteria " + version)
	sum := sha256.Sum256(bin)
	rel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hashes.txt") {
			io.WriteString(w, hex.EncodeToString(sum[:])+"  build/hysteria-linux-amd64\n")
			return
		}
		w.Write(bin)
	}))
	defer rel.Close()
	res := &hyrelease.Resolver{Base: rel.URL, HTTP: rel.Client()}
	vps.AddDownload(res.URL(version, "hysteria-linux-amd64"), bin)

	authSvc := auth.New(db)
	authSvc.Params = auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	inv := servers.New(db, keys)
	eng := jobs.New(db, keys, red, simConn{vps}, nil)
	eng.Poll = 10 * time.Millisecond
	eng.Register(deploy.Kind(deploy.Deps{Store: db, Keys: keys, Resolver: res, VerifyTimeout: time.Second, Poll: 10 * time.Millisecond}))
	jctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { eng.Run(jctx); close(done) }()
	defer func() { stop(); <-done }()

	h := api.New(api.Deps{Store: db, Auth: authSvc, Servers: inv, Connect: connect.New(inv, db, red), Jobs: eng,
		Deploy: &deploy.Submitter{Store: db, Keys: keys, Jobs: eng}, Keys: keys})
	srv := httptest.NewServer(h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, base: srv.URL + "/api/v1", c: &http.Client{Jar: jar}}

	// First run: the owner with the setup token.
	tok, _ := authSvc.PrepareSetup(ctx)
	var sess struct{ CSRFToken string }
	if code := b.do("POST", "/setup", map[string]string{"token": tok, "username": "owner", "password": "correct horse battery"}, &sess); code != http.StatusCreated {
		t.Fatalf("setup: %d", code)
	}
	b.csrf = sess.CSRFToken

	// Add the VPS. The SSH host key is confirmed in the admin (the check
	// dialog, tested on its own); here it is recorded directly.
	var s struct{ ID int64 }
	if code := b.do("POST", "/servers", map[string]any{"name": "Амстердам", "country": "NL", "host": "192.0.2.10", "authType": "password", "password": "fake-e2e-ssh-pass"}, &s); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	id := strconv.FormatInt(s.ID, 10)

	// Quick Deploy.
	var j struct {
		ID    int64
		State string
	}
	params := map[string]any{"version": version, "tls": "self-signed", "port": 443, "hopPorts": "20000-50000", "obfs": true, "masquerade": "https://www.example.com"}
	if code := b.do("POST", "/servers/"+id+"/deploy", params, &j); code != http.StatusAccepted {
		t.Fatalf("deploy: %d", code)
	}
	for i := 0; i < 500 && j.State != "completed" && j.State != "failed"; i++ {
		time.Sleep(20 * time.Millisecond)
		b.do("GET", "/jobs/"+strconv.FormatInt(j.ID, 10), nil, &j)
	}
	if j.State != "completed" {
		var full map[string]any
		b.do("GET", "/jobs/"+strconv.FormatInt(j.ID, 10), nil, &full)
		t.Fatalf("deploy job: %v", full)
	}
	time.Sleep(50 * time.Millisecond) // the Finished hook
	var info struct{ State string }
	b.do("GET", "/servers/"+id, nil, &info)
	if info.State != "healthy" || vps.ServiceState() != "active" {
		t.Fatalf("server %s, service %s", info.State, vps.ServiceState())
	}

	// The client link: the summary has no secrets, the reveal has them.
	var summary map[string]any
	b.do("GET", "/servers/"+id+"/client", nil, &summary)
	var prof struct{ URI, Compat string }
	b.do("GET", "/servers/"+id+"/client?reveal=1", nil, &prof)

	cfg, _ := vps.FileContent(deploy.ConfigPath)
	c, err := hyconfig.ParseServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _ := vps.FileContent(deploy.CertPath)
	blk, _ := pem.Decode(certPEM)
	pin := sha256.Sum256(blk.Bytes)
	sb, _ := json.Marshal(summary)
	if strings.Contains(string(sb), c.Auth.Password) || strings.Contains(string(sb), c.Obfs.Salamander.Password) {
		t.Fatalf("secrets in the summary: %s", sb)
	}
	for _, link := range []string{prof.URI, prof.Compat} {
		p, warns, err := hysteria.ParseURI(link)
		if err != nil || len(warns) != 0 {
			t.Fatalf("%q: %v %q", link, err, warns)
		}
		if p.Name != "Амстердам" || p.Host != "192.0.2.10" || p.Ports != "443,20000-50000" || p.Auth != c.Auth.Password ||
			p.Obfs.Type != "salamander" || p.Obfs.Password != c.Obfs.Salamander.Password || p.TLS.PinSHA256 != hex.EncodeToString(pin[:]) || !p.TLS.Insecure {
			t.Fatalf("the link does not match the server: %+v", p)
		}
	}
}
