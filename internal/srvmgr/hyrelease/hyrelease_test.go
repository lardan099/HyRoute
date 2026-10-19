package hyrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestAssetName(t *testing.T) {
	for arch, want := range map[string]string{"amd64": "hysteria-linux-amd64", "arm64": "hysteria-linux-arm64", "arm": "hysteria-linux-arm", "386": "hysteria-linux-386"} {
		if got, err := AssetName(arch); err != nil || got != want {
			t.Errorf("%s: %s %v", arch, got, err)
		}
	}
	for _, arch := range []string{"", "x86_64", "amd64-avx", "mipsle-sf", "sparc", "../amd64"} {
		if _, err := AssetName(arch); err == nil {
			t.Errorf("%q accepted", arch)
		}
	}
	// Every pinned binary is one a server can get: preflight finds its
	// architecture in uname -m, and AssetName asks for it.
	reach := map[string]bool{}
	for _, m := range []string{"x86_64", "aarch64", "armv7l", "armv6l", "armv5tel", "armv5tejl", "i686", "s390x", "riscv64", "mips", "loongarch64"} {
		a := preflight.HysteriaArch(m)
		if _, err := AssetName(a); err != nil {
			t.Errorf("uname -m %s: %v", m, err)
		}
		reach[a] = true
	}
	for v, sums := range pinned {
		if CheckVersion(v) != nil {
			t.Errorf("pinned version %q", v)
		}
		for name, s := range sums {
			a := strings.TrimPrefix(name, "hysteria-linux-")
			if _, err := AssetName(a); err != nil || !hexRe.MatchString(s) || !reach[a] {
				t.Errorf("%s %s: %v (reachable %v)", name, s, err, reach[a])
			}
		}
	}
}

func TestParseHashes(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("B", 64)
	got, err := ParseHashes([]byte(a + "  build/hysteria-linux-amd64\n\nnot a line\n" + b + " *build/hysteria-linux-arm64\nzz  build/hysteria-linux-386\n"))
	if err != nil || len(got) != 2 || got["hysteria-linux-amd64"] != a || got["hysteria-linux-arm64"] != strings.ToLower(b) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseHashes([]byte("<html>not found</html>")); err == nil {
		t.Fatal("no hashes accepted")
	}
}

func TestResolve(t *testing.T) {
	var hits atomic.Int32
	hashes := strings.Repeat("1", 64) + "  build/hysteria-linux-amd64\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/app/v2.13.0/hashes.txt" {
			w.Write([]byte(hashes))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	r := &Resolver{Base: srv.URL}
	ctx := context.Background()

	a, err := r.Resolve(ctx, "", "amd64")
	if err != nil || a.Version != DefaultVersion || a.SHA256 != pinned[DefaultVersion]["hysteria-linux-amd64"] || a.URL != srv.URL+"/app/"+DefaultVersion+"/hysteria-linux-amd64" {
		t.Fatalf("%+v %v", a, err)
	}
	if hits.Load() != 0 {
		t.Fatal("the pinned version went to the network")
	}
	a, err = r.Resolve(ctx, "v2.13.0", "amd64")
	if err != nil || a.SHA256 != strings.Repeat("1", 64) {
		t.Fatalf("%+v %v", a, err)
	}
	for _, c := range []struct{ v, arch string }{{"v2.13.0", "arm64"}, {"v9.9.9", "amd64"}, {"latest", "amd64"}, {"v2.13.0/../x", "amd64"}, {"", "sparc"}} {
		if _, err := r.Resolve(ctx, c.v, c.arch); err == nil {
			t.Errorf("%+v resolved", c)
		}
	}
}

// machine is a fake server with curl or wget and sha256sum over its files.
func machine(t *testing.T, downloads map[string][]byte, tools ...string) *fake.Executor {
	t.Helper()
	ex := fake.New()
	for _, tool := range []string{"curl", "wget"} {
		code := 1
		if strings.Contains(strings.Join(tools, " "), tool) {
			code = 0
		}
		ex.On("sh", "-c", `command -v "$1" >/dev/null 2>&1`, "sh", tool).Reply("", code)
	}
	fetch := func(url, dest string) (remote.Result, error) {
		b, ok := downloads[url]
		if !ok {
			return remote.Result{ExitCode: 22, Stderr: []byte("404")}, nil
		}
		ex.SetFile(dest, b)
		return remote.Result{}, nil
	}
	ex.On("curl").Do(func(c remote.Cmd) (remote.Result, error) {
		return fetch(c.Args[len(c.Args)-1], c.Args[len(c.Args)-3])
	})
	ex.On("wget").Do(func(c remote.Cmd) (remote.Result, error) {
		return fetch(c.Args[len(c.Args)-1], c.Args[len(c.Args)-3])
	})
	ex.On("sha256sum").Do(func(c remote.Cmd) (remote.Result, error) {
		p := c.Args[len(c.Args)-1]
		b, ok := ex.File(p)
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("sha256sum: " + p + ": No such file or directory")}, nil
		}
		return remote.Result{Stdout: []byte(sum(b) + "  " + p + "\n")}, nil
	})
	return ex
}

const tmp = "/tmp/hyroute.abcdefghij/hysteria"

func TestDirect(t *testing.T) {
	bin := []byte("fake hysteria binary")
	a := Asset{Name: "hysteria-linux-amd64", URL: "https://github.example/hysteria-linux-amd64", SHA256: sum(bin)}
	ctx := context.Background()
	for _, tool := range []string{"curl", "wget"} {
		ex := machine(t, map[string][]byte{a.URL: bin}, tool)
		if err := (Direct{}).Fetch(ctx, ex, a, tmp, true); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if got, _ := ex.File(tmp); string(got) != string(bin) {
			t.Fatalf("%s: file %q", tool, got)
		}
		if !strings.HasPrefix(ex.Commands()[len(ex.Commands())-2], tool) {
			t.Errorf("%s not used: %v", tool, ex.Commands())
		}
	}
	// A different file under the release name is refused.
	ex := machine(t, map[string][]byte{a.URL: []byte("tampered")}, "curl")
	if err := (Direct{}).Fetch(ctx, ex, a, tmp, true); !errors.Is(err, ErrChecksum) {
		t.Fatalf("tampered: %v", err)
	}
	ex = machine(t, nil, "curl")
	if err := (Direct{}).Fetch(ctx, ex, a, tmp, true); err == nil || errors.Is(err, ErrChecksum) {
		t.Fatalf("404: %v", err)
	}
	ex = machine(t, map[string][]byte{a.URL: bin})
	if err := (Direct{}).Fetch(ctx, ex, a, tmp, true); err == nil || !strings.Contains(err.Error(), "ни curl, ни wget") {
		t.Fatalf("no tools: %v", err)
	}
}

func TestRelay(t *testing.T) {
	bin := []byte("fake hysteria binary")
	var hits atomic.Int32
	body := bin
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(body)
	}))
	defer srv.Close()
	res := &Resolver{Base: srv.URL}
	a := Asset{Name: "hysteria-linux-arm64", URL: res.URL("v2.12.3", "hysteria-linux-arm64"), SHA256: sum(bin)}
	relay := NewRelay(res)
	ctx := context.Background()

	// The server cannot download anything: no curl, no wget.
	ex := machine(t, nil)
	if err := relay.Fetch(ctx, ex, a, tmp, false); err != nil {
		t.Fatal(err)
	}
	w := ex.Writes()
	if len(w) != 1 || w[0].Path != tmp || string(w[0].Data) != string(bin) || w[0].Spec.Mode != 0o600 {
		t.Fatalf("upload %+v", w)
	}
	// A second server gets the kept copy.
	if err := relay.Fetch(ctx, machine(t, nil), a, tmp, false); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d downloads", err, hits.Load())
	}
	// A wrong download never reaches the server.
	body = []byte("tampered")
	b := Asset{Name: "hysteria-linux-amd64", URL: res.URL("v2.12.3", "hysteria-linux-amd64"), SHA256: sum(bin[1:])}
	ex = machine(t, nil)
	if err := relay.Fetch(ctx, ex, b, tmp, false); !errors.Is(err, ErrChecksum) || len(ex.Writes()) != 0 {
		t.Fatalf("%v, writes %d", err, len(ex.Writes()))
	}
}
