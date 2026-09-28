package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.10.0", "v1.9.9", 1},
		{"app/v2.12.3", "app/v2.12.4", -1},
		{"v1.0.0", "v1.0.0-beta.1", 1},
		{"v1.0.0-3-gabcdef", "v1.0.0", 1},
		{"dev", "v0.0.1", -1},
		{"v1.1.0-beta.10", "v1.1.0-beta.9", 1},
		{"v1.1.0-beta.2", "v1.1.0-beta", 1},
		{"v1.1.0-alpha.1", "v1.1.0-beta", -1},
		{"v1.1.0-beta.1", "v1.1.0-beta.x", -1},
		{"v1.1.0-beta.1", "v1.1.0-beta.1", 0},
		{"v1.0.0-10-gabcdef", "v1.0.0-9-gabcdef", 1},
		{"v1.1.0-beta.1-2-gabcdef", "v1.1.0-beta.1", 1},
	} {
		if got := Compare(c.a, c.b); (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("%s vs %s: %d", c.a, c.b, got)
		}
	}
	list := []Release{{Tag: "app/v2.12.3"}, {Tag: "app/v2.13.0", Prerelease: true}, {Tag: "app/v2.12.10"}, {Tag: "app/v1.3.5"}, {Tag: "junk"}}
	r, ok := Latest(list, false, func(tag string) bool { return strings.HasPrefix(tag, "app/v2.") })
	if !ok || r.Tag != "app/v2.12.10" {
		t.Fatalf("%+v", r)
	}
	beta := []Release{{Tag: "v1.1.0-beta.9", Prerelease: true}, {Tag: "v1.1.0-beta.10", Prerelease: true}, {Tag: "v1.1.0-beta.2", Prerelease: true}}
	if r, ok := Latest(beta, true, nil); !ok || r.Tag != "v1.1.0-beta.10" {
		t.Fatalf("%+v", r)
	}
}

// A write that fails (disk full) fails the download: the hash of the
// network stream says nothing about the file.
func TestDownloadWriteFails(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("needs /dev/full")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hello")) }))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "a")
	if err := os.Symlink("/dev/full", path+".part"); err != nil {
		t.Skip(err)
	}
	good := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if _, err := (&Client{}).Download(context.Background(), srv.URL, path, 100, nil, good); err == nil || !strings.Contains(err.Error(), "записать") {
		t.Fatalf("write error hidden: %v", err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("file kept")
	}
}

func TestDownloadVerifies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hello")) }))
	defer srv.Close()
	c := &Client{}
	dir := t.TempDir()
	good := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if _, err := c.Download(context.Background(), srv.URL, filepath.Join(dir, "a"), 100, nil, good, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Download(context.Background(), srv.URL, filepath.Join(dir, "b"), 100, nil, strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatch accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); err == nil {
		t.Fatal("bad file kept")
	}
	if _, err := c.Download(context.Background(), srv.URL, filepath.Join(dir, "c"), 100, nil); err == nil {
		t.Fatal("unverified download accepted")
	}
	if SumFor([]byte(good+"  build/hysteria-windows-amd64.exe\n"), "hysteria-windows-amd64.exe") != good {
		t.Fatal("SumFor")
	}
}

// A slow download is not cut off after a fixed time (http.Client.Timeout
// covers reading the body too); only a server that stops sending is.
func TestDownloadSlowButSteady(t *testing.T) {
	if (&Client{}).http().Timeout != 0 {
		t.Fatal("the default client limits the whole download")
	}
	old := stallTimeout
	stallTimeout = 500 * time.Millisecond
	t.Cleanup(func() { stallTimeout = old })
	body := []byte(strings.Repeat("x", 15))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A byte every 100 ms, 1.5 s in all: three times stallTimeout.
		for _, b := range body {
			w.Write([]byte{b})
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()
	sum := sha256.Sum256(body)
	c := &Client{}
	if _, err := c.Download(context.Background(), srv.URL, filepath.Join(t.TempDir(), "a"), 100, nil, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadStalled(t *testing.T) {
	old := stallTimeout
	stallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { stallTimeout = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	dir := t.TempDir()
	start := time.Now()
	_, err := (&Client{}).Download(context.Background(), srv.URL, filepath.Join(dir, "a"), 100, nil, strings.Repeat("0", 64))
	if !errors.Is(err, errStalled) {
		t.Fatalf("stalled download: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("gave up after %v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.part")); err == nil {
		t.Fatal("partial file kept")
	}
}
