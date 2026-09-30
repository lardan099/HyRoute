package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The controller starts on a clean data directory, serves the admin and
// the health endpoint, and stops when its context ends.
func TestRunServesHealthAndUI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data") // created by the controller, 0700
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	env := func(k string) string {
		if k == "HYROUTE_SERVER_DATA_DIR" {
			return dir
		}
		return ""
	}
	go func() { done <- run(ctx, []string{"-listen", "127.0.0.1:0"}, env, io.Discard, ready) }()

	var addr string
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("not started")
	}

	res, err := http.Get("http://" + addr + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Status        string
		SchemaVersion int
	}
	json.NewDecoder(res.Body).Decode(&h)
	res.Body.Close()
	if res.StatusCode != 200 || h.Status != "ok" || h.SchemaVersion < 1 {
		t.Fatalf("health %d %+v", res.StatusCode, h)
	}

	res, err = http.Get("http://" + addr + "/servers")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "<div id=\"app\">") {
		t.Fatalf("UI %d %q", res.StatusCode, body)
	}

	// First run: the setup token is in a 0600 file.
	tok, err := os.ReadFile(filepath.Join(dir, "setup-token"))
	if err != nil || len(strings.TrimSpace(string(tok))) < 32 {
		t.Fatalf("setup token file: %q %v", tok, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, "setup-token")); st.Mode().Perm() != 0o600 {
			t.Fatalf("setup token mode %v", st.Mode())
		}
	}
	setup := `{"token":"` + strings.TrimSpace(string(tok)) + `","username":"owner","password":"correct horse battery"}`
	res, err = http.Post("http://"+addr+"/api/v1/setup", "application/json", strings.NewReader(setup))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("setup %d", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dir, "setup-token")); !os.IsNotExist(err) {
		t.Fatal("setup token file left after setup")
	}

	// A master key file was created next to the database, owner-only.
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Join(dir, "master.key")); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("master key file: %v %v", st, err)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no graceful shutdown")
	}
}
