package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The controller starts on a clean data directory, serves the admin and
// the health endpoint, and stops when its context ends.
func TestRunServesHealthAndUI(t *testing.T) {
	dir := t.TempDir()
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
