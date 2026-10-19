package hyrelease

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The newest release is the tag /latest redirects to, and its hashes.txt
// must list the amd64 build; anything else is not taken.
func TestLatest(t *testing.T) {
	loc, hashes := "", ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			if loc == "" {
				w.Write([]byte("<html>"))
				return
			}
			http.Redirect(w, r, loc, http.StatusFound)
		case "/app/v2.13.0/hashes.txt":
			w.Write([]byte(hashes))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := &Resolver{Base: srv.URL, LatestURL: srv.URL + "/releases/latest"}
	ctx := context.Background()

	loc, hashes = srv.URL+"/apernet/hysteria/releases/tag/app/v2.13.0", strings.Repeat("2", 64)+"  build/hysteria-linux-amd64\n"
	if v, err := r.Latest(ctx); err != nil || v != "v2.13.0" {
		t.Fatalf("%q %v", v, err)
	}
	// The pinned version needs no hashes.txt.
	loc = "https://github.example/apernet/hysteria/releases/tag/app/" + DefaultVersion
	if v, err := r.Latest(ctx); err != nil || v != DefaultVersion {
		t.Fatalf("%q %v", v, err)
	}
	for _, c := range []struct{ loc, hashes string }{
		{"", ""}, // no redirect
		{"https://github.example/apernet/hysteria/releases/tag/core/v2.13.0", ""},
		{"https://github.example/apernet/hysteria/releases/tag/app/latest", ""},
		{"https://github.example/apernet/hysteria/releases/tag/app/v2.13.0", strings.Repeat("2", 64) + "  build/hysteria-linux-arm64\n"},
		{"https://github.example/apernet/hysteria/releases/tag/app/v2.13.0", "<html>not found</html>"},
	} {
		loc, hashes = c.loc, c.hashes
		if v, err := r.Latest(ctx); err == nil {
			t.Errorf("%+v: %q", c, v)
		}
	}
}

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		v, than string
		want    bool
	}{
		{"v2.6.0", "v2.12.3", true}, {"v2.12.3", "v2.12.3", false}, {"v2.12.10", "v2.12.3", false},
		{"v1.99.99", "v2.0.0", true}, {"", "v2.0.0", false}, {"v2.0.0", "", false}, {"2.0.0", "v3.0.0", false}, {"unknown", "v3.0.0", false},
	} {
		if got := Older(c.v, c.than); got != c.want {
			t.Errorf("%q < %q: %v", c.v, c.than, got)
		}
	}
	if (Release{}).Target() != DefaultVersion || (Release{Version: "v2.0.0"}).Target() != DefaultVersion || (Release{Version: "v9.0.0"}).Target() != "v9.0.0" {
		t.Error("target")
	}
}

type memSettings map[string]string

func (m memSettings) Setting(_ context.Context, k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (m memSettings) SetSetting(_ context.Context, k, v string, _ time.Time) error {
	m[k] = v
	return nil
}

// The watch looks once per interval, retries a failed lookup after a
// tick keeping what it found before, and a new process starts from what
// the last one found. No network: the lookup is injected.
func TestWatch(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_790_000_000, 0)
	found, fail, calls := "v2.13.0", false, 0
	find := func(context.Context) (string, error) {
		calls++
		if fail {
			return "", errors.New("GitHub is down")
		}
		return found, nil
	}
	set := memSettings{}
	w := &Watch{Find: find, Settings: set, Interval: 24 * time.Hour, Tick: time.Hour, Now: func() time.Time { return now }}
	if !w.Due() || w.Latest().Version != "" {
		t.Fatal("a new watch has nothing and is due")
	}
	if r := w.Check(ctx); r.Version != "v2.13.0" || !r.CheckedAt.Equal(now) || r.Error != "" || calls != 1 {
		t.Fatalf("%+v %d", r, calls)
	}
	now = now.Add(23 * time.Hour)
	if w.Due() {
		t.Fatal("due before the interval")
	}
	now = now.Add(time.Hour)
	fail = true
	if !w.Due() {
		t.Fatal("not due after the interval")
	}
	if r := w.Check(ctx); r.Version != "v2.13.0" || r.Error == "" || r.CheckedAt.Equal(now) || !r.TriedAt.Equal(now) {
		t.Fatalf("failed lookup: %+v", r)
	}
	now = now.Add(30 * time.Minute)
	if w.Due() {
		t.Fatal("a failed lookup is retried before a tick")
	}
	now = now.Add(30 * time.Minute)
	if !w.Due() {
		t.Fatal("a failed lookup is not retried after a tick")
	}
	fail, found = false, "v2.14.1"
	w.Check(ctx)

	// A new process: what the last one found, and not due yet.
	again := &Watch{Find: find, Settings: set, Interval: 24 * time.Hour, Tick: time.Hour, Now: func() time.Time { return now.Add(time.Minute) }}
	again.load(ctx)
	if r := again.Latest(); r.Version != "v2.14.1" || again.Due() {
		t.Fatalf("restarted: %+v due %v", r, again.Due())
	}
	// A lookup that returns no version tag is a failure.
	found = "nightly"
	if r := w.Check(ctx); r.Version != "v2.14.1" || r.Error == "" {
		t.Fatalf("bad tag: %+v", r)
	}
	if (*Watch)(nil).Latest().Version != "" {
		t.Fatal("nil watch")
	}
}

// Run waits Delay before the first lookup: a controller started for a
// moment does not ask GitHub.
func TestWatchRunDelay(t *testing.T) {
	calls := make(chan struct{}, 10)
	find := func(context.Context) (string, error) { calls <- struct{}{}; return "v2.13.0", nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { (&Watch{Find: find, Delay: time.Hour}).Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if len(calls) != 0 {
		t.Fatal("looked up before the delay")
	}
	w := &Watch{Find: find, Delay: time.Millisecond, Tick: time.Hour}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("never looked up")
	}
}
