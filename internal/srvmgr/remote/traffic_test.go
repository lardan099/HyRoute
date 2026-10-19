package remote_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

const fakeStatsSecret = "fake-stats-secret-0000"

// Answers of the Hysteria stats API (v2.6 format), fake users.
const (
	trafficFixture = `{"alice":{"tx":51234,"rx":9876543},"user":{"tx":0,"rx":120}}`
	onlineFixture  = `{"alice":2,"user":1}`
	streamsFixture = `{"streams":[
{"state":"estab","auth":"alice","connection":3157438,"stream":12,"req_addr":"example.com:443","hooked_req_addr":"example.com:443","tx":2048,"rx":81920,"initial_at":"2026-10-01T12:00:00.123456789Z","last_active_at":"2026-10-01T12:00:05Z"},
{"state":"connecting","auth":"user","connection":42,"stream":4,"req_addr":"192.0.2.10:443","hooked_req_addr":"example.org:443","tx":0,"rx":0,"initial_at":"2026-10-01T12:00:06Z","last_active_at":"2026-10-01T12:00:06Z"}]}`
)

func TestStatsURL(t *testing.T) {
	for _, c := range []struct{ listen, want string }{
		{"127.0.0.1:25413", "http://127.0.0.1:25413/traffic"},
		{":9999", "http://127.0.0.1:9999/traffic"},
		{"0.0.0.0:9999", "http://127.0.0.1:9999/traffic"},
		{"[::]:9999", "http://[::1]:9999/traffic"},
		{"[::1]:9999", "http://[::1]:9999/traffic"},
		{"localhost:9999", "http://127.0.0.1:9999/traffic"},
		{"192.0.2.1:9999", ""},
		{"example.com:9999", ""},
		{"127.0.0.1", ""},
		{"127.0.0.1:0", ""},
	} {
		got, err := remote.StatsURL(c.listen, remote.StatsTraffic)
		if (err != nil) != (c.want == "") || got != c.want {
			t.Errorf("%s: %q %v, want %q", c.listen, got, err, c.want)
		}
	}
	if _, err := remote.StatsURL("127.0.0.1:1", "/kick"); err == nil {
		t.Fatal("kick allowed")
	}
}

// statsServer answers curl requests like the stats API with secret and
// records the requests.
func statsServer(t *testing.T, secret string) (*fake.Executor, *[]string) {
	ex := fake.New()
	var reqs []string
	ex.On("curl").Do(func(c remote.Cmd) (remote.Result, error) {
		in := string(c.Stdin)
		reqs = append(reqs, in)
		if !strings.Contains(in, `header = "Authorization: `+secret+`"`) {
			return remote.Result{Stdout: []byte("unauthorized\n\n401")}, nil
		}
		body := map[string]string{"/traffic": trafficFixture, "/online": onlineFixture, "/dump/streams": streamsFixture}
		for p, b := range body {
			if strings.Contains(in, p+`"`) {
				return remote.Result{Stdout: []byte(b + "\n200")}, nil
			}
		}
		return remote.Result{Stdout: []byte("404 page not found\n\n404")}, nil
	})
	return ex, &reqs
}

func TestReadStats(t *testing.T) {
	ctx := context.Background()
	ex, reqs := statsServer(t, fakeStatsSecret)
	// Through the read-only executor: the monitor reads with it.
	ro := remote.ReadOnly(ex)

	b, err := remote.ReadStats(ctx, ro, "127.0.0.1:25413", fakeStatsSecret, remote.StatsTraffic)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := remote.ParseTraffic(b)
	if err != nil || tr["alice"] != (remote.UserTraffic{Tx: 51234, Rx: 9876543}) || tr["user"].Rx != 120 {
		t.Fatalf("%v %v", tr, err)
	}
	b, err = remote.ReadStats(ctx, ro, "127.0.0.1:25413", fakeStatsSecret, remote.StatsOnline)
	if err != nil {
		t.Fatal(err)
	}
	if on, err := remote.ParseOnline(b); err != nil || on["alice"] != 2 || len(on) != 2 {
		t.Fatalf("%v %v", on, err)
	}
	b, err = remote.ReadStats(ctx, ro, "[::1]:25413", fakeStatsSecret, remote.StatsStreams)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := remote.ParseStreams(b)
	if err != nil || len(ss) != 2 {
		t.Fatalf("%v %v", ss, err)
	}
	if s := ss[0]; s.User != "alice" || s.Addr != "example.com:443" || s.HookedAddr != "" || s.Rx != 81920 || s.Since.Nanosecond() != 123456789 || s.LastActive.IsZero() {
		t.Fatalf("%+v", s)
	}
	if s := ss[1]; s.HookedAddr != "example.org:443" || s.State != "connecting" {
		t.Fatalf("%+v", s)
	}

	if _, err := remote.ReadStats(ctx, ro, "127.0.0.1:25413", "fake-wrong-secret", remote.StatsTraffic); !errors.Is(err, remote.ErrStatsAuth) {
		t.Fatalf("wrong secret: %v", err)
	}

	// The secret is never in argv: only in the request on stdin.
	for _, c := range ex.Calls() {
		if strings.Contains(strings.Join(c.Args, " "), "secret") || c.Sudo {
			t.Fatalf("call %+v", c)
		}
	}
	if len(*reqs) != 4 || !strings.Contains((*reqs)[0], `url = "http://127.0.0.1:25413/traffic"`) {
		t.Fatalf("%q", *reqs)
	}

	// A secret with quotes is escaped; one with a line break is refused
	// (it would add a line to curl's config).
	ex2, reqs2 := statsServer(t, `fa"ke\x`)
	if _, err := remote.ReadStats(ctx, ex2, "127.0.0.1:1", `fa"ke\x`, remote.StatsOnline); err == nil {
		t.Fatal("escaped secret matched raw")
	}
	if !strings.Contains((*reqs2)[0], `"Authorization: fa\"ke\\x"`) {
		t.Fatalf("%q", (*reqs2)[0])
	}
	if _, err := remote.ReadStats(ctx, ex2, "127.0.0.1:1", "fake\noutput = /etc/x", remote.StatsOnline); err == nil || len(*reqs2) != 1 {
		t.Fatalf("line break: %v", err)
	}
}

func TestReadStatsFailures(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		res  remote.Result
		want error
	}{
		{remote.Result{ExitCode: 127}, remote.ErrNoCurl},
		{remote.Result{ExitCode: 7, Stderr: []byte("curl: (7) Failed to connect")}, remote.ErrStatsDown},
		{remote.Result{Stdout: []byte("\n401")}, remote.ErrStatsAuth},
	} {
		ex := fake.New()
		ex.On("curl").Reply(string(c.res.Stdout), c.res.ExitCode)
		if _, err := remote.ReadStats(ctx, ex, "127.0.0.1:25413", fakeStatsSecret, remote.StatsOnline); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v", c.res, err)
		}
	}
	ex := fake.New()
	ex.On("curl").Reply("oops", 0)
	if _, err := remote.ReadStats(ctx, ex, "127.0.0.1:25413", "", remote.StatsOnline); err == nil {
		t.Fatal("no status code accepted")
	}
	ex.On("curl").Reply("\n500", 0)
	if _, err := remote.ReadStats(ctx, ex, "127.0.0.1:25413", "", remote.StatsOnline); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500: %v", err)
	}
	for _, bad := range []string{"{", `{"alice":"x"}`} {
		if _, err := remote.ParseTraffic([]byte(bad)); err == nil {
			t.Errorf("traffic %q parsed", bad)
		}
	}
	if _, err := remote.ParseStreams([]byte(`{"streams":5}`)); err == nil {
		t.Error("streams parsed")
	}
}

// The read-only executor lets curl run only a GET of the stats API on
// loopback, in the form ReadStats builds.
func TestReadOnlyCurl(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("curl").Reply("{}\n200", 0)
	ro := remote.ReadOnly(ex)
	args := []string{"curl", "-sS", "--max-time", "5", "-K", "-"}
	ok := "url = \"http://127.0.0.1:25413/online\"\nheader = \"Authorization: x\"\nwrite-out = \"\\n%{http_code}\"\n"
	if _, err := ro.Run(ctx, remote.Cmd{Args: args, Stdin: []byte(ok)}); err != nil {
		t.Fatalf("stats request refused: %v", err)
	}
	for name, cmd := range map[string]remote.Cmd{
		"sudo":      {Args: args, Stdin: []byte(ok), Sudo: true},
		"other url": {Args: args, Stdin: []byte(strings.Replace(ok, "127.0.0.1", "192.0.2.1", 1))},
		"name":      {Args: args, Stdin: []byte(strings.Replace(ok, "127.0.0.1", "localhost", 1))},
		"kick":      {Args: args, Stdin: []byte(strings.Replace(ok, "/online", "/kick", 1))},
		"output":    {Args: args, Stdin: []byte(strings.Replace(ok, "header = ", "output = ", 1))},
		"extra":     {Args: args, Stdin: []byte("request = \"POST\"\n" + ok)},
		"argv":      {Args: []string{"curl", "-sS", "--max-time", "5", "-o", "/tmp/x", "-K", "-"}, Stdin: []byte(ok)},
		"url argv":  {Args: []string{"curl", "-sS", "http://127.0.0.1:25413/online"}},
	} {
		if _, err := ro.Run(ctx, cmd); !errors.Is(err, remote.ErrNotReadOnly) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
