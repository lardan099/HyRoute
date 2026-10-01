package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The Hysteria traffic stats API (trafficStats in the server config) is
// an HTTP server on the managed machine. The controller asks it from the
// machine itself, with curl, so the API never has to be reachable from
// outside: curl gets its whole request (URL and the Authorization header
// with the secret) as a config on stdin, never in argv, where other users
// of the machine would see it in the process list.

// StatsPath is one reading endpoint of the stats API.
type StatsPath string

const (
	StatsTraffic StatsPath = "/traffic"      // bytes per user since the start
	StatsOnline  StatsPath = "/online"       // connections per online user
	StatsStreams StatsPath = "/dump/streams" // the open streams, live
)

var statsPaths = []StatsPath{StatsTraffic, StatsOnline, StatsStreams}

var (
	// ErrNoCurl: the machine has no curl.
	ErrNoCurl = errors.New("на сервере нет curl")
	// ErrStatsDown: nothing listens on the stats address.
	ErrStatsDown = errors.New("API статистики Hysteria не отвечает")
	// ErrStatsAuth: the API refused the secret.
	ErrStatsAuth = errors.New("API статистики Hysteria не принял секрет")
)

// curlStats is the argv of a stats request; everything else comes on
// stdin (statsRequest).
var curlStats = []string{"curl", "-sS", "--max-time", "5", "-K", "-"}

// StatsURL is the URL of path on the API listening on listen (host:port
// from the config). An API on every interface is asked on loopback; the
// host must be a loopback address otherwise.
func StatsURL(listen string, path StatsPath) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("trafficStats.listen %q: %w", listen, err)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("trafficStats.listen %q: bad port", listen)
	}
	switch ip := net.ParseIP(host); {
	case host == "" || host == "localhost" || (ip != nil && ip.IsUnspecified() && ip.To4() != nil):
		host = "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		host = "::1"
	case ip == nil || !ip.IsLoopback():
		return "", fmt.Errorf("trafficStats.listen %q: not a loopback address", listen)
	}
	if !slices.Contains(statsPaths, path) {
		return "", fmt.Errorf("bad stats path %q", path)
	}
	return "http://" + net.JoinHostPort(host, port) + string(path), nil
}

// statsRequest is the curl config of a request: the secret is a quoted
// string (curl's config syntax: backslash escapes).
func statsRequest(url, secret string) ([]byte, error) {
	if strings.ContainsAny(secret, "\x00\r\n") {
		return nil, errors.New("trafficStats.secret: line break in the secret")
	}
	q := func(s string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "url = %s\n", q(url))
	if secret != "" {
		fmt.Fprintf(&b, "header = %s\n", q("Authorization: "+secret))
	}
	b.WriteString("write-out = \"\\n%{http_code}\"\n")
	return b.Bytes(), nil
}

// statsStdin reports whether stdin is a request statsRequest builds for a
// loopback URL: what the read-only executor lets curl run.
func statsStdin(stdin []byte) bool {
	lines := strings.Split(strings.TrimSuffix(string(stdin), "\n"), "\n")
	if len(lines) < 2 || len(lines) > 3 || lines[len(lines)-1] != `write-out = "\n%{http_code}"` {
		return false
	}
	url, ok := strings.CutPrefix(lines[0], `url = "http://`)
	if !ok || !strings.HasSuffix(url, `"`) {
		return false
	}
	hostPort, path, ok := strings.Cut(strings.TrimSuffix(url, `"`), "/")
	if !ok || !slices.Contains(statsPaths, StatsPath("/"+path)) {
		return false
	}
	if host, _, err := net.SplitHostPort(hostPort); err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	return len(lines) == 2 || strings.HasPrefix(lines[1], `header = "Authorization: `)
}

// ReadStats asks the stats API listening on listen for path and returns
// the body of a 200 answer.
func ReadStats(ctx context.Context, ex Executor, listen, secret string, path StatsPath) ([]byte, error) {
	url, err := StatsURL(listen, path)
	if err != nil {
		return nil, err
	}
	req, err := statsRequest(url, secret)
	if err != nil {
		return nil, err
	}
	res, err := ex.Run(ctx, Cmd{Args: curlStats, Stdin: req})
	if err != nil {
		return nil, err
	}
	switch res.ExitCode {
	case 0:
	case 127:
		return nil, ErrNoCurl
	case 7: // could not connect
		return nil, ErrStatsDown
	default:
		return nil, &ExitError{Op: "curl", Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	out := bytes.TrimRight(res.Stdout, "\n")
	i := bytes.LastIndexByte(out, '\n')
	code, err := strconv.Atoi(string(out[i+1:]))
	if err != nil {
		return nil, errors.New("API статистики Hysteria: ответ без кода")
	}
	body := out[:max(i, 0)]
	switch {
	case code == 200:
		return body, nil
	case code == 401:
		return nil, ErrStatsAuth
	default:
		return nil, fmt.Errorf("API статистики Hysteria ответил %d", code)
	}
}

// UserTraffic is what a user moved since Hysteria started, as Hysteria
// counts it: Tx is the client's upload, Rx its download.
type UserTraffic struct {
	Tx uint64 `json:"tx"`
	Rx uint64 `json:"rx"`
}

// ParseTraffic reads a /traffic answer: user ID → bytes.
func ParseTraffic(b []byte) (map[string]UserTraffic, error) {
	m := map[string]UserTraffic{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("ответ /traffic не разобрать: %w", err)
	}
	return m, nil
}

// ParseOnline reads an /online answer: user ID → open connections.
func ParseOnline(b []byte) (map[string]int, error) {
	m := map[string]int{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("ответ /online не разобрать: %w", err)
	}
	return m, nil
}

// Stream is one open proxied stream (TCP connection) of a client.
type Stream struct {
	State      string    `json:"state"` // init, hooking, connecting, estab, closed
	User       string    `json:"user"`
	Connection uint32    `json:"connection"`
	Stream     uint64    `json:"stream"`
	Addr       string    `json:"addr"`       // where the client asked to go
	HookedAddr string    `json:"hookedAddr"` // after sniffing, when it changed
	Tx         uint64    `json:"tx"`
	Rx         uint64    `json:"rx"`
	Since      time.Time `json:"since"`
	LastActive time.Time `json:"lastActive"`
}

// ParseStreams reads a /dump/streams answer (JSON).
func ParseStreams(b []byte) ([]Stream, error) {
	var d struct {
		Streams []struct {
			State         string `json:"state"`
			Auth          string `json:"auth"`
			Connection    uint32 `json:"connection"`
			Stream        uint64 `json:"stream"`
			ReqAddr       string `json:"req_addr"`
			HookedReqAddr string `json:"hooked_req_addr"`
			Tx            uint64 `json:"tx"`
			Rx            uint64 `json:"rx"`
			InitialAt     string `json:"initial_at"`
			LastActiveAt  string `json:"last_active_at"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("ответ /dump/streams не разобрать: %w", err)
	}
	out := make([]Stream, 0, len(d.Streams))
	for _, s := range d.Streams {
		x := Stream{State: s.State, User: s.Auth, Connection: s.Connection, Stream: s.Stream, Addr: s.ReqAddr, Tx: s.Tx, Rx: s.Rx}
		if s.HookedReqAddr != s.ReqAddr {
			x.HookedAddr = s.HookedReqAddr
		}
		x.Since, _ = time.Parse(time.RFC3339Nano, s.InitialAt)
		x.LastActive, _ = time.Parse(time.RFC3339Nano, s.LastActiveAt)
		out = append(out, x)
	}
	return out, nil
}
