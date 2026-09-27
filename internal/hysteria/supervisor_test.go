package hysteria

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/socks5"
)

// The test binary doubles as a fake hysteria.exe: with FAKE_HYSTERIA set it
// reads the generated config, serves SOCKS5 with the configured credentials
// and logs like the real client.
func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_HYSTERIA"); mode != "" {
		fakeHysteria(mode)
		return
	}
	os.Exit(m.Run())
}

func fakeHysteria(mode string) {
	// args: client -c <path>
	cfgPath := os.Args[len(os.Args)-1]
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"fatal","time":0,"msg":"failed to read client config","error":%q}`+"\n", err.Error())
		os.Exit(1)
	}
	var c yConfig
	yaml.Unmarshal(raw, &c)
	if !strings.HasPrefix(c.SOCKS5.Listen, "127.0.0.1:") {
		os.Exit(2) // never listen beyond loopback (a firewall prompt)
	}
	switch mode {
	case "auth":
		fmt.Fprintf(os.Stderr, `{"level":"fatal","time":1726480000000,"msg":"failed to initialize client","error":"authentication error, HTTP status code: 404 (auth=%s)"}`+"\n", c.Auth)
		os.Exit(1)
	case "ok":
		s := &socks5.Server{Username: c.SOCKS5.Username, Password: c.SOCKS5.Password}
		if err := s.Listen(c.SOCKS5.Listen); err != nil {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, `{"level":"info","time":1726480000000,"msg":"connected to server","addr":%q,"udpEnabled":true,"count":1}`+"\n", c.Server)
		select {}
	case "late":
		// Like the real client: connect first, open the SOCKS5 port later.
		fmt.Fprintf(os.Stderr, `{"level":"info","time":1726480000000,"msg":"connected to server","addr":%q,"udpEnabled":true,"count":1}`+"\n", c.Server)
		time.Sleep(500 * time.Millisecond)
		s := &socks5.Server{Username: c.SOCKS5.Username, Password: c.SOCKS5.Password}
		if err := s.Listen(c.SOCKS5.Listen); err != nil {
			os.Exit(2)
		}
		select {}
	case "lost":
		// Connected, then the server goes away. The real client stays up,
		// drops the dead connection and logs every request whose reconnect
		// fails. A target error and a dropped connection come first: they
		// alone must not restart it.
		s := &socks5.Server{Username: c.SOCKS5.Username, Password: c.SOCKS5.Password}
		if err := s.Listen(c.SOCKS5.Listen); err != nil {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, `{"level":"info","time":1726480000000,"msg":"connected to server","addr":%q,"udpEnabled":true,"count":1}`+"\n", c.Server)
		warn := func(e string) {
			fmt.Fprintf(os.Stderr, `{"level":"warn","time":1726480000000,"msg":"SOCKS5 TCP error","addr":"127.0.0.1:50000","reqAddr":"example.com:443","error":%q}`+"\n", e)
		}
		time.Sleep(300 * time.Millisecond)
		warn("dial error: dial tcp 192.0.2.1:443: i/o timeout")
		warn("connection closed: timeout: no recent network activity")
		time.Sleep(300 * time.Millisecond)
		warn("connect error: timeout: handshake did not complete in time")
		select {}
	case "deaf":
		// Connected, but the SOCKS5 port never opens. Sleep rather than
		// select{}: with no other goroutine the runtime reports a deadlock
		// and exits (it does on Windows).
		fmt.Fprintf(os.Stderr, `{"level":"info","time":1726480000000,"msg":"connected to server","addr":%q,"udpEnabled":true,"count":1}`+"\n", c.Server)
		for {
			time.Sleep(time.Hour)
		}
	}
}

func TestLogParse(t *testing.T) {
	l := ParseLogLine(`{"level":"info","time":1726480000000,"msg":"connected to server","addr":"1.2.3.4:443","udpEnabled":false,"tx":0,"count":1}`)
	if l.Level != "info" || l.Msg != "connected to server" || l.Str("addr") != "1.2.3.4:443" || l.Time.UnixMilli() != 1726480000000 {
		t.Fatalf("%+v", l)
	}
	ev, ok := Interpret(l)
	if !ok || !ev.Connected || ev.UDPEnabled {
		t.Fatalf("%+v", ev)
	}
	raw := ParseLogLine("panic: something")
	if raw.Level != "raw" || raw.Msg != "panic: something" {
		t.Fatalf("%+v", raw)
	}
	if _, ok := Interpret(raw); ok {
		t.Fatal("raw line must not be an event")
	}
	for text, kind := range map[string]ErrorKind{
		"authentication error, HTTP status code: 404":                            ErrAuth,
		"tls: failed to verify certificate: x509: certificate signed by unknown": ErrTLS,
		"CRYPTO_ERROR 0x12a (remote): tls: bad certificate":                      ErrTLS,
		"timeout: no recent network activity":                                    ErrTimeout,
		"invalid config: obfs.type: unsupported obfuscation type":                ErrConfig,
		"something else": ErrOther,
	} {
		if k, _ := Classify(text); k != kind {
			t.Fatalf("%q: kind %d want %d", text, k, kind)
		}
	}
	ev, ok = Interpret(ParseLogLine(`{"level":"fatal","time":0,"msg":"failed to initialize client","error":"authentication error, HTTP status code: 404"}`))
	if !ok || !ev.Fatal || ev.Kind != ErrAuth {
		t.Fatalf("%+v", ev)
	}
}

func newSupervisor(t *testing.T, mode string, p Profile) (*Supervisor, chan Status, *[]string) {
	t.Helper()
	t.Setenv("FAKE_HYSTERIA", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Status, 64)
	var lines []string
	var mu sync.Mutex
	red := &logx.Redactor{}
	s := &Supervisor{
		Exe:      exe,
		RunDir:   t.TempDir(),
		Profile:  p,
		Redactor: red,
		OnStatus: func(st Status) { ch <- st },
		LogLine: func(l LogLine) {
			mu.Lock()
			lines = append(lines, l.Raw)
			mu.Unlock()
		},
	}
	return s, ch, &lines
}

func waitState(t *testing.T, ch chan Status, want State) Status {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case st := <-ch:
			if st.State == want {
				return st
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %v", want)
		}
	}
}

func TestSupervisorConnectsAndTunnels(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	var gotIPs []netip.Addr
	p := Profile{Host: "hy.example", Ports: "443", Auth: "SuperSecretAuth", PinServerIP: true}
	s, ch, _ := newSupervisor(t, "ok", p)
	s.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.1")}, nil
	}
	s.SetServerIPs = func(ips []netip.Addr) error { gotIPs = ips; return nil }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitState(t, ch, Connected)
	if !s.Available() || !st.UDPEnabled {
		t.Fatal("should be available")
	}
	// All resolved IPs are excluded, IPv4 is pinned.
	if len(gotIPs) != 3 || st.PinnedIP != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("ips %v pinned %v", gotIPs, st.PinnedIP)
	}
	c, err := s.Dial(context.Background(), socks5.AddrFromAddrPort(echo.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ok"))
	buf := make([]byte, 2)
	io.ReadFull(c, buf)
	c.Close()
	if string(buf) != "ok" {
		t.Fatal("tunnel echo")
	}
	// Config file is removed once connected.
	entries, _ := os.ReadDir(s.RunDir)
	if len(entries) != 0 {
		t.Fatalf("config not removed: %v", entries)
	}
	s.Stop()
	if s.Available() {
		t.Fatal("must be unavailable after stop")
	}
}

func TestSupervisorAuthErrorBacksOff(t *testing.T) {
	p := Profile{Host: "198.51.100.1", Ports: "443", Auth: "SuperSecretAuth"}
	s, ch, lines := newSupervisor(t, "auth", p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, ch, Failed)
	s.Stop()
	if st.Kind != ErrAuth || st.RetryIn != backoffMax || !strings.Contains(st.Message, "Неверный пароль") {
		t.Fatalf("%+v", st)
	}
	for _, l := range *lines {
		if strings.Contains(l, "SuperSecretAuth") {
			t.Fatalf("secret leaked into log: %s", l)
		}
	}
	if len(*lines) == 0 {
		t.Fatal("no log lines captured")
	}
}

func TestSupervisorMissingExe(t *testing.T) {
	p := Profile{Host: "198.51.100.1", Ports: "443"}
	s, ch, _ := newSupervisor(t, "ok", p)
	s.Exe = "/nonexistent/hysteria"
	s.Start()
	st := waitState(t, ch, Failed)
	s.Stop()
	if st.RetryIn != backoffMin {
		t.Fatalf("first retry should use minimum backoff: %+v", st)
	}
}

func TestReservePortUnique(t *testing.T) {
	var mu sync.Mutex
	seen := map[int]bool{}
	var wg sync.WaitGroup
	var releases []func()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, rel, err := reservePort()
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			if seen[p] {
				t.Errorf("port %d handed out twice", p)
			}
			seen[p] = true
			releases = append(releases, rel)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, r := range releases {
		r()
	}
	if len(reserved) != 0 {
		t.Fatal("reservations leaked")
	}
}

func TestClassifyPortBusy(t *testing.T) {
	k, _ := Classify("invalid config: listen: listen tcp4 127.0.0.1:4383: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if k != ErrPortBusy {
		t.Fatalf("kind %v", k)
	}
	if k, _ := Classify("invalid config: server: bad port"); k != ErrConfig {
		t.Fatalf("kind %v", k)
	}
}

func TestSupervisorWaitsForSOCKSPort(t *testing.T) {
	p := Profile{Host: "198.51.100.1", Ports: "443", Auth: "x"}
	s, ch, _ := newSupervisor(t, "late", p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	// Connected must mean the port already takes connections.
	if !dialOK(s.SOCKS().Server) {
		t.Fatal("reported connected before the SOCKS5 port opened")
	}
}

func TestSupervisorRestartsWhenSOCKSClosed(t *testing.T) {
	p := Profile{Host: "198.51.100.1", Ports: "443", Auth: "x"}
	s, ch, _ := newSupervisor(t, "ok", p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	first := s.SOCKS().Server
	// Simulate a port that stopped answering: point the client at a closed
	// port of this run and dial.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	s.mu.Lock()
	s.socks.Server = dead
	s.mu.Unlock()
	if _, err := s.Dial(context.Background(), socks5.Addr{Host: "example.com", Port: 80}); err == nil || !isRefused(err) {
		t.Fatalf("want refused, got %v", err)
	}
	st := waitState(t, ch, Failed)
	if st.Kind != ErrPortBusy || st.RetryIn > time.Second {
		t.Fatalf("%+v", st)
	}
	waitState(t, ch, Connected)
	if now := s.SOCKS().Server; now == dead || now == "" {
		t.Fatalf("not restarted on a new port: %s (first %s)", now, first)
	}
}

func TestSupervisorRestartsWhenSOCKSNeverOpens(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 15s")
	}
	p := Profile{Host: "198.51.100.1", Ports: "443", Auth: "x"}
	s, ch, _ := newSupervisor(t, "deaf", p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case st := <-ch:
			if st.State == Connected {
				t.Fatal("must not report connected without a SOCKS5 port")
			}
			if st.State == Failed {
				if st.Kind != ErrPortBusy {
					t.Fatalf("%+v", st)
				}
				return
			}
		case <-deadline:
			t.Fatal("no restart")
		}
	}
}

// Profiles started together share RunDir: each Hysteria must read its own
// config (server, SOCKS5 port and credentials).
func TestSupervisorsShareRunDir(t *testing.T) {
	const n = 5
	dir := t.TempDir()
	var sups []*Supervisor
	var logs []*[]string
	for i := range n {
		s, _, lines := newSupervisor(t, "ok", Profile{Host: fmt.Sprintf("198.51.100.%d", i+1), Ports: "443", Auth: fmt.Sprintf("auth-%d", i)})
		s.RunDir = dir
		sups, logs = append(sups, s), append(logs, lines)
	}
	var wg sync.WaitGroup
	for _, s := range sups {
		wg.Add(1)
		go func() { defer wg.Done(); s.Start() }()
	}
	wg.Wait()
	defer func() {
		for _, s := range sups {
			s.Stop()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for i, s := range sups {
		for !s.Available() {
			if time.Now().After(deadline) {
				t.Fatalf("profile %d never connected: %+v", i, s.Status())
			}
			time.Sleep(20 * time.Millisecond)
		}
		if st := s.Status(); st.Restarts > 0 {
			t.Errorf("profile %d restarted %d times (%s)", i, st.Restarts, st.Message)
		}
	}
	time.Sleep(100 * time.Millisecond)
	for i, l := range logs {
		want := fmt.Sprintf("198.51.100.%d:443", i+1)
		found := false
		for _, line := range *l {
			if strings.Contains(line, "connected to server") {
				found = found || strings.Contains(line, want)
				if !strings.Contains(line, want) {
					t.Errorf("profile %d: Hysteria read another profile's config: %s", i, line)
				}
			}
		}
		if !found {
			t.Errorf("profile %d: no connect line for %s", i, want)
		}
	}
}

// After the first connection Hysteria never exits: a server that goes away
// shows up only as request warnings. Failed reconnects count, target
// errors and dropped connections do not.
func TestInterpretReconnectFailure(t *testing.T) {
	line := func(errText string) LogLine {
		b, _ := json.Marshal(map[string]any{"level": "warn", "time": 1726480000000, "msg": "SOCKS5 TCP error",
			"addr": "127.0.0.1:50000", "reqAddr": "example.com:443", "error": errText})
		return ParseLogLine(string(b))
	}
	for text, kind := range map[string]ErrorKind{
		"connect error: timeout: handshake did not complete in time":                            ErrTimeout,
		"connect error: CRYPTO_ERROR 0x12a (remote): tls: bad certificate":                      ErrTLS,
		"authentication error, HTTP status code: 404":                                           ErrAuth,
		"connect error: wsasendto: A socket operation was attempted to an unreachable network.": ErrOther,
		"invalid config: server: lookup hy.example: no such host":                               ErrOther,
	} {
		ev, ok := Interpret(line(text))
		if !ok || !ev.Lost || ev.Kind != kind || ev.Message == "" {
			t.Errorf("%q: %+v %v", text, ev, ok)
		}
	}
	for _, text := range []string{
		"dial error: dial tcp 192.0.2.1:443: i/o timeout",
		"connection closed: timeout: no recent network activity",
		"connection closed: Application error 0x0 (remote)",
		"wsarecv: An existing connection was forcibly closed by the remote host.",
		"",
	} {
		if ev, ok := Interpret(line(text)); ok {
			t.Errorf("%q must not be an event: %+v", text, ev)
		}
	}
}

func TestSupervisorRestartsWhenServerLost(t *testing.T) {
	p := Profile{Host: "198.51.100.1", Ports: "443", Auth: "x"}
	s, ch, _ := newSupervisor(t, "lost", p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	st := waitState(t, ch, Failed)
	if st.Kind != ErrTimeout || !strings.Contains(st.Message, "Сервер не отвечает") || st.RetryIn != backoffMin {
		t.Fatalf("%+v", st)
	}
	if s.Available() {
		t.Fatal("a lost server must not stay available")
	}
	if st := waitState(t, ch, Connected); st.Restarts != 1 {
		t.Fatalf("not restarted: %+v", st)
	}
}

// Without a pinned IP Hysteria resolves the host itself and may still use
// any address seen during the run: re-resolving only grows the exclusion.
func TestSupervisorReResolveWithoutPinOnlyGrows(t *testing.T) {
	p := Profile{Host: "hy.example", Ports: "443", Auth: "x"}
	s, ch, _ := newSupervisor(t, "ok", p)
	s.ReResolveEvery = 20 * time.Millisecond
	var mu sync.Mutex
	var sets [][]netip.Addr
	n := 0
	s.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		n++ // .1, .2, then .3 for good
		return []netip.Addr{netip.AddrFrom4([4]byte{198, 51, 100, byte(min(n, 3))})}, nil
	}
	s.SetServerIPs = func(ips []netip.Addr) error {
		mu.Lock()
		sets = append(sets, slices.Clone(ips))
		mu.Unlock()
		return nil
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		last := sets[len(sets)-1]
		mu.Unlock()
		if len(last) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("exclusion never grew: %v", last)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // more ticks with an unchanged answer
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(sets); i++ {
		for _, ip := range sets[i-1] {
			if !slices.Contains(sets[i], ip) {
				t.Fatalf("exclusion narrowed while Hysteria runs: %v", sets)
			}
		}
	}
	if len(sets) != 3 {
		t.Fatalf("exclusion set again without new addresses: %v", sets)
	}
	if st := s.Status(); st.State != Connected || st.Restarts != 0 || len(st.ServerIPs) != 3 {
		t.Fatalf("%+v", st)
	}
}

// Secrets are redacted after parsing: one that matches the JSON syntax or
// the message must not hide "connected to server".
func TestSupervisorSecretLikeLogSyntax(t *testing.T) {
	for _, auth := range []string{"connected", "true"} {
		t.Run(auth, func(t *testing.T) {
			s, ch, lines := newSupervisor(t, "ok", Profile{Host: "198.51.100.1", Ports: "443", Auth: auth})
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			st := waitState(t, ch, Connected)
			s.Stop()
			if !st.UDPEnabled {
				t.Fatalf("udpEnabled lost: %+v", st)
			}
			for _, l := range *lines {
				if strings.Contains(l, auth) {
					t.Fatalf("secret leaked into log: %s", l)
				}
			}
		})
	}
}

func TestRedactLine(t *testing.T) {
	r := &logx.Redactor{}
	r.Set("hunter22")
	l := redactLine(r, ParseLogLine(`{"level":"warn","time":1,"msg":"x hunter22","error":"auth hunter22","nested":{"a":["hunter22",7]},"n":5}`))
	nested, _ := l.Fields["nested"].(map[string]any)
	if l.Msg != "x ***" || l.Str("error") != "auth ***" || strings.Contains(l.Raw, "hunter22") ||
		!reflect.DeepEqual(nested["a"], []any{"***", 7.0}) || l.Fields["n"] != 5.0 || l.Level != "warn" {
		t.Fatalf("%+v", l)
	}
}
