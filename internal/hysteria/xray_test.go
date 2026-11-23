package hysteria

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/vless"
)

const testUUID = "5f0b7c1e-1234-4abc-9def-0123456789ab"

// fakeXray stands in for xray.exe (FAKE_XRAY): it reads the generated
// JSON config, serves its SOCKS5 inbound and connects straight to the
// destinations, as a working server would.
func fakeXray(mode string) {
	// args: run -format json -c <path>
	if len(os.Args) < 6 || os.Args[1] != "run" || os.Args[2] != "-format" || os.Args[3] != "json" || os.Args[4] != "-c" {
		fmt.Println("Failed to start: bad arguments", os.Args)
		os.Exit(23)
	}
	raw, err := os.ReadFile(os.Args[5])
	if err != nil {
		fmt.Println("Failed to start:", err)
		os.Exit(23)
	}
	var c struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Settings struct {
				Accounts []struct{ User, Pass string } `json:"accounts"`
			} `json:"settings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Settings struct {
				ID string `json:"id"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || len(c.Inbounds) != 1 || len(c.Outbounds) != 1 {
		fmt.Println("Failed to start: main: failed to load config files > infra/conf: invalid JSON")
		os.Exit(23)
	}
	in := c.Inbounds[0]
	if in.Listen != "127.0.0.1" {
		os.Exit(2)
	}
	fmt.Println("Xray 26.10.31 (Xray, Penetrates Everything.) Custom (go1.27.1 windows/amd64)")
	switch mode {
	case "fail":
		fmt.Println("Failed to start: main: failed to load config files: [x] > infra/conf: Failed to build REALITY config.")
		os.Exit(23)
	case "busy":
		fmt.Printf("Failed to start: app/proxyman/inbound: failed to listen TCP on %d > listen tcp 127.0.0.1:%d: bind: address already in use\n", in.Port, in.Port)
		os.Exit(23)
	}
	s := &socks5.Server{Username: in.Settings.Accounts[0].User, Password: in.Settings.Accounts[0].Pass}
	if err := s.Listen(fmt.Sprintf("127.0.0.1:%d", in.Port)); err != nil {
		os.Exit(2)
	}
	fmt.Println("2026/11/05 10:51:23.123456 [Warning] core: Xray 26.10.31 started")
	// A line that would carry the user ID: the redactor must hide it.
	fmt.Printf("2026/11/05 10:51:23.200000 [Info] proxy/vless/outbound: user %s\n", c.Outbounds[0].Settings.ID)
	for {
		time.Sleep(time.Hour)
	}
}

// vlessProfile is a server whose port answers (a local listener): the
// direct check of a failed run must not depend on the network the tests
// run in.
func vlessProfile(t *testing.T) Profile {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return Profile{Host: "127.0.0.1", Ports: port, Protocol: ProtoVLESS,
		VLESS: vless.Settings{ID: testUUID, Security: "tls", SNI: "vpn.example"}}
}

func newXraySupervisor(t *testing.T, mode string, probe string) (*Supervisor, chan Status, *[]string) {
	t.Helper()
	t.Setenv("FAKE_XRAY", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Status, 64)
	var lines []string
	var mu sync.Mutex
	s := &Supervisor{
		Exe:       exe,
		RunDir:    t.TempDir(),
		Profile:   vlessProfile(t),
		Redactor:  &logx.Redactor{},
		ProbeURLs: []string{probe},
		OnStatus:  func(st Status) { ch <- st },
		LogLine: func(l LogLine) {
			mu.Lock()
			lines = append(lines, l.Raw)
			mu.Unlock()
		},
	}
	return s, ch, &lines
}

func fastProbes(t *testing.T) {
	t.Helper()
	every, retry, timeout, direct := vlessProbeEvery, vlessRetryEvery, vlessProbeTimeout, vlessDirectWait
	vlessProbeEvery, vlessRetryEvery, vlessProbeTimeout, vlessDirectWait = 100*time.Millisecond, 50*time.Millisecond, time.Second, 200*time.Millisecond
	t.Cleanup(func() {
		vlessProbeEvery, vlessRetryEvery, vlessProbeTimeout, vlessDirectWait = every, retry, timeout, direct
	})
}

func TestVLESSConnectsThroughXray(t *testing.T) {
	fastProbes(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer web.Close()
	s, ch, lines := newXraySupervisor(t, "ok", web.URL+"/generate_204")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitState(t, ch, Connected)
	if !s.Available() || !st.UDPEnabled || st.Message != "" {
		t.Fatalf("%+v", st)
	}
	// The tunnel carries traffic, and the config with the ID is gone.
	c, err := s.Dial(t.Context(), socks5.AddrFromAddrPort(web.Listener.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if entries, _ := os.ReadDir(s.RunDir); len(entries) != 0 {
		t.Fatalf("config not removed: %v", entries)
	}
	time.Sleep(200 * time.Millisecond)
	s.Stop()
	all := strings.Join(*lines, "\n")
	if strings.Contains(all, testUUID) || !strings.Contains(all, "Xray 26.10.31 started") {
		t.Fatalf("log: %s", all)
	}
}

func TestVLESSStartFails(t *testing.T) {
	s, ch, _ := newXraySupervisor(t, "fail", "http://127.0.0.1:1/")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitState(t, ch, Failed)
	if st.Kind != ErrConfig || !strings.Contains(st.Message, "Xray не запустилась: main: failed to load config files") || st.RetryIn != backoffMax {
		t.Fatalf("%+v", st)
	}
}

func TestVLESSServerNeverAnswers(t *testing.T) {
	fastProbes(t)
	// Nothing listens there: the server "cannot reach" anything.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String() + "/"
	ln.Close()
	s, ch, _ := newXraySupervisor(t, "ok", dead)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitState(t, ch, Failed)
	if st.Kind == ErrNone || s.Available() || st.Message == "" {
		t.Fatalf("%+v", st)
	}
}

func TestVLESSServerLost(t *testing.T) {
	fastProbes(t)
	var down sync.Mutex
	gone := false
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		down.Lock()
		g := gone
		down.Unlock()
		if g {
			// The far side stops answering: hijack and drop the connection.
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer web.Close()
	s, ch, _ := newXraySupervisor(t, "ok", web.URL+"/")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	down.Lock()
	gone = true
	down.Unlock()
	st := waitState(t, ch, Failed)
	if !strings.HasPrefix(st.Message, "Потеряна связь с сервером: ") || st.Kind != ErrOther {
		t.Fatalf("%+v", st)
	}
	down.Lock()
	gone = false
	down.Unlock()
	if st := waitState(t, ch, Connected); st.Restarts != 1 {
		t.Fatalf("not restarted: %+v", st)
	}
}

func TestParseXrayLine(t *testing.T) {
	l := ParseXrayLine("2026/11/05 10:51:23.123456 [Warning] core: Xray 26.10.31 started")
	if l.Level != "warn" || l.Msg != "core: Xray 26.10.31 started" || l.Time.IsZero() || l.Time.Minute() != 51 {
		t.Fatalf("%+v", l)
	}
	for line, level := range map[string]string{
		"2026/11/05 10:51:23 [Error] app/proxyman/outbound: failed to process outbound traffic": "error",
		"[Info] something": "info",
		"Xray 26.10.31 (Xray, Penetrates Everything.)": "raw",
		"Failed to start: main: x":                     "raw",
		"2026/11/05 10:51:23.123456 [Odd] x":           "raw",
	} {
		if got := ParseXrayLine(line); got.Level != level {
			t.Errorf("%q: %q", line, got.Level)
		}
	}
}

func TestInterpretXray(t *testing.T) {
	ev, ok := InterpretXray(ParseXrayLine("Failed to start: main: failed to load config files: [c.json] > infra/conf: unknown \"fingerprint\": x"))
	if !ok || !ev.Fatal || ev.Kind != ErrConfig || !strings.HasPrefix(ev.Message, "Xray не запустилась: main:") {
		t.Fatalf("%+v %v", ev, ok)
	}
	ev, _ = InterpretXray(ParseXrayLine("Failed to start: app/proxyman/inbound: failed to listen TCP on 1 > listen tcp 127.0.0.1:1: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."))
	if ev.Kind != ErrPortBusy {
		t.Fatalf("%+v", ev)
	}
	if _, ok := InterpretXray(ParseXrayLine("2026/11/05 10:51:23 [Warning] Failed to start: nothing")); ok {
		t.Fatal("a warning is no start failure")
	}
}

func TestClassifyXray(t *testing.T) {
	for _, c := range []struct {
		err  error
		warn string
		kind ErrorKind
	}{
		{errNoHTTP, "proxy/vless/outbound: failed to find an available destination > dial tcp 203.0.113.5:443: i/o timeout", ErrTimeout},
		{errNoHTTP, "transport/internet/tls: x509: certificate is valid for a.example, not b.example", ErrTLS},
		{errNoHTTP, "transport/internet/reality: REALITY: processed invalid connection", ErrAuth},
		{errNoHTTP, "dial tcp 203.0.113.5:443: connectex: No connection could be made because the target machine actively refused it.", ErrTimeout},
		{fmt.Errorf("%w: EOF", errNoHTTP), "", ErrOther},
		{errors.New("context deadline exceeded"), "", ErrTimeout},
		{errors.New("strange"), "", ErrOther},
	} {
		if kind, msg := ClassifyXray(c.err, c.warn); kind != c.kind || msg == "" {
			t.Errorf("%v / %q: %v %q", c.err, c.warn, kind, msg)
		}
	}
}

// A failed check says whether the server's port answers at all.
func TestDirectCheck(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	kind, msg := directCheck(t.Context(), ln.Addr().String(), ErrTimeout, "Сервер не отвечает: проверьте адрес и порт")
	if kind != ErrOther || !strings.HasPrefix(msg, "Порт сервера отвечает (TCP за ") || !strings.Contains(msg, "запросы через VLESS не проходят") {
		t.Fatalf("%v %q", kind, msg)
	}
	kind, msg = directCheck(t.Context(), ln.Addr().String(), ErrTLS, "Сертификат")
	if kind != ErrTLS || !strings.HasPrefix(msg, "Сертификат (порт сервера отвечает") {
		t.Fatalf("%v %q", kind, msg)
	}
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	kind, msg = directCheck(t.Context(), addr, ErrOther, "x")
	if kind != ErrTimeout || !strings.HasPrefix(msg, "Порт сервера не отвечает (") || strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("%v %q", kind, msg)
	}
}

// While a run starts, each failed check shows its reason at once.
func TestVLESSReasonWhileStarting(t *testing.T) {
	fastProbes(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String() + "/"
	ln.Close()
	s, ch, _ := newXraySupervisor(t, "ok", dead)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case st := <-ch:
			if st.State == Connecting && strings.Contains(st.Message, "(попытка 1 из 3)") {
				return
			}
		case <-deadline:
			t.Fatal("no reason while starting")
		}
	}
}

func TestXrayVersionAndTestReason(t *testing.T) {
	v, err := parseXrayVersion([]byte("Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 windows/amd64)\nA unified platform for anti-censorship.\n"))
	if err != nil || v != "v26.10.31" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := parseXrayVersion([]byte("Hysteria version v2")); err == nil {
		t.Fatal("another program taken for Xray")
	}
	out := "Xray 26.10.31 (Xray, Penetrates Everything.)\n2026/11/05 [Info] infra/conf/serial: Reading config: stdin:\nFailed to start: main: failed to load config files: [stdin:] > infra/conf: unknown \"fingerprint\": x\n"
	if r := xrayTestReason([]byte(out), errors.New("exit status 23")); r != `main: failed to load config files: [stdin:] > infra/conf: unknown "fingerprint": x` {
		t.Fatalf("%q", r)
	}
	if r := xrayTestReason(nil, errors.New("exit status 1")); r != "exit status 1" {
		t.Fatalf("%q", r)
	}
}

// While answers keep coming back through the server (Received grows),
// the periodic check is skipped; once they stop, it runs again.
func TestVLESSSkipsCheckWhileTrafficFlows(t *testing.T) {
	fastProbes(t)
	var hits atomic.Int64
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer web.Close()
	s, ch, _ := newXraySupervisor(t, "ok", web.URL+"/")
	var recv, flowing atomic.Int64
	flowing.Store(1)
	s.Received = func() int64 { return recv.Add(flowing.Load()) }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, ch, Connected)
	n := hits.Load()
	time.Sleep(10 * vlessProbeEvery)
	if got := hits.Load(); got != n {
		t.Fatalf("checked %d times while traffic came back", got-n)
	}
	flowing.Store(0)
	time.Sleep(10 * vlessProbeEvery)
	if hits.Load() == n {
		t.Fatal("no check once the traffic stopped")
	}
}

// The first probe URL answers: the others are not asked.
func TestProbeFirstURLFirst(t *testing.T) {
	var first, second atomic.Int64
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer b.Close()
	srv := &socks5.Server{}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c := socks5.Client{Server: srv.Addr()}
	s := &Supervisor{ProbeURLs: []string{a.URL + "/", b.URL + "/"}}
	if err := s.probeTunnel(t.Context(), c); err != nil || first.Load() != 1 || second.Load() != 0 {
		t.Fatalf("%v first %d second %d", err, first.Load(), second.Load())
	}
	a.Close()
	if err := s.probeTunnel(t.Context(), c); err != nil || second.Load() != 1 {
		t.Fatalf("the others were not asked when the first failed: %v %d", err, second.Load())
	}
}
