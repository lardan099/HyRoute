package hysteria

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/socks5"
)

type State int

const (
	Stopped State = iota
	Connecting
	Connected
	Failed
)

func (s State) String() string {
	return [...]string{"stopped", "connecting", "connected", "failed"}[s]
}

type Status struct {
	State      State
	Kind       ErrorKind
	Message    string
	UDPEnabled bool
	ServerIPs  []netip.Addr
	PinnedIP   netip.Addr
	Restarts   int
	RetryIn    time.Duration
	SOCKS      string // local SOCKS5 address of the current run
}

// Supervisor runs hysteria.exe in SOCKS5 mode, restarts it with backoff and
// exposes the SOCKS5 inbound as a relay.Tunnel.
type Supervisor struct {
	Exe     string
	RunDir  string
	Profile Profile
	// Redactor gets the current secrets (group RedactGroup); every log line
	// passes through it.
	Redactor    *logx.Redactor
	RedactGroup string
	// LogLine receives every Hysteria log line (Raw, Msg and string field
	// values already redacted).
	LogLine func(LogLine)
	// OnStatus receives status changes.
	OnStatus func(Status)
	// SetServerIPs receives all resolved server IPs before Hysteria starts
	// and whenever they change, so the exclusion is in place before
	// Hysteria sends its first packet.
	SetServerIPs func([]netip.Addr) error
	// Resolve defaults to the system resolver. On Windows that is
	// GetAddrInfoW -> Dnscache, whose DNS traffic is never routed.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// ReResolveEvery defaults to 5 minutes.
	ReResolveEvery time.Duration

	mu        sync.Mutex
	status    Status
	socks     socks5.Client
	cancel    context.CancelFunc
	done      chan struct{}
	available atomic.Bool
	kick      chan restart // current run's restart request
	probing   atomic.Bool
	// pinFailed is the pinned IP of the last run that never connected: the
	// next run pins another address. Used by the loop goroutine only.
	pinFailed netip.Addr
}

// restart asks the running Hysteria to be killed and started again.
type restart struct {
	kind ErrorKind
	msg  string
}

// Start launches the supervision loop. Stop must be called to end it.
func (s *Supervisor) Start() error {
	if err := s.Profile.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.RunDir, 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.done = make(chan struct{})
	s.mu.Unlock()
	go s.loop(ctx)
	return nil
}

// Stop kills Hysteria and waits for the loop to exit.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// Status returns the current status.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Available implements relay.Tunnel.
func (s *Supervisor) Available() bool { return s.available.Load() }

// Dial implements relay.Tunnel.
func (s *Supervisor) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	s.mu.Lock()
	c, kick := s.socks, s.kick
	s.mu.Unlock()
	if c.Server == "" {
		return nil, errors.New("hysteria: not running")
	}
	conn, err := c.Connect(ctx, dst)
	if err != nil && isRefused(err) {
		s.checkSOCKS(c.Server, kick)
	}
	return conn, err
}

// UDPAvailable reports whether tunneled UDP works: connected and the
// server allows UDP.
func (s *Supervisor) UDPAvailable() bool {
	if !s.available.Load() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.UDPEnabled
}

// UDPAssociate opens a SOCKS5 UDP association through Hysteria.
func (s *Supervisor) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	s.mu.Lock()
	c, kick := s.socks, s.kick
	s.mu.Unlock()
	if c.Server == "" {
		return nil, errors.New("hysteria: not running")
	}
	a, err := c.UDPAssociate(ctx)
	if err != nil && isRefused(err) {
		s.checkSOCKS(c.Server, kick)
	}
	return a, err
}

// checkSOCKS runs after a refused SOCKS5 connection while Hysteria is up:
// if the local port stays closed, Hysteria is restarted on a new one
// instead of rejecting every tunneled connection until the user
// reconnects.
func (s *Supervisor) checkSOCKS(addr string, kick chan restart) {
	if kick == nil || !s.available.Load() || !s.probing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.probing.Store(false)
		for range 3 {
			time.Sleep(300 * time.Millisecond)
			if dialOK(addr) {
				return
			}
		}
		select {
		case kick <- restart{ErrPortBusy, "Локальный порт SOCKS5 перестал отвечать, перезапуск Hysteria"}:
		default:
		}
	}()
}

func dialOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// waitListening waits until Hysteria accepts connections on its SOCKS5
// port. Hysteria connects to the server first and opens the port after
// that, so "connected to server" alone does not mean it can take traffic.
func waitListening(ctx context.Context, addr string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		if dialOK(addr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// isRefused reports a TCP connection refused (nothing listens on the port).
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 10061 // WSAECONNREFUSED
}

// SOCKS returns the current SOCKS5 client settings.
func (s *Supervisor) SOCKS() socks5.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.socks
}

func (s *Supervisor) setStatus(f func(*Status)) {
	s.mu.Lock()
	f(&s.status)
	st := s.status
	// Under the lock: an update from the run's wait loop (new server IPs)
	// may race the probe that marks the run connected.
	s.available.Store(st.State == Connected)
	s.mu.Unlock()
	if s.OnStatus != nil {
		s.OnStatus(st)
	}
}

const (
	backoffMin  = time.Second
	backoffMax  = 60 * time.Second
	stableAfter = 30 * time.Second
	// busyRetries: quick retries after ErrPortBusy in a row; a bind that
	// keeps failing (a policy or security software refusing it) is no
	// race, and each retry is a full connection to the server.
	busyRetries = 3
)

func (s *Supervisor) loop(ctx context.Context) {
	defer func() {
		s.setStatus(func(st *Status) { st.State = Stopped; st.RetryIn = 0 })
		s.mu.Lock()
		close(s.done)
		s.mu.Unlock()
	}()
	backoff := backoffMin
	busy := 0 // ErrPortBusy in a row
	for restarts := 0; ; restarts++ {
		s.setStatus(func(st *Status) {
			st.State, st.Kind, st.Message, st.Restarts, st.RetryIn = Connecting, ErrNone, "", restarts, 0
		})
		connectedFor, kind, msg := s.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if connectedFor >= stableAfter {
			backoff = backoffMin
		}
		delay := backoff
		if kind == ErrPortBusy {
			busy++
		} else {
			busy = 0
		}
		switch {
		case kind == ErrAuth || kind == ErrConfig:
			delay = backoffMax
		case kind == ErrPortBusy && busy <= busyRetries:
			// A local race, not the server's fault: retry at once and do
			// not grow the backoff.
			delay = 200 * time.Millisecond
			backoff /= 2
		case kind == ErrPortBusy:
			msg = "Hysteria не может открыть локальный порт SOCKS5, и это повторяется: возможно, его не даёт открыть защитная программа"
		}
		s.setStatus(func(st *Status) {
			st.State, st.Kind, st.Message, st.RetryIn = Failed, kind, msg, delay
		})
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

func (s *Supervisor) resolve(ctx context.Context) ([]netip.Addr, error) {
	if s.Profile.HostIsIP() {
		return []netip.Addr{netip.MustParseAddr(s.Profile.Host).Unmap()}, nil
	}
	res := s.Resolve
	if res == nil {
		res = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := res(rctx, s.Profile.Host)
	if err != nil {
		return nil, err
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	ips = slices.Compact(ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", s.Profile.Host)
	}
	return ips, nil
}

// pickPinned prefers IPv4: IPv6 connectivity is often absent. failed is
// the address of the last run that never connected: the one after it is
// taken (the other IPv4 addresses first, then IPv6, then around again), so
// one dead address of several does not keep the profile down.
func pickPinned(ips []netip.Addr, failed netip.Addr) netip.Addr {
	order := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() {
			order = append(order, ip)
		}
	}
	for _, ip := range ips {
		if !ip.Is4() {
			order = append(order, ip)
		}
	}
	if i := slices.Index(order, failed); i >= 0 {
		return order[(i+1)%len(order)]
	}
	return order[0]
}

// runOnce runs one Hysteria process until it exits. It returns how long it
// stayed connected and why it stopped.
func (s *Supervisor) runOnce(ctx context.Context) (time.Duration, ErrorKind, string) {
	ips, err := s.resolve(ctx)
	if err != nil {
		return 0, ErrTimeout, "Не удалось разрешить имя сервера " + s.Profile.Host + ": " + err.Error()
	}
	var pinned netip.Addr
	if s.Profile.PinServerIP && !s.Profile.HostIsIP() {
		pinned = pickPinned(ips, s.pinFailed)
	}
	if s.SetServerIPs != nil {
		if err := s.SetServerIPs(ips); err != nil {
			return 0, ErrOther, "Не удалось обновить исключение для сервера: " + err.Error()
		}
	}
	s.setStatus(func(st *Status) { st.ServerIPs, st.PinnedIP = ips, pinned })

	port, releasePort, err := reservePort()
	if err != nil {
		return 0, ErrOther, err.Error()
	}
	defer releasePort()
	user, pass := randomString(16), randomString(32)
	if s.Redactor != nil {
		s.Redactor.SetGroup(s.RedactGroup, s.Profile.Auth, s.Profile.Obfs.Password, user, pass)
	}
	opts := RunOptions{
		SOCKSListen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		SOCKSUsername: user,
		SOCKSPassword: pass,
	}
	if pinned.IsValid() {
		opts.ServerIP = pinned.String()
	}
	cfg, err := BuildConfig(&s.Profile, opts)
	if err != nil {
		return 0, ErrConfig, "Ошибка в профиле: " + err.Error()
	}
	kick := make(chan restart, 1)
	s.mu.Lock()
	// Every run gets a file of its own: supervisors of different profiles
	// share RunDir, and a shared name let one profile's Hysteria read
	// another profile's config (wrong server, clashing SOCKS5 port).
	cfgPath := filepath.Join(s.RunDir, configName())
	s.socks = socks5.Client{Server: opts.SOCKSListen, Username: user, Password: pass}
	s.kick = kick
	s.status.SOCKS = opts.SOCKSListen
	s.mu.Unlock()
	releaseCfg, err := writeSecretFile(cfgPath, cfg)
	if err != nil {
		return 0, ErrOther, "Не удалось записать конфиг Hysteria: " + err.Error()
	}
	// The config is read at startup only: it goes once Hysteria has
	// connected, or with the process.
	var dropOnce sync.Once
	dropConfig := func() {
		dropOnce.Do(func() {
			releaseCfg()
			os.Remove(cfgPath)
		})
	}
	defer dropConfig()

	pr, pw := io.Pipe()
	env := append(os.Environ(),
		"HYSTERIA_LOG_FORMAT=json",
		"HYSTERIA_LOG_LEVEL=info",
		"HYSTERIA_DISABLE_UPDATE_CHECK=1",
	)
	proc, err := startProcess(s.Exe, []string{"client", "-c", cfgPath}, env, pw)
	if err != nil {
		pw.Close()
		return 0, ErrOther, "Не удалось запустить " + s.Exe + ": " + err.Error()
	}

	var (
		connectedAt time.Time
		lastKind    = ErrOther
		lastMsg     = "Hysteria завершилась"
		lastUDP     bool
		evMu        sync.Mutex
		listening   atomic.Bool
		probes      sync.WaitGroup
	)
	runCtx, stopProbes := context.WithCancel(ctx)
	defer stopProbes()
	setConnected := func(udp bool) {
		if runCtx.Err() != nil {
			return
		}
		s.setStatus(func(st *Status) {
			st.State, st.Kind, st.Message, st.UDPEnabled = Connected, ErrNone, "", udp
			if !udp {
				st.Message = "Сервер запретил UDP: UDP-трафик с маршрутом Tunnel будет отклоняться"
			}
		})
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			// Parse and interpret the line as written, redact afterwards: a
			// secret that matches JSON syntax or the message ("true",
			// "connected") would otherwise break the line and hide events.
			l := ParseLogLine(sc.Text())
			ev, ok := Interpret(l)
			if s.Redactor != nil {
				l = redactLine(s.Redactor, l)
				ev.Message = s.Redactor.Redact(ev.Message)
			}
			if s.LogLine != nil {
				s.LogLine(l)
			}
			if !ok {
				continue
			}
			evMu.Lock()
			switch {
			case ev.Connected:
				first := connectedAt.IsZero()
				if first {
					connectedAt = time.Now()
					dropConfig()
				}
				lastUDP = ev.UDPEnabled
				evMu.Unlock()
				if !first {
					if listening.Load() {
						setConnected(ev.UDPEnabled)
					}
					continue
				}
				// Traffic goes to Hysteria only once its SOCKS5 port is open.
				probes.Add(1)
				go func() {
					defer probes.Done()
					if !waitListening(runCtx, opts.SOCKSListen, 15*time.Second) {
						if runCtx.Err() == nil {
							select {
							case kick <- restart{ErrPortBusy, "Hysteria подключилась, но не открыла локальный порт SOCKS5, перезапуск"}:
							default:
							}
						}
						return
					}
					listening.Store(true)
					evMu.Lock()
					udp := lastUDP
					evMu.Unlock()
					setConnected(udp)
				}()
				continue
			case ev.Fatal:
				lastKind, lastMsg = ev.Kind, ev.Message
			case ev.Lost:
				// The server went away after the first connection. Restart:
				// a failed first connection is fatal, so the profile turns
				// Failed (and rules move to their fallbacks) until the
				// server answers again.
				select {
				case kick <- restart{ev.Kind, ev.Message}:
				default:
				}
			}
			evMu.Unlock()
		}
		io.Copy(io.Discard, pr)
	}()

	exited := make(chan error, 1)
	go func() { exited <- proc.Wait(); pw.Close() }()

	var ticker <-chan time.Time
	if !s.Profile.HostIsIP() {
		every := s.ReResolveEvery
		if every == 0 {
			every = 5 * time.Minute
		}
		t := time.NewTicker(every)
		defer t.Stop()
		ticker = t.C
	}

	var waitErr error
	restartReason, restartKind := "", ErrOther
wait:
	for {
		select {
		case <-ctx.Done():
			proc.Kill()
			<-exited
			break wait
		case waitErr = <-exited:
			break wait
		case r := <-kick:
			restartReason, restartKind = r.msg, r.kind
			proc.Kill()
		case <-ticker:
			newIPs, err := s.resolve(ctx)
			if err != nil || slices.Equal(newIPs, ips) {
				continue
			}
			union := slices.Concat(newIPs, ips)
			slices.SortFunc(union, netip.Addr.Compare)
			union = slices.Compact(union)
			if !pinned.IsValid() {
				// Hysteria resolves the host itself, and HyRoute cannot
				// tell which address seen during this run it connected
				// to: the exclusion only grows until the process restarts.
				if len(union) > len(ips) {
					ips = union
					if s.SetServerIPs != nil {
						s.SetServerIPs(ips)
					}
					s.setStatus(func(st *Status) { st.ServerIPs = ips })
				}
				continue
			}
			// The pinned IP stays excluded while this process uses it. An
			// answer without it (a DNS pool that hands out a subset, short
			// TTLs) is no reason to cut every connection: a server that is
			// really gone Hysteria reports itself (Lost, then a restart),
			// and the next start pins an address of the new set.
			if s.SetServerIPs != nil {
				s.SetServerIPs(union)
			}
			ips = newIPs
			if !slices.Contains(ips, pinned) {
				ips = append(slices.Clone(ips), pinned)
				slices.SortFunc(ips, netip.Addr.Compare)
			}
		}
	}
	s.available.Store(false)
	stopProbes()
	probes.Wait()
	<-readDone

	evMu.Lock()
	defer evMu.Unlock()
	var connectedFor time.Duration
	if !connectedAt.IsZero() {
		connectedFor = time.Since(connectedAt)
	}
	kind, msg := lastKind, lastMsg
	if restartReason != "" {
		kind, msg = restartKind, restartReason
	} else if lastMsg == "Hysteria завершилась" && waitErr != nil {
		msg += ": " + waitErr.Error()
	}
	switch {
	case !pinned.IsValid() || ctx.Err() != nil:
	case !connectedAt.IsZero():
		s.pinFailed = netip.Addr{}
	case kind != ErrPortBusy && kind != ErrConfig:
		// Not a local problem or one of the profile: the address may be
		// the one that does not answer.
		s.pinFailed = pinned
	}
	return connectedFor, kind, msg
}

// redactLine hides secrets in a parsed log line: the raw text, the message
// and every string value of the fields.
func redactLine(r *logx.Redactor, l LogLine) LogLine {
	l.Raw, l.Msg = r.Redact(l.Raw), r.Redact(l.Msg)
	if l.Fields != nil {
		l.Fields = redactValue(r, l.Fields).(map[string]any)
	}
	return l
}

func redactValue(r *logx.Redactor, v any) any {
	switch v := v.(type) {
	case string:
		return r.Redact(v)
	case map[string]any:
		m := make(map[string]any, len(v))
		for k, x := range v {
			m[k] = redactValue(r, x)
		}
		return m
	case []any:
		s := make([]any, len(v))
		for i, x := range v {
			s[i] = redactValue(r, x)
		}
		return s
	}
	return v
}

// Ports handed to running Hysteria processes. Several profiles start at
// the same moment; asking the OS for a free port and closing it again can
// return the same port twice, so every port stays reserved until its
// Hysteria exits.
var (
	portMu   sync.Mutex
	reserved = map[int]bool{}
)

func reservePort() (int, func(), error) {
	portMu.Lock()
	defer portMu.Unlock()
	var held []net.Listener
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, nil, err
		}
		p := ln.Addr().(*net.TCPAddr).Port
		if reserved[p] {
			held = append(held, ln) // keep it open so the OS picks another
			continue
		}
		ln.Close()
		reserved[p] = true
		return p, func() {
			portMu.Lock()
			delete(reserved, p)
			portMu.Unlock()
		}, nil
	}
	return 0, nil, errors.New("no free loopback port")
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// process is the minimal view of a started child.
type process interface {
	Wait() error
	Kill() error
}

// configName is a unique name for one run's config file.
func configName() string {
	var b [12]byte
	rand.Read(b[:])
	return fmt.Sprintf("hy-%x.yaml", b)
}

// CleanRunDir removes the configs a run that ended mid-start left in dir
// (killed, crashed, the power gone while Hysteria connected): they hold
// the servers' passwords in clear text. Only files older than minAge go,
// and one a running Hysteria holds open cannot be removed.
func CleanRunDir(dir string, minAge time.Duration) {
	names, _ := filepath.Glob(filepath.Join(dir, "hy-*.yaml"))
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) >= minAge {
			os.Remove(n)
		}
	}
}
