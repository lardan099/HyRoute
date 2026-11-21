package hysteria

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// A VLESS profile runs in xray.exe (internal/vless writes its config). The
// supervisor runs it like Hysteria, but Xray reports no connection to the
// server: it connects per request. So a run is up once its SOCKS5 port
// answers and an HTTP request goes through the server (watchVLESS), and
// is restarted when such requests stop going through.

// DefaultProbeURLs answer any request with 204 and no body.
var DefaultProbeURLs = []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"}

// Test hooks. One check of a new run, every probe URL at once, takes at
// most vlessProbeTimeout: the 3 of a start fit in the 45 s «Проверить»
// waits (app.CheckProfile), which then shows this run's own reason.
var (
	vlessProbeTimeout = 8 * time.Second
	vlessProbeEvery   = time.Minute
	vlessRetryEvery   = 3 * time.Second
	vlessDirectWait   = 3 * time.Second // directCheck's dial
)

const (
	// vlessFirstTries: probes before a new run counts as failed (the first
	// connection to a server may be slow); vlessLostAfter: failed probes
	// in a row that end a run that was up.
	vlessFirstTries = 3
	vlessLostAfter  = 2
)

// coreName names the program this profile runs in.
func (s *Supervisor) coreName() string {
	if s.Profile.IsVLESS() {
		return "Xray"
	}
	return "Hysteria"
}

// watchVLESS waits for Xray's SOCKS5 port, calls up after the first
// request that went through the server, and keeps checking every
// vlessProbeEvery. A run that never gets a request through, or stops
// getting them through, is restarted with the reason (Xray's last warning
// says it best).
//
// server is the address Xray dials (the pinned IP or the host, with the
// port): a failed check also tries it directly, to tell a server that
// does not answer from one that answers but lets nothing through.
func (s *Supervisor) watchVLESS(ctx context.Context, addr, server string, kick chan restart, lastWarn *atomic.Pointer[string], up func()) {
	send := func(r restart) {
		if ctx.Err() == nil {
			select {
			case kick <- r:
			default:
			}
		}
	}
	if !waitListening(ctx, addr, 15*time.Second) {
		send(restart{ErrPortBusy, "Xray не открыла локальный порт SOCKS5, перезапуск"})
		return
	}
	c := s.SOCKS()
	connected, fails := false, 0
	var seen int64 // s.Received at the last check
	for {
		var err error
		if got := s.received(); connected && fails == 0 && got > seen {
			// Answers came back through the server since the last check:
			// it works, and a check of its own would only cost traffic.
			seen = got
		} else {
			err = s.probeVLESS(ctx, c)
			seen = s.received()
		}
		if ctx.Err() != nil {
			return
		}
		wait := vlessRetryEvery
		if err == nil {
			fails = 0
			if !connected {
				connected = true
				up()
			}
			wait = vlessProbeEvery
		} else {
			fails++
			warn := ""
			if w := lastWarn.Load(); w != nil {
				warn = *w
			}
			kind, msg := ClassifyXray(err, warn)
			if server != "" {
				kind, msg = directCheck(ctx, server, kind, msg)
			}
			if !connected && fails < vlessFirstTries {
				// Still starting: the reason shows at once, not only
				// after the last try.
				s.setStatusWhile(func() bool { return ctx.Err() == nil }, func(st *Status) {
					if st.State == Connecting {
						st.Message = fmt.Sprintf("%s (попытка %d из %d)", msg, fails, vlessFirstTries)
					}
				})
			}
			if !connected && fails >= vlessFirstTries || connected && fails >= vlessLostAfter {
				if connected {
					// It worked with these settings: no reason for the
					// long wait of a refused password.
					msg = "Потеряна связь с сервером: " + msg
					if kind == ErrAuth {
						kind = ErrOther
					}
				}
				send(restart{kind, msg})
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Supervisor) received() int64 {
	if s.Received == nil {
		return 0
	}
	return s.Received()
}

// probeVLESS sends an HTTP request through the tunnel to the first probe
// URL and, only when that fails, to the others at once; one answer is
// enough. Each request is a new connection to the server (its handshake
// is most of the traffic), so the others are not asked while the first
// answers.
func (s *Supervisor) probeVLESS(ctx context.Context, c socks5.Client) error {
	urls := s.ProbeURLs
	if len(urls) == 0 {
		urls = DefaultProbeURLs
	}
	first := probeHTTP(ctx, c, urls[0])
	if first == nil || len(urls) == 1 || ctx.Err() != nil {
		return first
	}
	urls = urls[1:]
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(urls))
	for _, u := range urls {
		go func() { errs <- probeHTTP(pctx, c, u) }()
	}
	for range urls {
		if err := <-errs; err == nil {
			return nil
		}
	}
	return first
}

// directCheck refines the reason of a failed check by connecting to the
// server itself, outside the tunnel (HyRoute's own traffic is never
// routed): a server whose port answers is up, and what fails is VLESS
// (the ID, REALITY, flow) or the server's way out.
func directCheck(ctx context.Context, server string, kind ErrorKind, msg string) (ErrorKind, string) {
	if server == "" {
		return kind, msg
	}
	dctx, cancel := context.WithTimeout(ctx, vlessDirectWait)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", server)
	if err != nil {
		if ctx.Err() != nil {
			return kind, msg
		}
		return ErrTimeout, "Порт сервера не отвечает (" + shortNetErr(err) + "): сервер выключен, порт другой или его блокирует сеть"
	}
	conn.Close()
	ms := time.Since(start).Milliseconds()
	if kind == ErrTimeout {
		// The port answers: not the server's absence. What Xray said is
		// the reason, the port's answer the hint.
		return ErrOther, fmt.Sprintf("Порт сервера отвечает (TCP за %d мс), но запросы через VLESS не проходят: %s", ms, msg)
	}
	return kind, fmt.Sprintf("%s (порт сервера отвечает, TCP за %d мс)", msg, ms)
}

// shortNetErr is the last part of a dial error ("i/o timeout",
// "connection refused"), without the addresses.
func shortNetErr(err error) string {
	e := err.Error()
	if i := strings.LastIndex(e, ": "); i >= 0 {
		e = e[i+2:]
	}
	return e
}

// errNoHTTP: the tunnel took the connection, but no HTTP answer came back
// through it.
var errNoHTTP = errors.New("no HTTP answer through the tunnel")

// probeHTTP is one plain HTTP GET through SOCKS5 c. Any HTTP status line
// counts: it came from the far side of the server.
func probeHTTP(ctx context.Context, c socks5.Client, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return fmt.Errorf("probe URL %q", rawURL)
	}
	port := 80
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return fmt.Errorf("probe URL %q", rawURL)
		}
	}
	dst := socks5.Addr{Host: u.Hostname(), Port: uint16(port)}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		dst = socks5.Addr{IP: ip, Port: uint16(port)}
	}
	pctx, cancel := context.WithTimeout(ctx, vlessProbeTimeout)
	defer cancel()
	conn, err := c.Connect(pctx, dst)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(pctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	path := u.RequestURI()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HyRoute\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/") {
		if err == nil {
			return errNoHTTP
		}
		return fmt.Errorf("%w: %v", errNoHTTP, err)
	}
	return nil
}

// ClassifyXray explains a failed probe: by Xray's last warning when it
// has one, else by the probe's error.
func ClassifyXray(probeErr error, lastWarn string) (ErrorKind, string) {
	text := lastWarn
	if text == "" && probeErr != nil {
		text = probeErr.Error()
	}
	e := strings.ToLower(text)
	switch {
	case strings.Contains(e, "x509") || strings.Contains(e, "certificate") || strings.Contains(e, "pinned"):
		return ErrTLS, "Сертификат сервера не прошёл проверку: проверьте sni или закрепите сертификат (pinSHA256)"
	case strings.Contains(e, "reality"):
		return ErrAuth, "REALITY не прошёл: проверьте публичный ключ (pbk), shortId и sni"
	case strings.Contains(e, "refused"):
		return ErrTimeout, "Сервер отклонил подключение: на этом адресе и порту ничего не слушает"
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline") || strings.Contains(e, "timed out"):
		return ErrTimeout, "Сервер не отвечает: проверьте адрес и порт"
	case strings.Contains(e, "no such host") || strings.Contains(e, "lookup "):
		return ErrTimeout, "Не удалось разрешить имя сервера"
	case errors.Is(probeErr, errNoHTTP) || strings.Contains(e, "eof") || strings.Contains(e, "reset") || strings.Contains(e, "closed"):
		// A wrong ID looks the same to the client as a server that drops
		// connections: no auth error, no long wait.
		return ErrOther, "Сервер не пропускает трафик: проверьте UUID, flow, encryption и параметры транспорта"
	}
	return ErrOther, "Запрос через сервер не прошёл: " + text
}

// ParseXrayLine reads one line of Xray's output:
//
//	2026/11/05 10:51:23.123456 [Warning] core: Xray 26.10.31 started
//
// Lines without a level (the banner, "Failed to start: …") come back with
// Level "raw".
func ParseXrayLine(line string) LogLine {
	l := LogLine{Raw: line, Level: "raw", Msg: line}
	rest := line
	if i := strings.Index(rest, " ["); i >= 19 && i <= 26 && rest[4] == '/' {
		for _, layout := range []string{"2006/01/02 15:04:05.000000", "2006/01/02 15:04:05"} {
			if t, err := time.ParseInLocation(layout, rest[:i], time.Local); err == nil {
				l.Time = t
				break
			}
		}
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if j := strings.Index(rest, "] "); j > 1 {
			switch lvl := strings.ToLower(rest[1:j]); lvl {
			case "warning":
				l.Level = "warn"
			case "error", "info", "debug":
				l.Level = lvl
			default:
				return l
			}
			l.Msg = rest[j+2:]
		}
	}
	return l
}

// InterpretXray reports a line that ends the run: Xray could not start
// (its config, a busy port).
func InterpretXray(l LogLine) (Event, bool) {
	text, ok := strings.CutPrefix(l.Raw, "Failed to start:")
	if !ok || l.Level != "raw" {
		return Event{}, false
	}
	text = strings.TrimSpace(text)
	kind, msg := Classify(text)
	if kind != ErrPortBusy {
		kind, msg = ErrConfig, "Xray не запустилась: "+text
	}
	return Event{Fatal: true, Kind: kind, Message: msg}, true
}
