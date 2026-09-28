package dnsproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// loopDialer dials addr (a loopback listener) whatever host it is asked
// for, and records the hosts.
func loopDialer(addr string, hosts *[]string) Dialer {
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if hosts != nil {
			*hosts = append(*hosts, net.JoinHostPort(host, strconv.Itoa(int(port))))
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func upAnswer(t testing.TB, body []byte) []byte {
	t.Helper()
	q, ok := ParseQuery(body)
	if !ok {
		t.Error("the server got no query")
		return nil
	}
	return answer(t, q, dnsmessage.RCodeSuccess, []rr{{q.Name + ".", dnsmessage.TypeA, 60, "1.2.3.4"}}, nil, 0, false)
}

func TestDoHClient(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1") // must be ignored
	var mode atomic.Value
	mode.Store("ok")
	var proto atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" ||
			r.Header.Get("Accept") != "application/dns-message" || r.Header.Get("User-Agent") != "" {
			t.Errorf("request %s %s %v", r.Method, r.URL, r.Header)
		}
		switch mode.Load().(string) {
		case "500":
			w.WriteHeader(500)
			return
		case "type":
			w.Header().Set("Content-Type", "text/html")
			w.Write(upAnswer(t, body))
			return
		case "redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		case "big":
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(make([]byte, 70000))
			return
		case "slow":
			time.Sleep(500 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(upAnswer(t, body))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	var hosts []string
	s := dnspolicy.Spec{Scheme: "https", Host: "example.com", Port: 443, Path: "/dns-query"}
	c := NewClient(s, loopDialer(ts.Listener.Addr().String(), &hosts), roots)
	defer c.Close()
	q := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 0, false))
	ctx := context.Background()
	b, err := c.Exchange(ctx, UpstreamQuery(q))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Reply(q, b, ReplyOpts{}); err != nil {
		t.Fatal(err)
	}
	if proto.Load() != 2 {
		t.Fatalf("HTTP/%d, want 2", proto.Load())
	}
	if len(hosts) == 0 || hosts[0] != "example.com:443" {
		t.Fatalf("dialled %v", hosts)
	}
	for _, m := range []string{"500", "type", "redirect"} {
		mode.Store(m)
		_, err := c.Exchange(ctx, UpstreamQuery(q))
		var he *httpError
		if !errors.As(err, &he) {
			t.Fatalf("%s: %v", m, err)
		}
		if kind, _, _ := errKind(ctx, err); kind != "http" {
			t.Fatalf("%s: kind %s", m, kind)
		}
	}
	mode.Store("big")
	if _, err := c.Exchange(ctx, UpstreamQuery(q)); !errors.Is(err, errAnswer) {
		t.Fatalf("big: %v", err)
	}
	mode.Store("slow")
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = c.Exchange(tctx, UpstreamQuery(q))
	cancel()
	if kind, _, counts := errKind(tctx, err); err == nil || kind != "timeout" || !counts {
		t.Fatalf("slow: %v %s", err, kind)
	}
	// The pooled connection dies (a restarted Hysteria): the next query
	// still gets its answer.
	mode.Store("ok")
	ts.CloseClientConnections()
	if _, err := c.Exchange(ctx, UpstreamQuery(q)); err != nil {
		t.Fatalf("after the connection closed: %v", err)
	}
	// A server whose certificate is not trusted: kind tls.
	bad := NewClient(s, loopDialer(ts.Listener.Addr().String(), nil), x509.NewCertPool())
	defer bad.Close()
	if _, err := bad.Exchange(ctx, UpstreamQuery(q)); err == nil {
		t.Fatal("untrusted certificate accepted")
	} else if kind, _, _ := errKind(ctx, err); kind != "tls" {
		t.Fatalf("untrusted: %v kind %s", err, kind)
	}
	// Bootstrap addresses are dialled instead of the host.
	hosts = nil
	s.Bootstrap = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	bs := NewClient(s, loopDialer(ts.Listener.Addr().String(), &hosts), roots)
	defer bs.Close()
	if _, err := bs.Exchange(ctx, UpstreamQuery(q)); err != nil || len(hosts) == 0 || hosts[0] != "192.0.2.1:443" {
		t.Fatalf("bootstrap: %v %v", err, hosts)
	}
}

// selfSigned makes a certificate for host and its pool.
func selfSigned(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// streamServer answers framed queries on ln. closeAfter > 0 closes a
// connection after that many answers; silent never answers.
func streamServer(t *testing.T, ln net.Listener, closeAfter int, silent *atomic.Bool, conns *atomic.Int32) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				for n := 0; closeAfter == 0 || n < closeAfter; n++ {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					body := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					if silent != nil && silent.Load() {
						time.Sleep(time.Second)
						return
					}
					a := upAnswer(t, body)
					out := binary.BigEndian.AppendUint16(nil, uint16(len(a)))
					c.Write(append(out, a...))
				}
			}()
		}
	}()
}

func testStream(t *testing.T, scheme string) {
	var ln net.Listener
	var roots *x509.CertPool
	var err error
	if scheme == "tls" {
		var cert tls.Certificate
		cert, roots = selfSigned(t, "dot.example")
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns atomic.Int32
	var silent atomic.Bool
	streamServer(t, ln, 2, &silent, &conns)
	c := NewClient(dnspolicy.Spec{Scheme: scheme, Host: "dot.example", Port: 853}, loopDialer(ln.Addr().String(), nil), roots)
	defer c.Close()
	q := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 0, false))
	ctx := context.Background()
	for i := range 5 {
		b, err := c.Exchange(ctx, UpstreamQuery(q))
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if _, _, err := Reply(q, b, ReplyOpts{}); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	// Two answers per connection: reused, then reconnected.
	if n := conns.Load(); n < 3 || n > 4 {
		t.Fatalf("%d connections for 5 queries", n)
	}
	silent.Store(true)
	tctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Exchange(tctx, UpstreamQuery(q)); err == nil || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("deadline: %v after %v", err, time.Since(start))
	}
}

func TestDoTClient(t *testing.T) { testStream(t, "tls") }
func TestTCPClient(t *testing.T) { testStream(t, "tcp") }

func TestRetryable(t *testing.T) {
	ctx := context.Background()
	if retryable(ctx, &httpError{500}) || retryable(ctx, errAnswer) || retryable(ctx, ErrTunnelDown) {
		t.Fatal("not a connection failure")
	}
	if !retryable(ctx, io.EOF) || !retryable(ctx, &net.OpError{Op: "read", Err: errors.New("reset")}) {
		t.Fatal("a broken connection is retried")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if retryable(cctx, io.EOF) {
		t.Fatal("retried after the caller gave up")
	}
}
