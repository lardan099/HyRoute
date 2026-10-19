package alerts

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const fakeSMTPPass = "fake-smtp-password-0451"

// letter is a mail the fake server took.
type letter struct {
	auth     string // user\x00password of AUTH PLAIN
	tls      bool   // the mail came over TLS
	from, to string
	data     string
}

// fakeSMTP is a mail server on 127.0.0.1: mode is none, starttls or tls.
func fakeSMTP(t *testing.T, mode string) (port int, pool *x509.CertPool, got chan letter) {
	t.Helper()
	cert, pool := testCert(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	var ln net.Listener
	var err error
	if mode == SecurityTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan letter, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSMTP(c, mode, cfg, got)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pool, got
}

func serveSMTP(c net.Conn, mode string, cfg *tls.Config, got chan letter) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	secure := mode == SecurityTLS
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
	var l letter
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch cmd {
		case "EHLO", "HELO":
			w.WriteString("250-fake\r\n")
			if mode == SecurityStartTLS && !secure {
				w.WriteString("250-STARTTLS\r\n")
			}
			say("250 AUTH PLAIN")
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, cfg)
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(tc), bufio.NewWriter(tc)
		case "AUTH":
			parts := strings.Fields(line)
			b, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			l.auth = strings.TrimPrefix(string(b), "\x00")
			say("235 ok")
		case "MAIL":
			l.from = line
			say("250 ok")
		case "RCPT":
			l.to += line + "\n"
			say("250 ok")
		case "DATA":
			say("354 go on")
			var data strings.Builder
			for {
				d, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if d == ".\r\n" {
					break
				}
				data.WriteString(d)
			}
			l.data, l.tls = data.String(), secure
			say("250 queued")
			got <- l
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 what")
		}
	}
}

// testCert is a certificate for 127.0.0.1 and the pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake smtp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// Mail goes over STARTTLS, TLS or, to this machine, without TLS, with
// the password only to the server; the letter has the event's text and
// neither secrets nor addresses.
func TestSMTP(t *testing.T) {
	for _, mode := range []string{SecurityNone, SecurityStartTLS, SecurityTLS} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			port, pool, got := fakeSMTP(t, mode)
			e.n.TLS = &tls.Config{RootCAs: pool}
			settings, _ := json.Marshal(SMTPSettings{Host: "127.0.0.1", Port: port, Security: mode, Username: "bot@example.com", From: "HyRoute <bot@example.com>", To: []string{"admin@example.com", "ops@example.com"}})
			c := e.channel(model.AlertChannel{Name: "Почта", Kind: model.ChannelSMTP, Settings: settings}, fakeSMTPPass)
			e.start()
			if err := e.n.Test(context.Background(), c.ID); err != nil {
				t.Fatal(err)
			}
			<-got
			e.raise("server:1", model.EventServer)
			var l letter
			select {
			case l = <-got:
			case <-time.After(5 * time.Second):
				t.Fatal("no mail")
			}
			if l.auth != "bot@example.com\x00"+fakeSMTPPass || l.tls != (mode != SecurityNone) || !strings.Contains(l.from, "<bot@example.com>") ||
				!strings.Contains(l.to, "<admin@example.com>") || !strings.Contains(l.to, "<ops@example.com>") {
				t.Fatalf("letter %+v", l)
			}
			msg, err := mail.ReadMessage(strings.NewReader(l.data))
			if err != nil {
				t.Fatal(err)
			}
			subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, msg.Body))
			if !strings.Contains(subject, "Сервер «Alpha» недоступен") || !strings.Contains(string(body), "Сервер «Alpha» недоступен") {
				t.Fatalf("subject %q, body %q", subject, body)
			}
			for _, bad := range []string{canaryHost, canaryPass, fakeSMTPPass} {
				if strings.Contains(l.data, bad) || strings.Contains(string(body), bad) || strings.Contains(subject, bad) {
					t.Fatalf("%q in the mail", bad)
				}
			}
		})
	}
}

// STARTTLS that the server does not offer is an error, not plain text.
func TestSMTPNoStartTLS(t *testing.T) {
	e := newEnv(t)
	port, _, _ := fakeSMTP(t, SecurityNone)
	settings, _ := json.Marshal(SMTPSettings{Host: "127.0.0.1", Port: port, Security: SecurityStartTLS, Username: "bot", From: "bot@example.com", To: []string{"a@example.com"}})
	c := e.channel(model.AlertChannel{Name: "Почта", Kind: model.ChannelSMTP, Settings: settings}, fakeSMTPPass)
	err := e.n.Test(context.Background(), c.ID)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") || strings.Contains(err.Error(), fakeSMTPPass) {
		t.Fatalf("%v", err)
	}
}
