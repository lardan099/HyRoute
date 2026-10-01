package sshexec

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// authServer is an SSH server on 127.0.0.1 that only authenticates and
// counts failed logins per method, as sshd logs them for fail2ban.
type authServer struct {
	port           int
	key            ssh.PublicKey
	passwordFails  atomic.Int32
	keyboardFails  atomic.Int32
	keyboardLogins atomic.Int32
}

func startAuthServer(t *testing.T, password, keyboard bool) *authServer {
	t.Helper()
	signer := sshtest.NewSigner(t)
	s := &authServer{key: signer.PublicKey()}
	cfg := &ssh.ServerConfig{}
	if password {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == fakePass {
				return nil, nil
			}
			s.passwordFails.Add(1)
			return nil, errors.New("denied")
		}
	}
	if keyboard {
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ask("", "", []string{"Password: "}, []bool{false})
			if err == nil && len(ans) == 1 && ans[0] == fakePass {
				s.keyboardLogins.Add(1)
				return nil, nil
			}
			s.keyboardFails.Add(1)
			return nil, errors.New("denied")
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					nc.Reject(ssh.Prohibited, "auth only")
				}
			}()
		}
	}()
	return s
}

func (s *authServer) dial(pw string) (*Client, error) {
	return Dial(context.Background(), Target{Host: "127.0.0.1", Port: s.port, User: "root"}, Auth{Password: pw},
		Options{HostKey: trust(s.key), Timeout: 5 * time.Second})
}

// A refused password is one failure in the server's log, not two: the
// same password is not offered again by keyboard-interactive.
func TestWrongPasswordFailsOnce(t *testing.T) {
	s := startAuthServer(t, true, true)
	if _, err := s.dial("wrong"); !errors.Is(err, remote.ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if p, k := s.passwordFails.Load(), s.keyboardFails.Load(); p != 1 || k != 0 {
		t.Fatalf("failures: password %d, keyboard-interactive %d", p, k)
	}
	c, err := s.dial(fakePass)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// A server without the password method gets the password by
// keyboard-interactive.
func TestKeyboardInteractiveOnly(t *testing.T) {
	s := startAuthServer(t, false, true)
	c, err := s.dial(fakePass)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s.keyboardLogins.Load() != 1 {
		t.Fatal("no keyboard-interactive login")
	}
	if _, err := s.dial("wrong"); !errors.Is(err, remote.ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if k := s.keyboardFails.Load(); k != 1 {
		t.Fatalf("keyboard-interactive failures: %d", k)
	}
}
