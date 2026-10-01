// Package sshtest is an in-process SSH server for tests of the remote
// layer: password and public key auth, exec requests handled by a function
// (by default the local /bin/sh, with "sudo -n --" stripped as if the user
// were root), the SFTP subsystem on the local filesystem (or on fixed
// files, SetFiles), and a host key
// that can be swapped to simulate a reinstalled server.
package sshtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ExecFunc runs one exec request and returns its exit code; ctx ends when
// the client sends a signal or closes the channel.
type ExecFunc func(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) int

// Server is a running test SSH server.
type Server struct {
	Host string
	Port int
	User string
	// Password and AuthorizedKey are the accepted credentials.
	Password      string
	AuthorizedKey ssh.PublicKey

	// AuthAttempts counts password and public key attempts: a client that
	// rejects the host key must not reach authentication at all.
	AuthAttempts atomic.Int32

	mu      sync.Mutex
	hostKey ssh.Signer
	exec    ExecFunc
	files   memFS
	lines   []string
	ln      net.Listener
	wg      sync.WaitGroup
}

// NewSigner makes a fresh ed25519 host or user key.
func NewSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// NewUserKey makes a client key pair: the signer to authorize on the
// server and the private key in OpenSSH PEM form, as an admin would paste.
func NewUserKey(t testing.TB) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, pem.EncodeToMemory(blk)
}

// Start listens on 127.0.0.1 and serves until the test ends.
func Start(t testing.TB, user, password string) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: user, Password: password, hostKey: NewSigner(t), exec: ShellExec, ln: ln}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// HostKey is the current host key.
func (s *Server) HostKey() ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostKey.PublicKey()
}

// SetHostKey replaces the host key (a reinstalled server or an attacker).
func (s *Server) SetHostKey(k ssh.Signer) {
	s.mu.Lock()
	s.hostKey = k
	s.mu.Unlock()
}

// SetExec replaces the exec handler.
func (s *Server) SetExec(f ExecFunc) {
	s.mu.Lock()
	s.exec = f
	s.mu.Unlock()
}

// SetFiles makes the SFTP subsystem serve only these files, read-only, from
// memory (path → content) instead of the local filesystem. Tests of code
// that reads /proc or /etc of the server use it: the local filesystem is
// the one of the test machine, which on Windows has no /proc at all.
func (s *Server) SetFiles(files map[string]string) {
	s.mu.Lock()
	s.files = memFS(files)
	s.mu.Unlock()
}

// Lines returns the command lines received so far.
func (s *Server) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// Close stops the server.
func (s *Server) Close() {
	s.ln.Close()
	s.wg.Wait()
}

// ShellExec runs the line with the local /bin/sh; "sudo -n -- " is
// stripped (the test user acts as root).
func ShellExec(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) int {
	line = strings.TrimPrefix(line, "sudo -n -- ")
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", line)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	// A killed shell may leave its child holding the output pipes.
	cmd.WaitDelay = 200 * time.Millisecond
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		io.WriteString(stderr, err.Error())
		return 127
	}
	return 0
}

func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.AuthAttempts.Add(1)
			if c.User() == s.User && s.Password != "" && string(pw) == s.Password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			s.AuthAttempts.Add(1)
			if c.User() == s.User && s.AuthorizedKey != nil && string(k.Marshal()) == string(s.AuthorizedKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	s.mu.Lock()
	cfg.AddHostKey(s.hostKey)
	s.mu.Unlock()
	return cfg
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	conn, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.session(ch, creqs)
		}()
	}
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for req := range reqs {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				return
			}
			n := binary.BigEndian.Uint32(req.Payload)
			line := string(req.Payload[4 : 4+n])
			req.Reply(true, nil)
			s.mu.Lock()
			s.lines = append(s.lines, line)
			f := s.exec
			s.mu.Unlock()
			// Signals and the channel closing arrive as more requests:
			// keep reading them while the command runs.
			go func() {
				for r := range reqs {
					if r.Type == "signal" {
						cancel()
					}
					if r.WantReply {
						r.Reply(false, nil)
					}
				}
				cancel()
			}()
			code := f(ctx, line, ch, ch, ch.Stderr())
			ch.CloseWrite()
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, uint32(code))
			ch.SendRequest("exit-status", false, status)
			return
		case "subsystem":
			if len(req.Payload) < 4 || string(req.Payload[4:]) != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.mu.Lock()
			files := s.files
			s.mu.Unlock()
			if files != nil {
				sftp.NewRequestServer(ch, files.handlers()).Serve()
				return
			}
			srv, err := sftp.NewServer(ch)
			if err != nil {
				return
			}
			srv.Serve()
			return
		default:
			req.Reply(false, nil)
		}
	}
}
