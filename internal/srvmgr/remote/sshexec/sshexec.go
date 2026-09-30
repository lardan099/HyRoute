// Package sshexec is the SSH transport of remote.Executor: golang.org/x/crypto/ssh
// for commands and github.com/pkg/sftp for files.
//
// The host key is checked by the caller's HostKey function before any
// credential is sent: an unknown or changed key aborts the handshake, so a
// man in the middle never sees the password.
package sshexec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Target is where to connect.
type Target struct {
	Host string
	Port int
	User string
}

// Auth is how to log in; Key (with Passphrase) is tried before Password.
type Auth struct {
	Password   string
	Key        []byte
	Passphrase string
}

// Options tune a connection.
type Options struct {
	// HostKey decides whether the presented host key is trusted; it must
	// return an error for unknown or changed keys.
	HostKey func(key ssh.PublicKey) error
	// Timeout bounds the TCP connect and the handshake (default 15 s).
	Timeout time.Duration
	// Keepalive is the interval of keepalive requests (default 30 s).
	Keepalive time.Duration
}

// maxOutput bounds what Run keeps of stdout and stderr, and ReadFile.
const maxOutput = 32 << 20

// Client is a connected remote.Executor.
type Client struct {
	ssh    *ssh.Client
	done   chan struct{}
	mu     sync.Mutex
	sftp   *sftp.Client
	closed bool
}

var _ remote.Executor = (*Client)(nil)

// Dial connects and authenticates.
func Dial(ctx context.Context, t Target, a Auth, o Options) (*Client, error) {
	if o.HostKey == nil {
		return nil, errors.New("sshexec: no host key check")
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.Keepalive == 0 {
		o.Keepalive = 30 * time.Second
	}
	var methods []ssh.AuthMethod
	if len(a.Key) > 0 {
		var signer ssh.Signer
		var err error
		if a.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(a.Key, []byte(a.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(a.Key)
		}
		if err != nil {
			return nil, fmt.Errorf("ssh key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		pw := a.Password
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(methods) == 0 {
		return nil, errors.New("sshexec: no credentials")
	}
	cfg := &ssh.ClientConfig{
		User: t.User,
		Auth: methods,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			return o.HostKey(key)
		},
		Timeout:       o.Timeout,
		ClientVersion: "SSH-2.0-HyRouteServer",
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	dctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, &remote.UnreachableError{Err: err}
	}
	conn.SetDeadline(time.Now().Add(o.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, classify(err)
	}
	conn.SetDeadline(time.Time{})
	cl := &Client{ssh: ssh.NewClient(c, chans, reqs), done: make(chan struct{})}
	go cl.keepalive(o.Keepalive)
	return cl, nil
}

// errKeySeen aborts FetchHostKey's handshake once the key is known.
var errKeySeen = errors.New("host key seen")

// FetchHostKey connects only far enough to see the server's host key: the
// handshake is aborted at the key check, so no credentials exist or are
// sent. Used to confirm a fingerprint before trusting it.
func FetchHostKey(ctx context.Context, t Target, timeout time.Duration) (ssh.PublicKey, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: t.User,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errKeySeen
		},
		Timeout:       timeout,
		ClientVersion: "SSH-2.0-HyRouteServer",
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, &remote.UnreachableError{Err: err}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if seen != nil {
		return seen, nil
	}
	if err == nil {
		err = errors.New("no host key presented")
	}
	return nil, classify(err)
}

// classify turns handshake errors into the remote package's errors.
func classify(err error) error {
	var unknown *remote.HostKeyUnknownError
	var changed *remote.HostKeyChangedError
	switch {
	case errors.As(err, &unknown), errors.As(err, &changed):
		return err
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%w: %v", remote.ErrAuthFailed, err)
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, io.EOF) {
		return &remote.UnreachableError{Err: err}
	}
	return fmt.Errorf("ssh handshake: %w", err)
}

func (c *Client) keepalive(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if _, _, err := c.ssh.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				c.ssh.Close()
				return
			}
		}
	}
}

// Close ends the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	if c.sftp != nil {
		c.sftp.Close()
	}
	return c.ssh.Close()
}

// limitedBuffer keeps the first max bytes.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// start opens a session and starts cmd; stop is closed-over cleanup that
// kills the program when ctx ends first.
func (c *Client) start(ctx context.Context, cmd remote.Cmd, stdout, stderr io.Writer) (*ssh.Session, func(), error) {
	line, err := remote.CommandLine(cmd)
	if err != nil {
		return nil, nil, err
	}
	s, err := c.ssh.NewSession()
	if err != nil {
		return nil, nil, &remote.UnreachableError{Err: err}
	}
	if cmd.Stdin != nil {
		s.Stdin = bytes.NewReader(cmd.Stdin)
	}
	s.Stdout, s.Stderr = stdout, stderr
	if err := s.Start(line); err != nil {
		s.Close()
		return nil, nil, err
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.Signal(ssh.SIGKILL)
			s.Close()
		case <-stop:
		}
	}()
	return s, func() { close(stop); s.Close() }, nil
}

func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus(), nil
	}
	return -1, err
}

// Run implements remote.Executor.
func (c *Client) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	out := &limitedBuffer{max: maxOutput}
	errb := &limitedBuffer{max: 1 << 20}
	s, done, err := c.start(ctx, cmd, out, errb)
	if err != nil {
		return remote.Result{}, err
	}
	defer done()
	werr := s.Wait()
	if ctx.Err() != nil {
		return remote.Result{}, ctx.Err()
	}
	code, err := exitCode(werr)
	if err != nil {
		return remote.Result{}, err
	}
	return remote.Result{Stdout: out.Bytes(), Stderr: errb.Bytes(), ExitCode: code}, nil
}

// Stream implements remote.Executor.
func (c *Client) Stream(ctx context.Context, cmd remote.Cmd, line func(string)) error {
	pr, pw := io.Pipe()
	errb := &limitedBuffer{max: 64 << 10}
	s, done, err := c.start(ctx, cmd, pw, errb)
	if err != nil {
		return err
	}
	defer done()
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line(sc.Text())
		}
		io.Copy(io.Discard, pr)
	}()
	werr := s.Wait()
	pw.Close()
	<-scanned
	if ctx.Err() != nil {
		return nil
	}
	code, err := exitCode(werr)
	if err != nil {
		return err
	}
	if code != 0 {
		return &remote.ExitError{Op: cmd.Args[0], Code: code, Stderr: strings.TrimSpace(errb.String())}
	}
	return nil
}

func (c *Client) sftpClient() (*sftp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sftp == nil {
		s, err := sftp.NewClient(c.ssh)
		if err != nil {
			return nil, fmt.Errorf("sftp: %w", err)
		}
		c.sftp = s
	}
	return c.sftp, nil
}

// ReadFile implements remote.Executor: SFTP as the SSH user, cat through
// sudo as root.
func (c *Client) ReadFile(ctx context.Context, p string, sudo bool) ([]byte, error) {
	if err := remote.CheckPath(p); err != nil {
		return nil, err
	}
	if sudo {
		res, err := c.Run(ctx, remote.Cmd{Args: []string{"cat", "--", p}, Sudo: true})
		if err != nil {
			return nil, err
		}
		if !res.OK() {
			if strings.Contains(string(res.Stderr), "No such file") {
				return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist) // as SFTP says it
			}
			return nil, &remote.ExitError{Op: "read " + p, Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
		}
		return res.Stdout, nil
	}
	sc, err := c.sftpClient()
	if err != nil {
		return nil, err
	}
	f, err := sc.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxOutput))
}

// WriteFile implements remote.Executor. The data goes by SFTP into a
// private temporary directory (mktemp -d, 0700), then install(1) copies it
// next to the target with mode and owner, and mv(1) renames it over the
// target: readers see the old file or the new one, never half of it.
func (c *Client) WriteFile(ctx context.Context, p string, data []byte, f remote.FileSpec) error {
	if err := remote.CheckPath(p); err != nil {
		return err
	}
	dir, err := c.output(ctx, "mktemp", remote.Cmd{Args: []string{"mktemp", "-d"}})
	if err != nil {
		return err
	}
	if remote.CheckPath(dir) != nil {
		return fmt.Errorf("mktemp returned %q", dir)
	}
	defer c.Run(context.WithoutCancel(ctx), remote.Cmd{Args: []string{"rm", "-rf", "--", dir}})

	sc, err := c.sftpClient()
	if err != nil {
		return err
	}
	tmp := path.Join(dir, "upload")
	w, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("sftp create: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return fmt.Errorf("sftp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("sftp close: %w", err)
	}

	staged := path.Join(path.Dir(p), "."+path.Base(p)+".hyroute-new")
	args := []string{"install", "-m", fmt.Sprintf("%04o", f.Mode.Perm())}
	if f.Owner != "" {
		args = append(args, "-o", f.Owner)
	}
	if f.Group != "" {
		args = append(args, "-g", f.Group)
	}
	args = append(args, "--", tmp, staged)
	if _, err := c.output(ctx, "install", remote.Cmd{Args: args, Sudo: f.Sudo}); err != nil {
		return err
	}
	if _, err := c.output(ctx, "mv", remote.Cmd{Args: []string{"mv", "-f", "--", staged, p}, Sudo: f.Sudo}); err != nil {
		c.Run(context.WithoutCancel(ctx), remote.Cmd{Args: []string{"rm", "-f", "--", staged}, Sudo: f.Sudo})
		return err
	}
	return nil
}

func (c *Client) output(ctx context.Context, op string, cmd remote.Cmd) (string, error) {
	res, err := c.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", &remote.ExitError{Op: op, Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}
