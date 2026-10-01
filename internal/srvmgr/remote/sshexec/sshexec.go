// Package sshexec is the SSH transport of remote.Executor: golang.org/x/crypto/ssh
// for commands and github.com/pkg/sftp for files.
//
// The host key is checked by the caller's HostKey function before any
// credential is sent: an unknown or changed key aborts the handshake, so a
// man in the middle never sees the password.
//
// A server can vanish mid-session (a dropped route, a frozen VPS): nothing
// answers, and TCP gives up only after many minutes. Keepalives with a
// deadline find such a connection and close it, and a cancelled operation
// that the server does not wind down within cancelGrace closes the whole
// connection, so everything waiting on it returns.
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Keepalive is the interval of keepalive requests (default 30 s). A
	// request still unanswered at the next tick is a miss; keepaliveMisses
	// misses in a row close the connection as dead.
	Keepalive time.Duration
}

// keepaliveMisses unanswered keepalive intervals in a row mean the server
// is gone (as OpenSSH's ServerAliveCountMax).
const keepaliveMisses = 3

// cancelGrace is how long a cancelled operation may take to wind down: the
// server confirms the closed channel in a round trip. Past it the whole
// connection is closed, as on a dead link nothing else ends the wait (a
// variable for tests).
var cancelGrace = 3 * time.Second

// maxOutput bounds what Run keeps of stdout and stderr.
const maxOutput = 32 << 20

// maxFile bounds ReadFile: a larger file is an error, not a truncated
// read (a variable for tests).
var maxFile = maxOutput

// Client is a connected remote.Executor.
type Client struct {
	ssh  *ssh.Client
	done chan struct{} // closed by Close: stops the keepalive

	// sftpMu serializes opening the SFTP session, which takes round trips;
	// mu guards the fields below and is never held across the network, so
	// Close never waits for a silent server.
	sftpMu sync.Mutex
	mu     sync.Mutex
	sftp   *sftp.Client
	closed bool
	down   error // why the connection ended; nil while it works
}

var _ remote.Executor = (*Client)(nil)

// errClosed: the caller closed the connection.
var errClosed = errors.New("connection closed")

// errPasswordRefused ends the login once the server refused the password:
// keyboard-interactive would only ask for the same password again and add
// a second failure to the server's log for one attempt (fail2ban bans the
// controller after a few).
var errPasswordRefused = fmt.Errorf("%w: the server refused the password", remote.ErrAuthFailed)

// onePassword stops the login after a failed "password" method. A server
// that does not offer that method still gets the password by
// keyboard-interactive.
func onePassword(c *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if slices.Contains(c.TriedMethods, "password") {
		return nil, errPasswordRefused
	}
	return nil, nil
}

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
		User:         t.User,
		Auth:         methods,
		AuthCallback: onePassword,
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
	// The caller's ctx ends the handshake as well.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !stop() {
		if err == nil {
			c.Close()
		}
		return nil, &remote.UnreachableError{Err: ctx.Err()}
	}
	if err != nil {
		conn.Close()
		return nil, classify(err)
	}
	conn.SetDeadline(time.Time{})
	cl := &Client{ssh: ssh.NewClient(c, chans, reqs), done: make(chan struct{})}
	go func() {
		err := cl.ssh.Wait()
		if err == nil {
			err = errors.New("the server closed the connection")
		}
		cl.setDown(err)
	}()
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
	case errors.As(err, &unknown), errors.As(err, &changed), errors.Is(err, remote.ErrAuthFailed):
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

// keepalive sends a request each interval; one still unanswered at the
// next tick is a miss, and keepaliveMisses misses in a row close the
// connection (SendRequest itself would wait for the answer forever).
func (c *Client) keepalive(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	answer := make(chan error, 1)
	waiting, missed := false, 0
	for {
		select {
		case <-c.done:
			return
		case err := <-answer:
			waiting, missed = false, 0
			if err != nil {
				c.abort(fmt.Errorf("keepalive: %w", err))
				return
			}
		case <-t.C:
			if !waiting {
				waiting = true
				go func() {
					_, _, err := c.ssh.SendRequest("keepalive@openssh.com", true, nil)
					answer <- err
				}()
				continue
			}
			if missed++; missed >= keepaliveMisses {
				c.abort(fmt.Errorf("no answer to keepalives for %v", time.Duration(missed)*every))
				return
			}
		}
	}
}

// setDown records why the connection ended (the first reason stays).
func (c *Client) setDown(err error) {
	c.mu.Lock()
	if c.down == nil {
		c.down = err
	}
	c.mu.Unlock()
}

// abort closes a connection that stopped answering: every operation
// waiting on it fails.
func (c *Client) abort(err error) {
	c.setDown(err)
	c.ssh.Close()
}

// alive fails when the connection has ended.
func (c *Client) alive() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down != nil {
		return &remote.UnreachableError{Err: c.down}
	}
	return nil
}

// failed is what an operation that failed with err returns: the context's
// error when it ended, UnreachableError when the connection is gone.
func (c *Client) failed(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if d := c.alive(); d != nil {
		return d
	}
	return err
}

// guard ends an operation that ctx cancels: interrupt (when set) asks the
// server to stop it, and if the operation has not finished cancelGrace
// later the whole connection is closed. The returned function marks the
// operation finished.
func (c *Client) guard(ctx context.Context, interrupt func()) (finished func()) {
	end := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		if interrupt != nil {
			go interrupt() // it writes, which a full send buffer blocks
		}
		t := time.NewTimer(cancelGrace)
		defer t.Stop()
		select {
		case <-end:
		case <-t.C:
			c.abort(fmt.Errorf("no answer from the server %v after cancelling: %w", cancelGrace, context.Cause(ctx)))
		}
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			stop()
			close(end)
		})
	}
}

// Close ends the connection. It never waits for the server.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.down == nil {
		c.down = errClosed
	}
	close(c.done)
	sc := c.sftp
	c.mu.Unlock()
	err := c.ssh.Close()
	if sc != nil {
		sc.Close() // returns at once: the connection is gone
	}
	if errors.Is(err, net.ErrClosed) {
		err = nil // already closed after a failure
	}
	return err
}

// limitedBuffer keeps the first max bytes; over says more came. The
// buffer is a field, not embedded: an embedded bytes.Buffer would give it
// ReadFrom, and io.Copy would fill it past max without calling Write.
type limitedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.max - b.buf.Len(); n > room {
		b.over = true
		p = p[:max(room, 0)]
	}
	b.buf.Write(p)
	return n, nil // the rest is dropped, not an error for the session
}

func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

// start opens a session and starts cmd. Until the returned function is
// called, a cancelled ctx kills the program and, if the server does not
// close the session within cancelGrace, closes the connection.
func (c *Client) start(ctx context.Context, cmd remote.Cmd, stdout, stderr io.Writer) (*ssh.Session, func(), error) {
	line, err := remote.CommandLine(cmd)
	if err != nil {
		return nil, nil, err
	}
	if err := c.alive(); err != nil {
		return nil, nil, err
	}
	var sess atomic.Pointer[ssh.Session]
	finished := c.guard(ctx, func() {
		if s := sess.Load(); s != nil {
			s.Signal(ssh.SIGKILL)
			s.Close()
		}
	})
	s, err := c.ssh.NewSession()
	if err != nil {
		finished()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, &remote.UnreachableError{Err: err}
	}
	sess.Store(s)
	if ctx.Err() != nil {
		// Cancelled before the session was stored: the guard missed it.
		s.Close()
		finished()
		return nil, nil, ctx.Err()
	}
	if cmd.Stdin != nil {
		s.Stdin = bytes.NewReader(cmd.Stdin)
	}
	s.Stdout, s.Stderr = stdout, stderr
	if err := s.Start(line); err != nil {
		s.Close()
		finished()
		return nil, nil, c.failed(ctx, err)
	}
	return s, func() { s.Close(); finished() }, nil
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
	res, _, err := c.run(ctx, cmd, maxOutput)
	return res, err
}

// run keeps up to limit bytes of stdout; over reports that there was
// more.
func (c *Client) run(ctx context.Context, cmd remote.Cmd, limit int) (res remote.Result, over bool, err error) {
	out := &limitedBuffer{max: limit}
	errb := &limitedBuffer{max: 1 << 20}
	s, done, err := c.start(ctx, cmd, out, errb)
	if err != nil {
		return remote.Result{}, false, err
	}
	defer done()
	werr := s.Wait()
	if ctx.Err() != nil {
		return remote.Result{}, false, ctx.Err()
	}
	code, err := exitCode(werr)
	if err != nil {
		return remote.Result{}, false, c.failed(ctx, err)
	}
	return remote.Result{Stdout: out.Bytes(), Stderr: errb.Bytes(), ExitCode: code}, out.over, nil
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
		return c.failed(ctx, err)
	}
	if code != 0 {
		return &remote.ExitError{Op: cmd.Args[0], Code: code, Stderr: strings.TrimSpace(errb.String())}
	}
	return nil
}

// sftpClient opens the SFTP session on first use. Opening takes round
// trips, so it holds sftpMu, not mu: Close does not wait for it.
func (c *Client) sftpClient(ctx context.Context) (*sftp.Client, error) {
	c.sftpMu.Lock()
	defer c.sftpMu.Unlock()
	if err := c.alive(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	sc := c.sftp
	c.mu.Unlock()
	if sc != nil {
		return sc, nil
	}
	finished := c.guard(ctx, nil)
	sc, err := sftp.NewClient(c.ssh)
	finished()
	if err != nil {
		return nil, c.failed(ctx, fmt.Errorf("sftp: %w", err))
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		sc.Close()
		return nil, &remote.UnreachableError{Err: errClosed}
	}
	c.sftp = sc
	c.mu.Unlock()
	return sc, nil
}

// ReadFile implements remote.Executor: SFTP as the SSH user, cat through
// sudo as root.
func (c *Client) ReadFile(ctx context.Context, p string, sudo bool) ([]byte, error) {
	if err := remote.CheckPath(p); err != nil {
		return nil, err
	}
	if sudo {
		res, over, err := c.run(ctx, remote.Cmd{Args: []string{"cat", "--", p}, Sudo: true}, maxFile)
		if err != nil {
			return nil, err
		}
		if over {
			return nil, tooLarge(p)
		}
		if !res.OK() {
			if strings.Contains(string(res.Stderr), "No such file") {
				return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist) // as SFTP says it
			}
			return nil, &remote.ExitError{Op: "read " + p, Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
		}
		return res.Stdout, nil
	}
	sc, err := c.sftpClient(ctx)
	if err != nil {
		return nil, err
	}
	// SFTP calls take no context: the guard ends them.
	finished := c.guard(ctx, nil)
	defer finished()
	f, err := sc.Open(p)
	if err != nil {
		return nil, c.failed(ctx, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(maxFile)+1))
	if err != nil {
		return nil, c.failed(ctx, err)
	}
	if len(b) > maxFile {
		return nil, tooLarge(p)
	}
	return b, nil
}

func tooLarge(p string) error {
	return fmt.Errorf("%s: %w (more than %d MB)", p, remote.ErrFileTooLarge, maxFile>>20)
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

	tmp := path.Join(dir, "upload")
	if err := c.upload(ctx, tmp, data); err != nil {
		return err
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

// upload writes data into a new file by SFTP.
func (c *Client) upload(ctx context.Context, p string, data []byte) error {
	sc, err := c.sftpClient(ctx)
	if err != nil {
		return err
	}
	finished := c.guard(ctx, nil)
	defer finished()
	w, err := sc.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return c.failed(ctx, fmt.Errorf("sftp create: %w", err))
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return c.failed(ctx, fmt.Errorf("sftp write: %w", err))
	}
	if err := w.Close(); err != nil {
		return c.failed(ctx, fmt.Errorf("sftp close: %w", err))
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
