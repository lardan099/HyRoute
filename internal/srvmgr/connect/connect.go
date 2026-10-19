// Package connect opens SSH connections to inventory servers: it takes the
// sealed credentials from the inventory, checks the host key against the
// trusted one (trust on first use, confirmed by an admin) and registers the
// credentials with the redactor so no log line can echo them.
//
// Credentials are never offered to a server whose host key is not trusted:
// the key check runs before authentication.
package connect

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshexec"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what the connector needs from storage.
type Store interface {
	store.HostKeys
	store.Audit
}

// DialFunc opens a connection (sshexec.Dial; tests may replace it).
type DialFunc func(ctx context.Context, t sshexec.Target, a sshexec.Auth, o sshexec.Options) (remote.Executor, error)

func defaultDial(ctx context.Context, t sshexec.Target, a sshexec.Auth, o sshexec.Options) (remote.Executor, error) {
	return sshexec.Dial(ctx, t, a, o)
}

// Connector connects to inventory servers.
type Connector struct {
	Servers *servers.Service
	Store   Store
	Redact  *redact.Redactor
	Dial    DialFunc
	// FetchHostKey reads a server's host key without logging in.
	FetchHostKey func(ctx context.Context, t sshexec.Target, timeout time.Duration) (ssh.PublicKey, error)
	Timeout      time.Duration
	Now          func() time.Time
	// Events hears how each login went (nil: nobody).
	Events Events
}

// Events hears the outcome of every login to a server: nil, another host
// key (remote.HostKeyChangedError), a refused login (remote.ErrAuthFailed)
// or any other error (events.Watcher).
type Events interface {
	SSH(ctx context.Context, serverID int64, err error)
}

// New returns a connector using SSH.
func New(srv *servers.Service, st Store, red *redact.Redactor) *Connector {
	return &Connector{Servers: srv, Store: st, Redact: red, Dial: defaultDial, FetchHostKey: sshexec.FetchHostKey, Timeout: 15 * time.Second, Now: time.Now}
}

// ErrFingerprintMismatch: the server now presents another key than the one
// the admin confirmed.
var ErrFingerprintMismatch = errors.New("the server presents another host key than the confirmed fingerprint")

func target(s model.Server) sshexec.Target {
	return sshexec.Target{Host: s.Host, Port: s.SSHPort, User: s.SSHUser}
}

// keyBytes is a trusted key as the transport presents keys now: a host
// certificate an earlier build trusted counts as the key it certifies.
func keyBytes(b []byte) []byte {
	if k, err := ssh.ParsePublicKey(b); err == nil {
		if c, ok := k.(*ssh.Certificate); ok {
			return c.Key.Marshal()
		}
	}
	return b
}

// checkAgainst returns the host key check for a trusted key (or none).
func checkAgainst(trusted *model.HostKey) func(ssh.PublicKey) error {
	return func(k ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(k)
		if trusted == nil {
			return &remote.HostKeyUnknownError{KeyType: k.Type(), Fingerprint: fp}
		}
		if !bytes.Equal(k.Marshal(), keyBytes(trusted.Key)) {
			return &remote.HostKeyChangedError{KeyType: k.Type(), Fingerprint: fp, OldKeyType: trusted.Type, OldFingerprint: trusted.Fingerprint}
		}
		return nil
	}
}

// Connect opens a connection to a server with its trusted host key. The
// caller closes the executor.
func (c *Connector) Connect(ctx context.Context, serverID int64) (remote.Executor, error) {
	info, err := c.Servers.Get(ctx, serverID)
	if err != nil {
		return nil, err
	}
	creds, err := c.Servers.Credentials(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if c.Redact != nil {
		c.Redact.Add(creds.Password, creds.KeyPassphrase)
	}
	ex, err := c.Dial(ctx, target(info.Server), sshexec.Auth{Password: creds.Password, Key: creds.Key, Passphrase: creds.KeyPassphrase},
		sshexec.Options{HostKey: checkAgainst(info.HostKey), Timeout: c.Timeout})
	if c.Events != nil && ctx.Err() == nil {
		c.Events.SSH(context.WithoutCancel(ctx), serverID, err)
	}
	return ex, err
}

// Check connects and identifies the server (remote.RunProbe); it changes
// nothing on the server. A server without root or passwordless sudo is
// reported with remote.ErrSudoRequired along with the probe.
func (c *Connector) Check(ctx context.Context, serverID int64) (remote.Probe, error) {
	ex, err := c.Connect(ctx, serverID)
	if err != nil {
		return remote.Probe{}, err
	}
	defer ex.Close()
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return p, err
	}
	if !p.Privileged() {
		return p, remote.ErrSudoRequired
	}
	return p, nil
}

// Trust makes the host key the server presents now trusted, if its
// fingerprint is the one the admin confirmed. A server with a trusted key
// that differs needs replace (the explicit re-trust after a reinstall). The
// handshake stops at the key: no credentials are sent.
func (c *Connector) Trust(ctx context.Context, actor, serverID int64, fingerprint string, replace bool) (model.HostKey, error) {
	info, err := c.Servers.Get(ctx, serverID)
	if err != nil {
		return model.HostKey{}, err
	}
	seen, err := c.FetchHostKey(ctx, target(info.Server), c.Timeout)
	if err != nil {
		return model.HostKey{}, err
	}
	fp := ssh.FingerprintSHA256(seen)
	if strings.TrimSpace(fingerprint) != fp {
		return model.HostKey{}, ErrFingerprintMismatch
	}
	if old := info.HostKey; old != nil {
		if bytes.Equal(old.Key, seen.Marshal()) {
			return *old, nil
		}
		// A certificate an earlier build trusted is stored again as its
		// key, without replace.
		if !replace && !bytes.Equal(keyBytes(old.Key), seen.Marshal()) {
			return model.HostKey{}, &remote.HostKeyChangedError{KeyType: seen.Type(), Fingerprint: fp, OldKeyType: old.Type, OldFingerprint: old.Fingerprint}
		}
	}
	hk := model.HostKey{ServerID: serverID, Type: seen.Type(), Key: seen.Marshal(), Fingerprint: fp, TrustedAt: c.Now(), TrustedBy: actor}
	if err := c.Store.SetHostKey(ctx, hk); err != nil {
		return model.HostKey{}, err
	}
	action := "host_key_trusted"
	details := hk.Type + " " + fp
	if info.HostKey != nil {
		action = "host_key_replaced"
		details = info.HostKey.Fingerprint + " -> " + fp
	}
	c.Store.AddAudit(ctx, model.AuditEntry{Time: c.Now(), UserID: actor, Action: action, Target: "server/" + strconv.FormatInt(serverID, 10), Details: details})
	return hk, nil
}
