package cascade

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// SlowHandshake: a link whose client needs longer to reach the exit is
// degraded.
const SlowHandshake = 2 * time.Second

// tunnelProbe bounds the SOCKS5 probe through the SSH tunnel, with room
// for the exit to dial the check target.
var tunnelProbe = 15 * time.Second

// Probe is what a check of a link needs.
type Probe struct {
	Chain   int64
	Link    model.ChainLink
	Params  Params
	Secrets Secrets
	// Entry is the installation on the entry (the binary, where the link
	// config is); Exit the exit server (the default check target).
	Entry model.Installation
	Exit  model.Server
	// Sudo: the SSH user is not root (the link config is readable by
	// root and the service's group only).
	Sudo bool
}

// CheckLink checks a link from its entry over ex (P3-03). SOCKS5 of the
// Hysteria client answers every failure with the same code, so there are
// two signals: through an SSH tunnel to the entry's loopback the link
// service's SOCKS5 must take the password of the entry's outbound — what
// Hysteria itself does — and `hysteria ping` with the link's config must
// reach the exit and open the check target through it. Offline: the
// service does not run, its SOCKS5 does not answer or takes another
// password, the exit does not answer; degraded: the exit answers but does
// not open the target, or slowly.
func CheckLink(ctx context.Context, ex remote.Executor, pr Probe, now time.Time) model.LinkCheck {
	c := model.LinkCheck{ChainID: pr.Chain, Idx: pr.Link.Idx, At: now, Status: model.StateHealthy}
	red := redact.New()
	red.Add(pr.Secrets.ExitPassword, pr.Secrets.SOCKSPassword)
	off := func(format string, a ...any) model.LinkCheck {
		c.Status, c.Reason = model.StateOffline, red.String(fmt.Sprintf(format, a...))
		return c
	}
	target, err := checkTarget(pr.Params, pr.Exit)
	if err != nil {
		return off("адрес проверки связи не подходит")
	}
	unit := UnitName(pr.Chain, pr.Link.Idx)
	st, err := remote.ActiveState(ctx, ex, unit)
	if err != nil {
		return off("состояние службы связи не прочитано: %v", err)
	}
	c.Service = st
	if st != "active" {
		return off("служба связи %s не работает (%s)", unit, st)
	}

	tunnelTCP, tunnelTook := false, time.Duration(0)
	if pr.Params.LocalPort != 0 {
		dst, derr := socks5.ParseHostPort(target)
		if derr != nil {
			return off("адрес проверки связи не подходит")
		}
		pctx, cancel := context.WithTimeout(ctx, tunnelProbe)
		cl := socks5.Client{Username: pr.Secrets.SOCKSUser, Password: pr.Secrets.SOCKSPassword, HandshakeTimeout: tunnelProbe,
			Dial: func(ctx context.Context) (net.Conn, error) {
				conn, err := remote.DialLoopback(ctx, ex, pr.Params.LocalPort)
				if err == nil {
					// An SSH channel has no deadlines: the end of the
					// probe closes it.
					context.AfterFunc(ctx, func() { conn.Close() })
				}
				return conn, err
			}}
		start := time.Now()
		conn, err := cl.Connect(pctx, dst)
		took := time.Since(start)
		cancel()
		var rep socks5.ReplyError
		switch {
		case errors.Is(err, remote.ErrNoTunnel):
			// This connection cannot reach the loopback: ping alone.
		case errors.Is(err, socks5.ErrAuth):
			return off("клиент связи не принял пароль outbound «%s» сервера входа: обновите связь", OutboundName)
		case errors.As(err, &rep):
			// The client answered: the exit or the target did not.
		case err != nil:
			return off("клиент связи не отвечает на 127.0.0.1:%d сервера входа: %v", pr.Params.LocalPort, err)
		default:
			conn.Close()
			tunnelTCP, tunnelTook = true, took
		}
	}

	ping, err := PingLink(ctx, ex, pr.Entry.Binary, ConfigPath(pr.Entry, pr.Chain, pr.Link.Idx), target, pr.Sudo)
	if err != nil {
		return off("проверка связи не выполнилась на сервере входа: %v", err)
	}
	if !ping.Connected {
		why := ping.Error
		if why == "" {
			why = "нет ответа"
		}
		return off("сервер выхода не отвечает клиенту связи (%s)", why)
	}
	c.HandshakeMillis = int(ping.Handshake / time.Millisecond)
	switch {
	case ping.TCP:
		c.TCPMillis = max(int(ping.TCPTime/time.Millisecond), 1)
	case tunnelTCP:
		c.TCPMillis = max(int(tunnelTook/time.Millisecond), 1)
	}
	switch {
	case c.TCPMillis == 0:
		c.Status, c.Reason = model.StateDegraded, red.String("сервер выхода не открывает "+target)
	case ping.Handshake > SlowHandshake:
		c.Status, c.Reason = model.StateDegraded, "связь медленная: рукопожатие "+strconv.Itoa(c.HandshakeMillis)+" мс"
	}
	return c
}

func checkTarget(p Params, exit model.Server) (string, error) {
	if p.CheckTarget != "" {
		return CheckAddr(p.CheckTarget)
	}
	return CheckAddr(net.JoinHostPort(exit.Host, strconv.Itoa(exit.SSHPort)))
}

// CheckStore is what the link checks of the monitor read and write.
type CheckStore interface {
	ListChains(ctx context.Context) ([]model.Chain, error)
	LinkSecrets(ctx context.Context, chainID int64, idx int) ([]byte, error)
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	AddLinkCheck(ctx context.Context, c model.LinkCheck) error
	PruneLinkChecks(ctx context.Context, before time.Time) error
}

// Checker checks deployed links for the monitor, from their entries.
type Checker struct {
	Store CheckStore
	Keys  *secrets.Keyring
	Now   func() time.Time
}

func (k *Checker) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// deployed are the links checks look at: in effect on the servers.
func deployed(l model.ChainLink) bool {
	return l.State == model.LinkActive || l.State == model.LinkStale
}

// HasLinks reports whether a deployed link starts at server id.
func (k *Checker) HasLinks(ctx context.Context, id int64) bool {
	cs, err := k.Store.ListChains(ctx)
	if err != nil {
		return false
	}
	for _, c := range cs {
		for _, l := range c.Links {
			if l.From == id && deployed(l) {
				return true
			}
		}
	}
	return false
}

// CheckLinks checks the deployed links that start at entry over ex and
// stores the results. down says which one does not work ("" when every
// one does): the entry is degraded for it.
func (k *Checker) CheckLinks(ctx context.Context, entry model.Server, ex remote.Executor) (down string, err error) {
	cs, err := k.Store.ListChains(ctx)
	if err != nil {
		return "", err
	}
	sudoKnown, su := false, true
	for _, c := range cs {
		for _, l := range c.Links {
			if l.From != entry.ID || !deployed(l) {
				continue
			}
			if !sudoKnown {
				p, err := remote.RunProbe(ctx, ex)
				if err != nil {
					return "", err
				}
				sudoKnown, su = true, !p.Root
			}
			pr := Probe{Chain: c.ID, Link: l, Sudo: su}
			if pr.Params, err = ParseParams(l.Params); err != nil {
				return "", err
			}
			sealed, err := k.Store.LinkSecrets(ctx, c.ID, l.Idx)
			if err != nil {
				return "", err
			}
			if pr.Secrets, err = OpenSecrets(k.Keys, c.ID, l.Idx, sealed); err != nil {
				return "", err
			}
			if pr.Entry, err = k.Store.Installation(ctx, entry.ID); err != nil {
				return "", err
			}
			if pr.Exit, err = k.Store.ServerByID(ctx, l.To); err != nil {
				return "", err
			}
			res := CheckLink(ctx, ex, pr, k.now())
			if ctx.Err() != nil {
				return down, ctx.Err() // cut short: no verdict
			}
			if err := k.Store.AddLinkCheck(ctx, res); err != nil {
				return down, err
			}
			if res.Status == model.StateOffline && down == "" {
				down = "каскад до «" + pr.Exit.Name + "» не работает: " + res.Reason
			}
		}
	}
	return down, nil
}

// Prune drops link checks older than before.
func (k *Checker) Prune(ctx context.Context, before time.Time) error {
	return k.Store.PruneLinkChecks(ctx, before)
}
