package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/quicprobe"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// health are the states a check may set; the others belong to jobs and
// the admin.
var health = []model.ServerState{model.StateHealthy, model.StateDegraded, model.StateOffline}

// check is one health check under way.
type check struct {
	h    model.Health
	unit string
	port int
	udp  chan udpResult
}

type udpResult struct {
	state string
	rtt   time.Duration
	err   error
}

// startCheck starts the check of a server with Hysteria installed (nil
// without an installation): the UDP probe runs in the background.
func (c *Collector) startCheck(ctx context.Context, srv model.Server) *check {
	in, err := c.Store.Installation(ctx, srv.ID)
	if err != nil {
		return nil
	}
	hc := &check{h: model.Health{ServerID: srv.ID, UDP: model.UDPSkipped}, unit: in.Unit}
	cfg := c.config(ctx, srv.ID)
	if cfg == nil {
		return hc
	}
	l, err := hyconfig.ParseListen(cfg.Listen)
	if err != nil {
		return hc
	}
	hc.port = l.First
	var obfs string
	switch strings.ToLower(cfg.Obfs.Type) {
	case "", "plain": // plain is no obfuscation
	case "salamander":
		obfs = cfg.Obfs.Salamander.Password
	default:
		return hc // other obfuscation: not probed
	}
	hc.udp = make(chan udpResult, 1)
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(hc.port))
	go func() {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		rtt, err := c.Probe(pctx, addr, obfs)
		switch {
		case err == nil:
			hc.udp <- udpResult{state: model.UDPOK, rtt: rtt}
		case errors.Is(err, quicprobe.ErrNoAnswer):
			hc.udp <- udpResult{state: model.UDPNoAnswer, err: err}
		default:
			hc.udp <- udpResult{state: model.UDPError, err: err}
		}
	}()
	return hc
}

// config is the server's current config (nil: none or unreadable).
func (c *Collector) config(ctx context.Context, serverID int64) *hyconfig.Server {
	if c.Keys == nil {
		return nil
	}
	cur, err := c.Store.CurrentConfig(ctx, serverID)
	if err != nil {
		return nil
	}
	b, err := c.Keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	if err != nil {
		return nil
	}
	cfg, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil
	}
	return cfg
}

// waitUDP takes the probe's result (skipped when there was none).
func (hc *check) waitUDP() udpResult {
	if hc.udp == nil {
		return udpResult{state: model.UDPSkipped}
	}
	return <-hc.udp
}

// sshFailed completes a check when SSH did not connect: offline when the
// server answers neither SSH nor UDP.
func (hc *check) sshFailed(err error, unreachable bool) model.Health {
	u := hc.waitUDP()
	hc.h.UDP, hc.h.UDPMillis = u.state, int(u.rtt.Milliseconds())
	refused := errors.Is(err, remote.ErrAuthFailed)
	why := "Не удалось войти по SSH: " + err.Error()
	switch {
	case unreachable:
		why = "SSH не отвечает"
	case refused:
		why = "Сервер отклонил вход по SSH"
	}
	switch {
	case u.state == model.UDPOK:
		hc.h.Status, hc.h.Reason = model.StateDegraded, why+", но Hysteria отвечает на UDP "+strconv.Itoa(hc.port)+"."
	case unreachable:
		hc.h.Status, hc.h.Reason = model.StateOffline, why+hc.udpWhy(u)
	default:
		hc.h.Status, hc.h.Reason = model.StateDegraded, why+hc.udpWhy(u)
	}
	if refused {
		hc.h.Reason += fmt.Sprintf(" Проверьте пользователя, пароль или ключ. Пока данные входа не изменятся, мониторинг входит всё реже (до раза в %d ч), чтобы сервер не заблокировал адрес controller.", int(authPauseMax.Hours()))
	}
	return hc.h
}

func (hc *check) udpWhy(u udpResult) string {
	switch u.state {
	case model.UDPNoAnswer:
		return "; UDP " + strconv.Itoa(hc.port) + " тоже не отвечает."
	case model.UDPError:
		return "; проверка UDP " + strconv.Itoa(hc.port) + " не удалась."
	}
	return "."
}

// onServer completes a check over the SSH connection.
func (hc *check) onServer(ctx context.Context, ex remote.Executor, took time.Duration) model.Health {
	h := &hc.h
	h.SSHMillis = max(int(took.Milliseconds()), 1)
	if st, err := remote.ActiveState(ctx, ex, hc.unit); err == nil {
		h.Service = st
	}
	if hc.port > 0 && h.Service == "active" {
		if ls, err := remote.Listeners(ctx, ex, false); err == nil {
			found := false
			for _, l := range ls {
				found = found || (l.Proto == "udp" && l.Port == hc.port)
			}
			h.Listening = &found
		}
	}
	if ip, err := remote.RouteSource(ctx, ex); err == nil {
		h.Egress = ip
	}
	u := hc.waitUDP()
	h.UDP, h.UDPMillis = u.state, int(u.rtt.Milliseconds())

	var why []string
	switch {
	case h.Service == "":
		why = append(why, "состояние службы "+hc.unit+" не прочитать")
	case h.Service != "active":
		why = append(why, fmt.Sprintf("служба %s: %s", hc.unit, h.Service))
	case h.Listening != nil && !*h.Listening:
		why = append(why, fmt.Sprintf("Hysteria не слушает UDP %d", hc.port))
	}
	switch u.state {
	case model.UDPNoAnswer:
		if h.Service == "active" {
			why = append(why, fmt.Sprintf("UDP %d не отвечает снаружи: его закрывает брандмауэр сервера или провайдера", hc.port))
		}
	case model.UDPError:
		why = append(why, fmt.Sprintf("проверка UDP %d не удалась: %v", hc.port, u.err))
	}
	h.Status = model.StateHealthy
	if len(why) > 0 {
		h.Status = model.StateDegraded
		h.Reason = capitalize(why[0])
		if len(why) > 1 {
			h.Reason += "; " + strings.Join(why[1:], "; ")
		}
		h.Reason += "."
	}
	return *h
}

// capitalize upper-cases the first letter: the first rune, not the first
// byte, which is half of a Cyrillic letter.
func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// finish stores the check and sets the server's state from it.
func (c *Collector) finish(ctx context.Context, srv model.Server, h model.Health) {
	if ctx.Err() != nil {
		return
	}
	h.At = c.Now()
	if err := c.Store.AddHealth(ctx, h); err != nil {
		c.Log.Warn("monitor: store health", "server", srv.Name, "err", err)
		return
	}
	if ok, _ := c.Store.SwapServerState(ctx, srv.ID, without(health, h.Status), h.Status, h.At); ok {
		c.Log.Info("monitor: server state", "server", srv.Name, "state", h.Status, "reason", h.Reason)
	}
}

func without(list []model.ServerState, s model.ServerState) []model.ServerState {
	var out []model.ServerState
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
