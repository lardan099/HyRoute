package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// CheckStep is one line of a profile check.
type CheckStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Skip   bool   `json:"skip"`
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

type CheckResult struct {
	Profile    string      `json:"profile"`
	OK         bool        `json:"ok"`
	Steps      []CheckStep `json:"steps"`
	ExternalIP string      `json:"externalIP"`
	LatencyMs  int64       `json:"latencyMs"`
}

// Check targets (variables for tests): IP-echo services over HTTPS, a
// host for the latency CONNECT, a DNS server for the UDP probe.
var (
	ipServices    = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	latencyTarget = socks5.Addr{Host: "one.one.one.one", Port: 443}
	dnsProbe      = socks5.Addr{IP: netip.MustParseAddr("1.1.1.1"), Port: 53}
)

// CheckProfile starts the profile (or uses its running Hysteria), then
// checks TCP through it, the external IP, latency and UDP.
func (c *Controller) CheckProfile(id string) (CheckResult, error) {
	p, err := c.Profile(id)
	if err != nil {
		return CheckResult{}, err
	}
	res := CheckResult{Profile: p.Name}
	ep, release := c.acquire(p)
	defer release()

	// 1. Hysteria connects.
	start := time.Now()
	st, err := waitConnected(ep, 20*time.Second)
	step := CheckStep{Name: "Запуск Hysteria и подключение к серверу", Ms: time.Since(start).Milliseconds()}
	if err != nil {
		step.Detail = err.Error()
		res.Steps = append(res.Steps, step)
		res.Steps = append(res.Steps, CheckStep{Name: "TCP через туннель", Skip: true, Detail: "пропущено"})
		return res, nil
	}
	step.OK, step.Detail = true, "подключено"
	res.Steps = append(res.Steps, step)

	// 2. TCP: a CONNECT through the tunnel (latency) and HTTPS for the
	// external IP.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t0 := time.Now()
	conn, err := ep.Dial(ctx, latencyTarget)
	cancel()
	step = CheckStep{Name: "TCP через туннель", Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		step.Detail = "соединение через SOCKS5 не открылось: " + err.Error()
		res.Steps = append(res.Steps, step)
		return res, nil
	}
	conn.Close()
	res.LatencyMs = step.Ms
	step.OK, step.Detail = true, fmt.Sprintf("соединение открыто за %d мс (задержка до сервера и дальше до цели)", step.Ms)
	res.Steps = append(res.Steps, step)

	t0 = time.Now()
	ip, err := externalIP(ep)
	step = CheckStep{Name: "Внешний IP через туннель", Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		step.Detail = err.Error()
	} else {
		step.OK, step.Detail, res.ExternalIP = true, ip, ip
	}
	res.Steps = append(res.Steps, step)

	// 3. UDP: a DNS query to 1.1.1.1 through UDP ASSOCIATE.
	step = CheckStep{Name: "UDP через туннель"}
	if !st.UDPEnabled {
		step.Skip, step.Detail = true, "сервер запретил UDP: UDP-правила с этим профилем будут отклоняться"
	} else {
		t0 = time.Now()
		err := udpProbe(ep)
		step.Ms = time.Since(t0).Milliseconds()
		if err != nil {
			step.Detail = err.Error()
		} else {
			step.OK, step.Detail = true, fmt.Sprintf("DNS-запрос к 1.1.1.1 получил ответ за %d мс", step.Ms)
		}
	}
	res.Steps = append(res.Steps, step)
	res.OK = true
	for _, s := range res.Steps {
		if !s.OK && !s.Skip {
			res.OK = false
		}
	}
	c.Log.Info("profile check", "profile", p.Name, "ok", res.OK, "latencyMs", res.LatencyMs)
	return res, nil
}

// acquire returns an endpoint for p: the routing session's when connected
// (it excludes the server from interception), otherwise a standalone
// Hysteria.
func (c *Controller) acquire(p hysteria.Profile) (*tunnels.Endpoint, func()) {
	c.mu.Lock()
	sess := c.sess
	if sess == nil && c.checkMgr == nil {
		f := c.Runners
		if f == nil {
			base := c.Base
			base.Redactor = c.Redactor
			f = session.RunnerFactory(base)
		}
		c.checkMgr = &tunnels.Manager{New: f, Log: c.Log, LogLine: c.hysteriaLine}
	}
	mgr := c.checkMgr
	c.mu.Unlock()
	if sess != nil {
		return sess.Acquire(p)
	}
	return mgr.Acquire(p)
}

func waitConnected(ep *tunnels.Endpoint, timeout time.Duration) (hysteria.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st := ep.Status()
		switch {
		case st.State == hysteria.Connected:
			return st, nil
		case st.State == hysteria.Failed && st.Message != "":
			return st, errors.New(st.Message)
		case time.Now().After(deadline):
			if st.Message != "" {
				return st, errors.New(st.Message)
			}
			return st, errors.New("Hysteria не подключилась за 20 с: сервер не отвечает (порт, obfs-пароль или блокировка UDP)")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func externalIP(ep *tunnels.Endpoint) (string, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var pn uint16
			fmt.Sscan(port, &pn)
			return ep.Dial(ctx, socks5.Addr{Host: host, Port: pn})
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 12 * time.Second}
	var last error
	for _, u := range ipServices {
		resp, err := cl.Get(u)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if _, err := netip.ParseAddr(ip); resp.StatusCode == 200 && err == nil {
			return ip, nil
		}
		last = fmt.Errorf("%s ответил %s", u, resp.Status)
	}
	return "", fmt.Errorf("HTTPS через туннель не прошёл: %v", last)
}

func udpProbe(ep *tunnels.Endpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	a, err := ep.UDPAssociate(ctx)
	if err != nil {
		return fmt.Errorf("UDP ASSOCIATE не удался: %v", err)
	}
	defer a.Close()
	var idb [2]byte
	rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	q, _ := msg.Pack()
	dst := dnsProbe
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := a.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) == nil && m.ID == id {
				done <- nil
				return
			}
		}
	}()
	for try := 0; try < 3; try++ {
		if err := a.WriteTo(q, dst); err != nil {
			return fmt.Errorf("отправка не удалась: %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("ответ не получен: %v", err)
			}
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("ответа на DNS-запрос через UDP нет за 6 с: UDP через сервер не проходит")
}
