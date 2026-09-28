package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/lardan099/hyroute/internal/localproxy"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Local proxies: a SOCKS5 + HTTP port per entry, each going out through
// its own server. They run while HyRoute is connected; their servers are
// started like the ones rules use.

type ProxyView struct {
	store.LocalProxy
	Password    string `json:"password"` // store.LocalProxy hides it from JSON on disk
	ProfileName string `json:"profileName"`
	// State: off | waiting (not connected) | listening | error
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
	Active int64  `json:"active"`
	Total  int64  `json:"total"`
	Sent   int64  `json:"sent"`
	Recv   int64  `json:"recv"`
	// Address clients use (127.0.0.1:port, or this PC's LAN addresses).
	Addresses []string `json:"addresses"`
}

type proxyRun struct {
	cfg store.LocalProxy
	srv *localproxy.Server
	err string
}

// proxyProfileLocked resolves "" to the main server.
func (c *Controller) proxyProfileLocked(p store.LocalProxy) string {
	if p.Profile == "" {
		return c.profiles.Active
	}
	return p.Profile
}

func (c *Controller) Proxies() []ProxyView {
	c.mu.Lock()
	list := append([]store.LocalProxy(nil), c.proxies...)
	connected := c.sess != nil
	names := map[string]string{}
	for _, p := range list {
		id := c.proxyProfileLocked(p)
		if pr := c.profiles.Find(id); pr != nil {
			names[p.ID] = pr.Name
		}
	}
	c.mu.Unlock()
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	out := make([]ProxyView, 0, len(list))
	for _, p := range list {
		v := ProxyView{LocalProxy: p, Password: p.Password, ProfileName: names[p.ID], State: "off", Addresses: []string{}}
		switch r := c.proxyRuns[p.ID]; {
		case !p.Enabled:
		case r != nil && r.srv != nil:
			v.State = "listening"
			v.Active, v.Total = r.srv.Active.Load(), r.srv.Total.Load()
			v.Sent, v.Recv = r.srv.Sent.Load(), r.srv.Recv.Load()
		case r != nil && r.err != "":
			v.State, v.Error = "error", r.err
		case !connected:
			v.State = "waiting"
		}
		v.Addresses = proxyAddresses(p)
		out = append(out, v)
	}
	return out
}

// proxyAddresses: what to type into a program's proxy setting.
func proxyAddresses(p store.LocalProxy) []string {
	out := []string{fmt.Sprintf("127.0.0.1:%d", p.Port)}
	if !p.LAN {
		return out
	}
	ifs, _ := net.InterfaceAddrs()
	for _, a := range ifs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || !n.IP.IsPrivate() {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", n.IP, p.Port))
	}
	return out
}

func validateProxy(p store.LocalProxy, others []store.LocalProxy) error {
	if p.Port < 1024 || p.Port > 65535 {
		return errors.New("порт должен быть от 1024 до 65535")
	}
	for _, o := range others {
		if o.ID != p.ID && o.Port == p.Port {
			return fmt.Errorf("порт %d уже занят прокси «%s»", p.Port, o.Name)
		}
	}
	if (p.Username == "") != (p.Password == "") {
		return errors.New("укажите и логин, и пароль, или оставьте оба пустыми")
	}
	if strings.ContainsAny(p.Username, ":") {
		return errors.New("в логине не может быть двоеточия")
	}
	if len(p.Username) > 255 || len(p.Password) > 255 {
		return errors.New("логин и пароль — не длиннее 255 символов")
	}
	if p.LAN && p.Username == "" {
		return errors.New("для доступа из локальной сети задайте логин и пароль: иначе прокси сможет пользоваться любое устройство в сети")
	}
	if p.Enabled {
		if err := lanPortErr(p); err != nil {
			return err
		}
	}
	return nil
}

// lanPortErr keeps LAN proxies out of the relay's port range: the relay's
// firewall rule (fwrule) lets anyone reach HyRoute there in every network,
// public Wi-Fi included, while the proxies' rule keeps to home and work
// networks.
func lanPortErr(p store.LocalProxy) error {
	if p.LAN && p.Port >= relay.PortMin && p.Port <= relay.PortMax {
		return fmt.Errorf("для доступа из локальной сети выберите порт от 1024 до %d: порты %d–%d брандмауэр Windows открывает для HyRoute в любой сети, в том числе в публичной", relay.PortMin-1, relay.PortMin, relay.PortMax)
	}
	return nil
}

// lanHost is where LAN proxies listen: every IPv4 address (localproxy
// keeps "0.0.0.0" off IPv6). Tests keep to loopback.
var lanHost = "0.0.0.0"

// lanMaxConns caps simultaneous connections to a LAN proxy, lower than a
// local one's: any device in the network may open them before the
// password is asked.
const lanMaxConns = 256

// ProxyInput is a proxy as the editor sends it (with the password).
type ProxyInput struct {
	store.LocalProxy
	Password string `json:"password"`
}

// SaveProxy creates (empty ID) or replaces a proxy.
func (c *Controller) SaveProxy(in ProxyInput) (ProxyView, error) {
	p := in.LocalProxy
	p.Password = in.Password
	p.Name = strings.TrimSpace(p.Name)
	p.Username = strings.TrimSpace(p.Username)
	c.mu.Lock()
	if p.Profile != "" && c.profiles.Find(p.Profile) == nil {
		c.mu.Unlock()
		return ProxyView{}, errors.New("сервер не найден")
	}
	if err := validateProxy(p, c.proxies); err != nil {
		c.mu.Unlock()
		return ProxyView{}, err
	}
	next := append([]store.LocalProxy(nil), c.proxies...)
	if p.ID == "" {
		p.ID = newID()
		next = append(next, p)
	} else {
		i := proxyIndex(next, p.ID)
		if i < 0 {
			c.mu.Unlock()
			return ProxyView{}, errors.New("прокси не найден")
		}
		next[i] = p
	}
	if p.Name == "" {
		p.Name = fmt.Sprintf("Прокси %d", p.Port)
		next[proxyIndex(next, p.ID)].Name = p.Name
	}
	if err := c.saveProxiesLocked(next); err != nil {
		c.mu.Unlock()
		return ProxyView{}, err
	}
	c.applyRoutingLocked() // its server must run
	c.mu.Unlock()
	c.Redactor.SetGroup("proxy:"+p.ID, p.Password)
	c.syncProxiesLife()
	c.changed()
	for _, v := range c.Proxies() {
		if v.ID == p.ID {
			return v, nil
		}
	}
	return ProxyView{}, nil
}

func (c *Controller) DeleteProxy(id string) error {
	c.mu.Lock()
	i := proxyIndex(c.proxies, id)
	if i < 0 {
		c.mu.Unlock()
		return errors.New("прокси не найден")
	}
	next := append(append([]store.LocalProxy(nil), c.proxies[:i]...), c.proxies[i+1:]...)
	if err := c.saveProxiesLocked(next); err != nil {
		c.mu.Unlock()
		return err
	}
	c.applyRoutingLocked()
	c.mu.Unlock()
	c.syncProxiesLife()
	c.changed()
	return nil
}

// saveProxiesLocked stores next and makes it current (c.mu held).
func (c *Controller) saveProxiesLocked(next []store.LocalProxy) error {
	if c.proxiesBroken != nil {
		return fmt.Errorf("proxies.json не загружен, изменения не сохраняются, чтобы не потерять прокси: %v", c.proxiesBroken)
	}
	if err := c.Store.SaveProxies(next); err != nil {
		return err
	}
	c.proxies = next
	return nil
}

func proxyIndex(list []store.LocalProxy, id string) int {
	for i, p := range list {
		if p.ID == id {
			return i
		}
	}
	return -1
}

// syncProxiesLife is syncProxies for a proxy change: under lifeMu, so a
// Disconnect in between cannot leave ports open after it.
func (c *Controller) syncProxiesLife() {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.syncProxies()
}

// syncProxies opens the ports of enabled proxies while connected and
// closes the rest. A changed proxy is reopened.
func (c *Controller) syncProxies() {
	c.mu.Lock()
	connected := c.sess != nil
	want := map[string]store.LocalProxy{}
	if connected {
		for _, p := range c.proxies {
			if p.Enabled {
				want[p.ID] = p
			}
		}
	}
	c.mu.Unlock()

	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	if c.proxyRuns == nil {
		c.proxyRuns = map[string]*proxyRun{}
	}
	for id, r := range c.proxyRuns {
		if p, ok := want[id]; ok && p == r.cfg && r.srv != nil {
			continue
		}
		if r.srv != nil {
			r.srv.Close()
			c.Log.Info("local proxy closed", "name", r.cfg.Name, "port", r.cfg.Port)
		}
		delete(c.proxyRuns, id)
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var lanPorts []int
	for _, id := range ids {
		p := want[id]
		if err := lanPortErr(p); err != nil { // saved before the check existed
			c.proxyRuns[id] = &proxyRun{cfg: p, err: err.Error()}
			c.Log.Error("local proxy not started", "name", p.Name, "port", p.Port, "err", err)
			continue
		}
		if p.LAN {
			lanPorts = append(lanPorts, p.Port)
		}
		if c.proxyRuns[id] != nil {
			continue
		}
		srv := &localproxy.Server{Username: p.Username, Password: p.Password, Dial: c.proxyDialer(p), MaxConns: localproxy.DefaultMaxConns}
		host := "127.0.0.1"
		if p.LAN {
			host, srv.MaxConns = lanHost, lanMaxConns
		}
		srv.OnLimit = func(refused int64) {
			c.Log.Warn("local proxy full: new connections closed", "name", p.Name, "port", p.Port, "limit", srv.MaxConns, "refused", refused)
		}
		srv.OnAcceptError = func(err error) {
			c.Log.Error("local proxy accept failed", "name", p.Name, "port", p.Port, "err", err)
		}
		r := &proxyRun{cfg: p}
		if err := srv.Listen(fmt.Sprintf("%s:%d", host, p.Port)); err != nil {
			r.err = fmt.Sprintf("порт %d не открылся: %v (занят другой программой?)", p.Port, err)
			c.Log.Error("local proxy not started", "name", p.Name, "port", p.Port, "err", err)
		} else {
			r.srv = srv
			c.Log.Info("local proxy listening (SOCKS5 and HTTP)", "name", p.Name, "addr", srv.Addr(), "auth", p.Username != "")
		}
		c.proxyRuns[id] = r
	}
	// c.proxyFW nil: the rule is unknown (HyRoute just started, or it was
	// disconnected with LAN ports open and "Remove firewall rule" may have
	// deleted the rule since), so the first sync of a connection sets it.
	if c.ProxyFirewall != nil && ((connected && c.proxyFW == nil) || !equalInts(lanPorts, c.proxyFW)) {
		if err := c.ProxyFirewall(lanPorts); err != nil {
			c.Log.Error("firewall rule for local proxies not set: other devices may not reach them", "err", err)
		} else {
			c.proxyFW = append([]int{}, lanPorts...) // non-nil: known
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// proxyDialer goes through the proxy's server of the running session. The
// server is looked up per connection: "main" follows the main server.
func (c *Controller) proxyDialer(p store.LocalProxy) localproxy.Dialer {
	return func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		c.mu.Lock()
		s := c.sess
		id := c.proxyProfileLocked(p)
		c.mu.Unlock()
		if s == nil {
			return nil, errors.New("HyRoute не подключён")
		}
		ep := s.Endpoint(id)
		if ep == nil {
			return nil, errors.New("сервер прокси не запущен")
		}
		if !ep.Available() {
			ep.NoteRejected()
			return nil, socks5.ReplyError(1)
		}
		conn, err := ep.Dial(ctx, dst)
		if err != nil {
			ep.NoteRejected()
			return nil, err
		}
		return &tunnelConn{Conn: conn, ep: ep}, nil
	}
}

// tunnelConn counts a proxy connection into its server's traffic, as the
// relay does for intercepted ones.
type tunnelConn struct {
	net.Conn
	ep *tunnels.Endpoint
}

func (t *tunnelConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.ep.NoteTraffic(0, int64(n))
	return n, err
}

func (t *tunnelConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	t.ep.NoteTraffic(int64(n), 0)
	return n, err
}

// CloseWrite keeps half-close working through the wrapper (socks5.Pipe).
func (t *tunnelConn) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.Conn.Close()
}

// NetConn returns the wrapped connection (socks5.Abort resets through it).
func (t *tunnelConn) NetConn() net.Conn { return t.Conn }

// stopProxies closes every port (Disconnect).
func (c *Controller) stopProxies() {
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	for id, r := range c.proxyRuns {
		if r.srv != nil {
			r.srv.Close()
		}
		delete(c.proxyRuns, id)
	}
	// "Remove firewall rule" may delete the rule while disconnected: the
	// next Connect sets it again. A rule known to be absent stays absent.
	if len(c.proxyFW) > 0 {
		c.proxyFW = nil
	}
}
