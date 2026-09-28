package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
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

	// socks-udp. Active and Total count TCP connections only: every UDP
	// session holds a control connection, which the server counts too.
	UDPEffective bool   `json:"udpOn"`                // the switch's effective value (LocalProxy.UDPOn)
	UDPServed    bool   `json:"udpServed"`            // UDP ASSOCIATE served now (listening, UDP on, socket open)
	UDPActive    int64  `json:"udpActive"`            // open UDP sessions
	UDPTotal     int64  `json:"udpTotal"`             // UDP sessions served
	UDPDropped   int64  `json:"udpDropped"`           // datagrams dropped
	UDPError     string `json:"udpError,omitempty"`   // LAN: the shared UDP port did not open (retrying)
	UDPBlocked   string `json:"udpBlocked,omitempty"` // "server" | "group": the target cannot carry UDP now
}

type proxyRun struct {
	cfg store.LocalProxy
	srv *localproxy.Server
	err string
	// socks-udp: udpErr: UDP left off because the firewall rule for the
	// port is not set (a LAN socket without it makes Windows ask the user).
	udpErr string
}

// proxyProfileLocked resolves "" to the main target (a server or a group).
func (c *Controller) proxyProfileLocked(p store.LocalProxy) string {
	if p.Profile == "" {
		return c.mainTargetLocked()
	}
	return p.Profile
}

func (c *Controller) Proxies() []ProxyView {
	c.mu.Lock()
	list := append([]store.LocalProxy(nil), c.proxies...)
	sess := c.sess
	connected := sess != nil
	names := map[string]string{}
	targets := map[string]string{}
	for _, p := range list {
		targets[p.ID] = c.proxyProfileLocked(p)
		if n := c.targetNameLocked(targets[p.ID]); n != "" {
			names[p.ID] = n
		}
	}
	c.mu.Unlock()
	c.proxyMu.Lock()
	out := make([]ProxyView, 0, len(list))
	for _, p := range list {
		v := ProxyView{LocalProxy: p, Password: p.Password, ProfileName: names[p.ID], State: "off", Addresses: []string{}, UDPEffective: p.UDPOn()}
		switch r := c.proxyRuns[p.ID]; {
		case !p.Enabled:
		case r != nil && r.srv != nil:
			v.State = "listening"
			v.Sent, v.Recv = r.srv.Sent.Load(), r.srv.Recv.Load()
			proxyUDPView(&v, r.srv)
			if r.udpErr != "" {
				v.UDPError = r.udpErr
			}
		case r != nil && r.err != "":
			v.State, v.Error = "error", r.err
		case !connected:
			v.State = "waiting"
		}
		v.Addresses = proxyAddresses(p)
		out = append(out, v)
	}
	c.proxyMu.Unlock()
	// Endpoints are asked with no lock held (they take their own).
	for i := range out {
		if v := &out[i]; v.State == "listening" && v.UDPServed && sess != nil {
			v.UDPBlocked = c.proxyUDPBlocked(sess, targets[v.ID])
		}
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
	if p.UDP != "" && p.UDP != "on" && p.UDP != "off" { // socks-udp
		return errors.New("UDP: неверное значение")
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
	p.NormalizeUDP()
	c.mu.Lock()
	if p.Profile != "" && !c.targetExistsLocked(p.Profile) {
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
// closes the rest. A changed proxy is reopened. The firewall rules are set
// before any port opens: a LAN socket bound without its rule can make
// Windows Firewall ask the user, and the answer creates broad rules.
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
	var fw proxyPorts
	for _, id := range ids {
		if p := want[id]; p.LAN && lanPortErr(p) == nil {
			fw.tcp = append(fw.tcp, p.Port)
			if p.UDPOn() {
				fw.udp = append(fw.udp, p.Port)
			}
		}
	}
	// c.proxyFW nil: the rules are unknown (HyRoute just started, or it was
	// disconnected with LAN ports open and "Remove firewall rule" may have
	// deleted them since), so the first sync of a connection sets them.
	have := proxyPorts{}
	if c.proxyFW != nil {
		have = *c.proxyFW
	}
	if c.ProxyFirewall != nil && ((connected && c.proxyFW == nil) || !equalInts(fw.tcp, have.tcp) || !equalInts(fw.udp, have.udp)) {
		if err := c.ProxyFirewall(fw.tcp, fw.udp); err != nil {
			c.Log.Error("firewall rule for local proxies not set: other devices may not reach them", "err", err)
		} else {
			c.proxyFW = &proxyPorts{tcp: slices.Clone(fw.tcp), udp: slices.Clone(fw.udp)} // non-nil: known
		}
	}
	c.reopenUDPRuledLocked()
	for _, id := range ids {
		p := want[id]
		if err := lanPortErr(p); err != nil { // saved before the check existed
			c.proxyRuns[id] = &proxyRun{cfg: p, err: err.Error()}
			c.Log.Error("local proxy not started", "name", p.Name, "port", p.Port, "err", err)
			continue
		}
		if c.proxyRuns[id] != nil {
			continue
		}
		srv := &localproxy.Server{Username: p.Username, Password: p.Password, Dial: c.proxyDialer(p), MaxConns: localproxy.DefaultMaxConns}
		c.proxyUDPServer(srv, p)
		udpErr := c.proxyUDPUnruledLocked(srv, p)
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
		r := &proxyRun{cfg: p, udpErr: udpErr}
		if err := srv.Listen(fmt.Sprintf("%s:%d", host, p.Port)); err != nil {
			r.err = fmt.Sprintf("порт %d не открылся: %v (занят другой программой?)", p.Port, err)
			c.Log.Error("local proxy not started", "name", p.Name, "port", p.Port, "err", err)
		} else {
			r.srv = srv
			c.Log.Info("local proxy listening (SOCKS5 and HTTP)", "name", p.Name, "addr", srv.Addr(), "auth", p.Username != "", "udp", srv.UDPState())
			if err := srv.UDPError(); err != nil {
				c.Log.Error("local proxy UDP port not opened: UDP ASSOCIATE refused, retrying", "name", p.Name, "port", p.Port, "err", err)
			}
		}
		c.proxyRuns[id] = r
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
		if groups.IsGroupID(id) {
			return c.proxyGroupDial(ctx, s, p, id, dst)
		}
		ep := s.Endpoint(id)
		if ep == nil {
			return nil, errors.New("сервер прокси не запущен")
		}
		if !ep.Available() {
			ep.NoteRejected()
			c.proxyRecord(p, 6, dst, id, "", false, "rst: tunnel unavailable") // stats
			return nil, socks5.ReplyError(1)
		}
		conn, err := ep.Dial(ctx, dst)
		if err != nil {
			if !proxyDialStopped(ctx) { // stats
				ep.NoteRejected()
				c.proxyRecord(p, 6, dst, id, "", false, "rst: socks5 connect failed")
			}
			return nil, err
		}
		return c.newTunnelConn(conn, ep, c.proxyRecord(p, 6, dst, id, "", false, "proxied")), nil
	}
}

// tunnelConn counts a proxy connection into its server's traffic, as the
// relay does for intercepted ones, and into its statistics record (rec;
// nil in tests that build one by hand).
type tunnelConn struct {
	net.Conn
	ep  *tunnels.Endpoint
	rec *flows.Record
	fc  *flowCloser
}

func (c *Controller) newTunnelConn(conn net.Conn, ep *tunnels.Endpoint, rec *flows.Record) *tunnelConn {
	return &tunnelConn{Conn: conn, ep: ep, rec: rec, fc: &flowCloser{rec: rec, reg: c.proxyFlows}}
}

func (t *tunnelConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.ep.NoteTraffic(0, int64(n))
	if n > 0 && t.rec != nil {
		t.rec.Recv.Add(int64(n))
	}
	return n, err
}

func (t *tunnelConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	t.ep.NoteTraffic(int64(n), 0)
	if n > 0 && t.rec != nil {
		t.rec.Sent.Add(int64(n))
	}
	return n, err
}

// Close closes the connection and, once, its record.
func (t *tunnelConn) Close() error {
	t.fc.close()
	return t.Conn.Close()
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
	// "Remove firewall rule" may delete the rules while disconnected: the
	// next Connect sets them again. Rules known to be absent stay absent.
	if c.proxyFW != nil && (len(c.proxyFW.tcp) > 0 || len(c.proxyFW.udp) > 0) {
		c.proxyFW = nil
	}
}

// ---- socks-udp: SOCKS5 UDP ASSOCIATE of local proxies ----

// proxyUDPState is socks-udp's controller state.
type proxyUDPState struct {
	// proxyWarnMu guards proxyWarned (innermost, held around no call).
	proxyWarnMu sync.Mutex
	proxyWarned map[string]time.Time // per proxy ID and message: the last warning
	// v12Checked: KeepV12ProxyUDP has looked for v1.2.0's rule since the
	// start (guarded by mu).
	v12Checked bool
}

// proxyPorts are the LAN proxy ports the firewall rules allow.
type proxyPorts struct{ tcp, udp []int }

// lanMaxUDP caps simultaneous UDP sessions of a LAN proxy (DefaultMaxUDP
// for one on this computer).
const lanMaxUDP = 32

// proxyUDPUnruledLocked leaves UDP off on a LAN proxy whose UDP firewall
// rule is not set (ProxyFirewall failed): its socket would bind on every
// interface and make Windows Firewall ask the user. Returns the reason to
// show (proxyMu held).
func (c *Controller) proxyUDPUnruledLocked(srv *localproxy.Server, p store.LocalProxy) string {
	if !p.LAN || srv.AssociateUDP == nil || c.proxyUDPRuledLocked(p.Port) {
		return ""
	}
	srv.AssociateUDP, srv.SharedUDP = nil, false
	c.Log.Error("local proxy UDP not served: firewall rule not set", "name", p.Name, "port", p.Port)
	return "UDP через этот прокси выключен: правило брандмауэра для UDP-порта не установлено (подробности в журнале). TCP работает. HyRoute попробует снова при следующем подключении или изменении прокси."
}

// proxyUDPRuledLocked: the UDP firewall rule allows this port (proxyMu held).
func (c *Controller) proxyUDPRuledLocked(port int) bool {
	return c.ProxyFirewall == nil || (c.proxyFW != nil && slices.Contains(c.proxyFW.udp, port))
}

// reopenUDPRuledLocked closes proxies started without UDP for want of a
// firewall rule once the rule is set, so syncProxies reopens them with UDP
// (proxyMu held).
func (c *Controller) reopenUDPRuledLocked() {
	for id, r := range c.proxyRuns {
		if r.udpErr != "" && c.proxyUDPRuledLocked(r.cfg.Port) {
			if r.srv != nil {
				r.srv.Close()
			}
			delete(c.proxyRuns, id)
		}
	}
}

// proxyUDPView fills the UDP figures of a listening proxy (proxyMu held).
func proxyUDPView(v *ProxyView, srv *localproxy.Server) {
	udpActive, udpTotal := srv.UDPActive.Load(), srv.UDPTotal.Load()
	// TCP connections only: every UDP ASSOCIATE control connection, refused
	// ones included, is left out.
	v.Active = max(0, srv.Active.Load()-srv.UDPCtlActive.Load())
	v.Total = max(0, srv.Total.Load()-srv.UDPCtlTotal.Load())
	v.UDPServed = srv.UDP()
	v.UDPActive, v.UDPTotal, v.UDPDropped = udpActive, udpTotal, srv.UDPDropped.Load()
	if err := srv.UDPError(); err != nil {
		v.UDPError = fmt.Sprintf("UDP-порт %d не открылся: %v. TCP работает, UDP через этот прокси — нет (порт занят другой программой?). HyRoute пробует снова каждые 30 секунд.", v.Port, err)
	}
}

// proxyUDPBlocked says why the target cannot carry UDP now: "server" (the
// server does not allow UDP), "group" (no member can) or "". No lock held.
func (c *Controller) proxyUDPBlocked(s Session, id string) string {
	if groups.IsGroupID(id) {
		avail, udp := false, false
		for _, m := range c.groupsRT.Members(id) {
			if ep := s.Endpoint(m); ep != nil {
				avail = avail || ep.Available()
				udp = udp || ep.UDPAvailable()
			}
		}
		if avail && !udp {
			return "group"
		}
		return ""
	}
	if ep := s.Endpoint(id); ep != nil {
		if st := ep.Status(); st.State == hysteria.Connected && !st.UDPEnabled {
			return "server"
		}
	}
	return ""
}

// proxyUDPServer sets up a proxy's UDP side: served when the switch is on;
// a socket per session on this computer, the TCP port number shared by
// every session for a LAN proxy (its firewall rule stays exact). The owner
// check covers sessions from this computer on a proxy with a password
// (LAN proxies always have one).
func (c *Controller) proxyUDPServer(srv *localproxy.Server, p store.LocalProxy) {
	if p.UDPOn() {
		srv.AssociateUDP = c.proxyUDPDialer(p)
		srv.MaxUDP = localproxy.DefaultMaxUDP
		if p.LAN {
			srv.SharedUDP, srv.MaxUDP, srv.Owners = true, lanMaxUDP, proxyOwners
		} else if p.Username != "" {
			srv.Owners = proxyOwners
		}
	}
	srv.OnUDPLimit = func(n int64) {
		c.Log.Warn("local proxy UDP full: new associations refused", "name", p.Name, "port", p.Port, "limit", srv.MaxUDP, "refused", n)
	}
	srv.OnUDPEvent = func(ev localproxy.UDPEvent, n int64, size int) {
		if ev == localproxy.EventOwnerUnknown {
			c.Log.Warn("local proxy UDP: owner of the control connection not found", "name", p.Name, "port", p.Port, "count", n)
			return
		}
		c.Log.Warn("local proxy UDP", "name", p.Name, "port", p.Port, "event", string(ev), "count", n, "size", size)
	}
	srv.OnUDPPort = func(err error) {
		if err == nil {
			c.Log.Info("local proxy UDP port opened", "name", p.Name, "port", p.Port)
			return
		}
		c.Log.Warn("local proxy UDP socket not opened", "name", p.Name, "port", p.Port, "err", err)
	}
}

// proxyUDPDialer opens a proxy's UDP association through its server, or
// through one member of its group chosen once for the association
// (ChooseUDP). It never goes out directly.
func (c *Controller) proxyUDPDialer(p store.LocalProxy) localproxy.UDPDialer {
	return func(ctx context.Context) (localproxy.UDPUpstream, error) {
		c.mu.Lock()
		s := c.sess
		id := c.proxyProfileLocked(p)
		c.mu.Unlock()
		if s == nil {
			return nil, errors.New("HyRoute не подключён")
		}
		member, group, failover := id, "", false
		abandon := func() {} // every committed pick is used by a flow or abandoned
		if groups.IsGroupID(id) {
			pk, ok := c.groupsRT.ChooseUDP(id, groups.Hint{App: "proxy:" + p.ID}, func(m string) bool {
				ep := s.Endpoint(m)
				return ep != nil && ep.UDPAvailable()
			})
			if !ok {
				c.groupsRT.NoteRejected(id)
				c.proxyUDPFailed(p, refusedVia(pk, id), id, pk.Failover, "dropped: tunnel unavailable")
				c.warnProxyUDP(p, "local proxy: no server of the group can carry UDP", "group", c.profileName(id))
				return nil, socks5.ReplyError(1)
			}
			member, group, failover = pk.Member, id, pk.Failover
			abandon = func() { c.groupsRT.Abandon(pk) }
		}
		ep := s.Endpoint(member)
		if ep == nil {
			abandon()
			return nil, errors.New("сервер прокси не запущен")
		}
		if !ep.UDPAvailable() { // the member may have gone down since it was chosen
			abandon()
			ep.NoteRejected()
			c.proxyUDPFailed(p, member, group, failover, "dropped: tunnel unavailable")
			if ep.Available() {
				c.warnProxyUDP(p, "local proxy: server does not allow UDP", "server", ep.Profile.Name)
				return nil, socks5.ReplyError(2)
			}
			return nil, socks5.ReplyError(1)
		}
		a, err := ep.UDPAssociate(ctx) // reported to the group through the endpoint (dst "udp")
		if err != nil && (errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled) {
			abandon() // the proxy is closing: not a failure of the server, no record
			return nil, err
		}
		if err != nil {
			ep.NoteRejected()
			c.proxyUDPFailed(p, member, group, failover, "dropped: socks5 associate failed")
			c.warnProxyUDP(p, "local proxy: UDP association through the server failed", "err", err)
			return nil, err
		}
		// One statistics record per association: it has many destinations,
		// so the record has none.
		rec := c.proxyRecord(p, 17, socks5.Addr{}, member, group, failover, "proxied")
		return &tunnelUDP{a: a, ep: ep, rec: rec, fc: &flowCloser{rec: rec, reg: c.proxyFlows}}, nil
	}
}

// proxyUDPFailed records a refused UDP association of a local proxy: a
// record closed at once, which the statistics count as a failed connection
// (View.Failed). Not connected, no endpoint and a closing proxy leave none.
func (c *Controller) proxyUDPFailed(p store.LocalProxy, member, group string, failover bool, outcome string) {
	c.proxyFlows.Close(c.proxyRecord(p, 17, socks5.Addr{}, member, group, failover, outcome), time.Now())
}

// warnProxyUDP logs a UDP refusal at most once a minute per proxy and
// message.
func (c *Controller) warnProxyUDP(p store.LocalProxy, msg string, args ...any) {
	key := p.ID + "\x00" + msg
	now := time.Now()
	c.proxyWarnMu.Lock()
	if c.proxyWarned == nil {
		c.proxyWarned = map[string]time.Time{}
	}
	last, seen := c.proxyWarned[key]
	quiet := seen && now.Sub(last) < time.Minute
	if !quiet {
		c.proxyWarned[key] = now
	}
	c.proxyWarnMu.Unlock()
	if !quiet {
		c.Log.Warn(msg, append([]any{"name", p.Name}, args...)...)
	}
}

// tunnelUDP counts a proxy UDP association into its server's traffic and
// its statistics record (payload bytes), as tunnelConn does for TCP.
type tunnelUDP struct {
	a   *socks5.UDPAssoc
	ep  *tunnels.Endpoint
	rec *flows.Record
	fc  *flowCloser
}

func (t *tunnelUDP) WriteTo(b []byte, dst socks5.Addr) error {
	err := t.a.WriteTo(b, dst)
	if err == nil {
		t.ep.NoteTraffic(int64(len(b)), 0)
		t.rec.Sent.Add(int64(len(b)))
	}
	return err
}

func (t *tunnelUDP) ReadFrom(b []byte) (int, socks5.Addr, error) {
	n, from, err := t.a.ReadFrom(b)
	if err == nil {
		t.ep.NoteTraffic(0, int64(n))
		t.rec.Recv.Add(int64(n))
	}
	return n, from, err
}

// Close ends the association and, once, its record.
func (t *tunnelUDP) Close() error {
	t.fc.close()
	return t.a.Close()
}

// KeepV12ProxyUDP keeps UDP on for the LAN proxies of a v1.2.0 user: v1.2.0
// served UDP on every LAN proxy, enabled or not, and wrote no "udp" field,
// while a LAN proxy's default is now off. Its UDP firewall rule is the
// evidence (ours carry a mark, fwrule.LegacyProxyUDP); the first sync of a
// connection rewrites the rule, so this happens once. main calls it once
// after Load, before the window can show or edit a proxy, so the card and
// the editor show the real state from the start. Needs no connection.
func (c *Controller) KeepV12ProxyUDP() {
	if c.LegacyProxyUDP == nil {
		return
	}
	c.mu.Lock()
	if c.v12Checked || c.proxiesBroken != nil {
		c.mu.Unlock()
		return
	}
	c.v12Checked = true
	lan := false
	for _, p := range c.proxies {
		if p.UDP != "" { // written by this version: nothing of v1.2.0 left
			c.mu.Unlock()
			return
		}
		lan = lan || p.LAN
	}
	c.mu.Unlock()
	if !lan || !c.LegacyProxyUDP() { // netsh, outside the lock
		return
	}
	c.mu.Lock()
	next := append([]store.LocalProxy(nil), c.proxies...)
	var names []string
	for i := range next {
		if next[i].LAN && next[i].UDP == "" {
			next[i].UDP = "on"
			names = append(names, next[i].Name)
		}
	}
	if len(names) == 0 {
		c.mu.Unlock()
		return
	}
	err := c.saveProxiesLocked(next)
	c.mu.Unlock()
	if err != nil {
		c.Log.Error("local proxies: UDP of v1.2.0 not kept", "err", err)
		return
	}
	c.Log.Info("local proxies: UDP stays on for LAN proxies set up in v1.2.0", "names", strings.Join(names, ", "))
	c.changed()
}

// proxyUDPDiag is the UDP part of a proxy's diagnostics line (no
// addresses).
func proxyUDPDiag(p ProxyView) string {
	mode := "выкл"
	switch {
	case p.UDPError != "":
		mode = "ошибка"
	case p.UDPEffective && p.LAN:
		mode = "вкл, проверка программы для этого ПК"
	case p.UDPEffective && p.Username != "":
		mode = "вкл, проверка программы"
	case p.UDPEffective:
		mode = "вкл"
	}
	return fmt.Sprintf(", UDP %s, UDP-сессий %d, отброшено UDP %d%s", mode, p.UDPTotal, p.UDPDropped, msgSuffix(p.UDPError))
}
