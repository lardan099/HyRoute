package app

import (
	"context"
	"net"
	"net/http"
	"time"
)

// HyRoute resolves its own hosts through the Windows API, so a lookup comes
// from the Windows DNS client like anyone's (dns). Every direct connection
// HyRoute opens itself registers its host first as HyRoute's own name for
// ownNameTTL: its lookup is passed on as before, even when the rules send
// the name to a tunnel that is down (a new subscription while the VPN does
// not work). The names live in the controller (c.ownNames), not in a
// session: a fetch that starts before or while a session starts is covered
// as soon as its filters are. A new direct HTTP client must use
// directTransport, http.DefaultTransport or OwnDial, or its host is judged
// by the rules.

// ownDial is OwnDial's dialer: net.Dialer with the defaults of
// http.DefaultTransport (a variable for tests).
var ownDial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext

// OwnDial dials addr after registering its host as HyRoute's own name, so
// the lookup that follows is passed on by any session's DNS policy. IP
// literals are not registered. It never takes c.mu: fetches run outside
// it.
func (c *Controller) OwnDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.passOwnName(addr)
	return ownDial(ctx, network, addr)
}

// passOwnName registers the host of addr (host:port or a bare host).
func (c *Controller) passOwnName(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	c.ownNames.Add(host, ownNameTTL)
}

// InstallOwnDial routes every direct HTTP client of HyRoute through
// OwnDial: the app's directTransport (subscriptions, geodata) and
// http.DefaultTransport (release checks and downloads, geodata's
// defaultClient, runtimefiles). Not concurrency-safe: main calls it once,
// before anything fetches.
func (c *Controller) InstallOwnDial() {
	directTransport.DialContext = c.OwnDial
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t = t.Clone()
		t.DialContext = c.OwnDial
		http.DefaultTransport = t
	}
}
