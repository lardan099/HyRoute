package monitor

import (
	"context"
	"net"
	"time"
)

// anycast are well-known public anycast addresses (Cloudflare, Google and
// Quad9 resolvers, IPv4 and IPv6): when the controller reaches none of
// them, it is its own network that is down.
var anycast = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443", "[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}

// onlineTimeout bounds the check: a controller with network connects in
// well under a second.
const onlineTimeout = 3 * time.Second

// Online reports whether the controller reaches the internet: a TCP
// connection to any of the anycast addresses within 3 s, nothing sent.
// The collector asks it only when no server of a round answered (main
// sets it; tests never use it).
func Online(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, onlineTimeout)
	defer cancel()
	ok := make(chan bool, len(anycast))
	for _, addr := range anycast {
		go func() {
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
			}
			ok <- err == nil
		}()
	}
	for range anycast {
		if <-ok {
			return true
		}
	}
	return false
}
