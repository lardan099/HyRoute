//go:build windows

package engine

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/sysdns"
)

// systemDNS answers Core.SystemDNS from the DNS servers of the adapters
// that are up. The list is read again when an address is not on it and
// the last read is older than sysDNSRefresh (a network change), so only
// the rare Dnscache connection to port 443 or 853 pays for it.
type systemDNS struct {
	mu   sync.Mutex
	at   time.Time
	list map[netip.Addr]bool
}

const sysDNSRefresh = 5 * time.Second

func (s *systemDNS) Has(a netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.list[a] {
		return true
	}
	if time.Since(s.at) < sysDNSRefresh {
		return false
	}
	s.at = time.Now()
	if l, err := sysdns.Servers(); err == nil {
		s.list = l
	}
	return s.list[a]
}

// ipv4Route answers Core.IPv4Route from the routing table (read at most
// every sysDNSRefresh): only an IPv6 connection that may go through the
// tunnel pays for it.
type ipv4Route struct {
	mu sync.Mutex
	at time.Time
	ok bool
}

func (r *ipv4Route) Has() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.at.IsZero() && time.Since(r.at) < sysDNSRefresh {
		return r.ok
	}
	r.at = time.Now()
	// Any public address: the best interface for it is the default
	// route's. Only the table is read, nothing is sent.
	var idx uint32
	r.ok = windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &idx) == nil
	return r.ok
}
