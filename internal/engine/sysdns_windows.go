//go:build windows

package engine

import (
	"net/netip"
	"sync"
	"time"

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
