//go:build windows

package netwatch

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/netmode"
)

// Watcher reads the networks Windows is connected to. New only allocates:
// no thread, no COM, no registration until a method is called.
type Watcher struct {
	nlm *worker[*nlmConn, struct{}, map[string]nlmNet]
}

// New makes a Watcher.
func New() *Watcher { return &Watcher{nlm: newNLMWorker()} }

// Snapshot reads the networks Windows is connected to. wantSSID asks the
// WLAN API for the Wi-Fi name of the active network (on Windows 11 24H2
// each such query counts as location use, so the controller asks only
// while a new network settles, on a fresh page read and for «Текущее»).
// The NLM part is bounded by its worker's timeout (3 s to be taken while
// another caller's read runs, 3 s to answer): 6 s at worst; the registry,
// the neighbour table and WLAN answer at once on a healthy system (the
// start decision may wait for two reads plus netConfirm). Nothing is sent
// on the network.
func (w *Watcher) Snapshot(wantSSID bool) (netmode.Snapshot, error) {
	var snap netmode.Snapshot
	ads, err := adapters()
	if err != nil {
		return snap, err
	}
	idx, _ := bestIndex()
	active := bestNetwork(ads, idx)
	nets, nlmErr := w.nlm.Do(struct{}{})
	if nlmErr != nil {
		snap.Err = "сведения о сети от Windows (NLM): " + nlmErr.Error()
		snap.NLMDown = w.nlm.Down()
	}
	var sigErr error
	for i := range ads {
		a := &ads[i]
		n := netmode.Network{Adapter: adapterKind(a.ifType), AdapterName: a.name, AdapterID: a.guid}
		info, known := nets[strings.ToUpper(a.guid)]
		if known {
			n.ID, n.Name, n.Category = info.id, info.name, info.cat
		}
		if a != active {
			if known { // connected by NLM's account
				snap.Others = append(snap.Others, n)
			}
			continue
		}
		v4, v6 := splitGateways(a.gateways)
		n.GatewayIP = pickGateway(v4, v6)
		if gw, err := netip.ParseAddr(n.GatewayIP); err == nil {
			ifIndex := a.ifIndex
			if gw.Is6() {
				ifIndex = a.ipv6IfIndex
			}
			n.GatewayMAC = gatewayMAC(gw, ifIndex)
		}
		if n.ID != "" {
			ok, err := identified(n.ID, n.Category)
			n.Identified = ok
			sigErr = err
		}
		if wantSSID && n.Adapter == netmode.WiFi {
			switch s, err := querySSID(n.AdapterID); {
			case err == netmode.ErrSSIDDenied:
				n.SSIDDenied = true
			case err != nil:
				snap.Err = joinErr(snap.Err, "имя Wi-Fi: "+err.Error())
			default:
				n.SSID = s
			}
		}
		snap.Active = &n
	}
	if sigErr != nil {
		snap.Err = joinErr(snap.Err, "Не удалось проверить, опознала ли Windows сеть")
	}
	return snap, nil
}

// SSID asks the WLAN API now for one adapter ("" + nil when it is not
// connected to Wi-Fi); netmode.ErrSSIDDenied when Windows refuses.
func (w *Watcher) SSID(adapterID string) (string, error) { return querySSID(adapterID) }

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// adapters lists the interfaces that are up (loopback left out) with their
// gateways.
func adapters() ([]adapter, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_INCLUDE_GATEWAYS
	size := uint32(16 << 10)
	for tries := 0; ; tries++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW && tries < 5 {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []adapter
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.IfType == ifTypeLoopback {
				continue
			}
			ad := adapter{ifIndex: a.IfIndex, ipv6IfIndex: a.Ipv6IfIndex, ifType: a.IfType,
				guid: strings.ToUpper(windows.BytePtrToString(a.AdapterName)), name: windows.UTF16PtrToString(a.FriendlyName)}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				if ip, ok := netip.AddrFromSlice(g.Address.IP()); ok {
					ad.gateways = append(ad.gateways, ip.Unmap())
				}
			}
			out = append(out, ad)
		}
		return out, nil
	}
}

// bestIndex is the interface Windows would use for the internet: the best
// route to 1.1.1.1, else to 2606:4700:4700::1111. No packet is sent.
func bestIndex() (uint32, bool) {
	var idx uint32
	if windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &idx) == nil {
		return idx, true
	}
	v6 := &windows.SockaddrInet6{Addr: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	if windows.GetBestInterfaceEx(v6, &idx) == nil {
		return idx, true
	}
	return 0, false
}

// ---- change notifications ----

var (
	notifyOnce sync.Once
	notifyCB   uintptr
	// notifyCh is the channel of the current Watch (one at a time).
	notifyCh atomic.Pointer[chan struct{}]
)

// notify is the one callback of the three MIB notifications (the number of
// callbacks a process can make is limited): a non-blocking send only.
func notify(callerContext, row, notificationType uintptr) uintptr {
	if p := notifyCh.Load(); p != nil {
		select {
		case *p <- struct{}{}:
		default:
		}
	}
	return 0
}

// Watch reports interface, address and route changes (coalesced into a
// 1-buffered channel) until ctx ends.
func (w *Watcher) Watch(ctx context.Context) (<-chan struct{}, error) {
	notifyOnce.Do(func() { notifyCB = windows.NewCallback(notify) })
	ch := make(chan struct{}, 1)
	var handles []windows.Handle
	cancel := func() {
		for _, h := range handles {
			windows.CancelMibChangeNotify2(h)
		}
	}
	for _, reg := range []func(*windows.Handle) error{
		func(h *windows.Handle) error {
			return windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, notifyCB, nil, false, h)
		},
		func(h *windows.Handle) error {
			return windows.NotifyUnicastIpAddressChange(windows.AF_UNSPEC, notifyCB, nil, false, h)
		},
		func(h *windows.Handle) error {
			return windows.NotifyRouteChange2(windows.AF_UNSPEC, notifyCB, nil, false, h)
		},
	} {
		var h windows.Handle
		if err := reg(&h); err != nil {
			cancel()
			return nil, err
		}
		handles = append(handles, h)
	}
	notifyCh.Store(&ch)
	go func() {
		<-ctx.Done()
		cancel()
		notifyCh.CompareAndSwap(&ch, nil)
	}()
	return ch, nil
}
