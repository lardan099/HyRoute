//go:build windows

package killswitch

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/sysdns"
)

// WFP errors (fwpmu.h).
const (
	errFilterNotFound   = syscall.Errno(0x80320003)
	errSublayerNotFound = syscall.Errno(0x80320007)
	errAlreadyExists    = syscall.Errno(0x80320009)
)

// Every object has a fixed GUID, so a later run (after a crash) finds and
// removes them without enumerating the system's filters.
var sublayerID = wf.SublayerID(windows.GUID{Data1: 0x7a1d4c62, Data2: 0x3b5e, Data3: 0x4f0a,
	Data4: [8]byte{0x9c, 0x21, 0x5e, 0x8d, 0x3f, 0x6a, 0x0b, 0x17}})

func ruleID(layer int, kind byte) wf.RuleID {
	return wf.RuleID(windows.GUID{Data1: 0x7a1d4c63, Data2: 0x3b5e, Data3: 0x4f0a,
		Data4: [8]byte{0x9c, 0x21, 0x5e, 0x8d, 0x3f, 0x6a, byte(layer), kind}})
}

const (
	kindBlock byte = iota + 1
	kindLoopback
	kindLAN
	kindPorts
	kindApps
	kindSecureDNS
	kindRelay
	kindPass byte = 0xf0
)

// blockKinds are the filters of the normal session: Release removes them
// all (the sublayer cannot go while one is left). Arm replaces the
// refreshedKinds every time (see exceptions.rules).
var (
	blockKinds     = []byte{kindBlock, kindLoopback, kindLAN, kindPorts, kindApps, kindSecureDNS, kindRelay}
	refreshedKinds = []byte{kindPorts, kindSecureDNS, kindApps, kindRelay}
)

// Weights inside the sublayer: the highest matching filter decides.
const (
	weightBlock     = 1
	weightException = 10
	// weightRelay: the relay's port is closed above the exception that
	// lets HyRoute through, and open under the pass.
	weightRelay = 15
	weightPass  = 20
)

var layers = []struct {
	id wf.LayerID
	v6 bool
}{
	{wf.LayerALEAuthConnectV4, false},
	{wf.LayerALEAuthConnectV6, true},
	{wf.LayerALEAuthRecvAcceptV4, false},
	{wf.LayerALEAuthRecvAcceptV6, true},
}

const name = "HyRoute kill switch"

// ownerName: the fixed GUIDs are shared by every HyRoute on the machine.
// Another one running at the same time in another Windows session (fast
// user switching) would remove this one's block with its Disconnect, so
// the first to use the filters owns them while it runs; the others leave
// them alone. The named object goes when its process exits.
const ownerName = `Global\HyRoute-kill-switch-7a1d4c62`

var owner struct {
	sync.Mutex
	h windows.Handle
}

var errNotOwner = errors.New("kill switch занят другим запущенным HyRoute (например, у другого пользователя Windows)")

// claim makes this process the owner of the filters, or reports that
// another HyRoute is.
func claim() error {
	owner.Lock()
	defer owner.Unlock()
	if owner.h != 0 {
		return nil
	}
	n, err := windows.UTF16PtrFromString(ownerName)
	if err != nil {
		return err
	}
	h, err := windows.CreateMutex(nil, false, n)
	switch {
	case err == nil:
		owner.h = h
		return nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		windows.CloseHandle(h)
		return errNotOwner
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// Another user's object we may not open, or no right to create
		// global objects; in the latter case there is none to find.
		o, oerr := windows.OpenMutex(windows.SYNCHRONIZE, false, n)
		if oerr == nil {
			windows.CloseHandle(o)
		}
		if errors.Is(oerr, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return errNotOwner
	}
	return fmt.Errorf("kill switch: %w", err)
}

// Switch installs and removes the filters. The zero value is ready.
type Switch struct {
	// Apps returns the programs the block lets through (full paths).
	Apps func() []string
	// Self is HyRoute's own program (full path, "" = unknown). Its relay's
	// port stays closed to other hosts while the block holds, although
	// Apps lets the program through (see Arm).
	Self string

	mu   sync.Mutex
	pass *wf.Session // dynamic session holding the pass filters
}

func open(dynamic bool) (*wf.Session, error) {
	s, err := wf.New(&wf.Options{Name: name, Dynamic: dynamic})
	if err != nil {
		return nil, fmt.Errorf("служба фильтрации Windows (BFE) недоступна: %w", err)
	}
	return s, nil
}

func (k *Switch) apps() []string {
	if k.Apps == nil {
		return nil
	}
	var ids []string
	seen := map[string]bool{}
	for _, p := range k.Apps() {
		id := appID(p)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

// appID is the app ID of the program at path p ("" if there is none: a
// file that does not exist has no app ID). The app ID is the file's NT
// path, and the kernel matches it against the long name: a short 8.3
// path (RUNNER~1) never matches.
func appID(p string) string {
	if p == "" {
		return ""
	}
	id, err := wf.AppID(longPath(p))
	if err != nil {
		return ""
	}
	return id
}

// serviceHost is the app ID of svchost.exe, which runs Windows' DNS and
// DHCP clients ("" if unknown).
func serviceHost() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	id, err := wf.AppID(filepath.Join(dir, "svchost.exe"))
	if err != nil {
		return ""
	}
	return id
}

// dnsServers lists the adapters' DNS servers in a stable order (none if
// unknown).
func dnsServers() []netip.Addr {
	m, err := sysdns.Servers()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// exceptions is what the filters Arm replaces every time depend on.
type exceptions struct {
	apps  []string     // app IDs let through (HyRoute, Hysteria)
	svc   string       // app ID of svchost.exe ("" if unknown)
	dns   []netip.Addr // the adapters' DNS servers
	self  string       // app ID of HyRoute.exe ("" if unknown)
	relay uint16       // the port the relay listens on (0: none)
}

// fixedRules are the filters of layer i that never change: loopback, the
// local network and the block itself.
func fixedRules(i int) []*wf.Rule {
	l := layers[i]
	var lan []*wf.Match
	for _, p := range LAN {
		if p.Addr().Is6() == l.v6 {
			lan = append(lan, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: p})
		}
	}
	rules := []*wf.Rule{
		{ID: ruleID(i, kindLoopback), Name: name + ": loopback", Weight: weightException, Action: wf.ActionPermit,
			Conditions: []*wf.Match{{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback}}},
		{ID: ruleID(i, kindLAN), Name: name + ": local network", Weight: weightException, Action: wf.ActionPermit, Conditions: lan},
		{ID: ruleID(i, kindBlock), Name: name + ": block", Weight: weightBlock, Action: wf.ActionBlock},
	}
	for _, r := range rules {
		r.Layer, r.Sublayer = l.id, sublayerID
	}
	return rules
}

// rules are the filters of layer i Arm replaces every time: the app list
// may change (a Hysteria update moves hysteria.exe), so may the DNS
// servers and the relay's port, and a block an older version left has its
// ports open to every program.
func (e exceptions) rules(i int) []*wf.Rule {
	l := layers[i]
	// Only Windows' own DNS and DHCP clients get through on their ports:
	// another program could reach any server on port 53. Without the app
	// ID the ports stay open to all, as in versions before.
	var ports []*wf.Match
	for _, p := range Ports {
		ports = append(ports, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: p})
	}
	if e.svc != "" {
		ports = append(ports, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: e.svc})
	}
	rules := []*wf.Rule{{ID: ruleID(i, kindPorts), Name: name + ": DNS and DHCP", Weight: weightException,
		Action: wf.ActionPermit, Conditions: ports}}
	// With encrypted DNS only (DoH, DoT) the DNS client resolves nothing
	// on port 53, and HyRoute could not find its servers to reconnect: the
	// client also reaches the adapters' DNS servers on the ports of DoH
	// and DoT (only the client, and only these servers).
	var dns []*wf.Match
	for _, a := range e.dns {
		if a.Is6() == l.v6 {
			dns = append(dns, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: a})
		}
	}
	if e.svc != "" && len(dns) > 0 {
		m := []*wf.Match{
			{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: e.svc},
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
		}
		for _, p := range SecureDNSPorts {
			m = append(m, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: p})
		}
		rules = append(rules, &wf.Rule{ID: ruleID(i, kindSecureDNS), Name: name + ": encrypted DNS", Weight: weightException,
			Action: wf.ActionPermit, Conditions: append(m, dns...)})
	}
	if r := appsRule(i, e.apps); r != nil {
		rules = append(rules, r)
	}
	// The relay's connections have the real remote hosts for peers (the
	// engine reflects them): once the engine is gone, whatever their
	// sockets still send (FIN, retransmissions, a keepalive after a
	// crash) would reach those hosts directly past the block, since
	// HyRoute gets through. Loopback is left open.
	if e.self != "" && e.relay != 0 {
		rules = append(rules, &wf.Rule{ID: ruleID(i, kindRelay), Name: name + ": HyRoute relay port", Weight: weightRelay,
			Action: wf.ActionBlock, Conditions: []*wf.Match{
				{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: e.relay},
				{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: e.self},
				{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsNoneSet, Value: wf.ConditionFlagIsLoopback},
			}})
	}
	for _, r := range rules {
		r.Layer, r.Sublayer = l.id, sublayerID
	}
	return rules
}

// appsRule lets HyRoute's programs through on layer i (nil: none known).
func appsRule(i int, apps []string) *wf.Rule {
	if len(apps) == 0 {
		return nil
	}
	var am []*wf.Match
	for _, id := range apps {
		am = append(am, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: id})
	}
	return &wf.Rule{ID: ruleID(i, kindApps), Name: name + ": HyRoute and Hysteria", Layer: layers[i].id, Sublayer: sublayerID,
		Weight: weightException, Action: wf.ActionPermit, Conditions: am}
}

// Arm is called when the packet engine is up: it adds the pass filters,
// then installs the block and its exceptions (idempotent; the app list,
// the DNS servers and the relay's port are refreshed). relay is the port
// the session's relay listens on (0: none).
func (k *Switch) Arm(relay uint16) error {
	if err := claim(); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := open(false)
	if err != nil {
		return err
	}
	defer s.Close()
	err = s.AddSublayer(&wf.Sublayer{ID: sublayerID, Name: name,
		Description: "Blocks the internet while HyRoute's routing is down", Weight: math.MaxUint16})
	if err != nil && !errors.Is(err, errAlreadyExists) {
		return fmt.Errorf("kill switch: sublayer: %w", err)
	}
	if err := k.setPassLocked(true); err != nil {
		return err
	}
	e := exceptions{apps: k.apps(), svc: serviceHost(), dns: dnsServers(), self: appID(k.Self), relay: relay}
	for i := range layers {
		for _, r := range fixedRules(i) {
			if err := s.AddRule(r); err != nil && !errors.Is(err, errAlreadyExists) {
				return fmt.Errorf("kill switch: %s: %w", r.Name, err)
			}
		}
		for _, kind := range refreshedKinds {
			if err := s.DeleteRule(ruleID(i, kind)); err != nil && !errors.Is(err, errFilterNotFound) {
				return fmt.Errorf("kill switch: %w", err)
			}
		}
		for _, r := range e.rules(i) {
			if err := s.AddRule(r); err != nil {
				return fmt.Errorf("kill switch: %s: %w", r.Name, err)
			}
		}
	}
	return nil
}

// RefreshApps renews the program exceptions of an installed block (a
// Hysteria core update or rollback moves hysteria.exe); the pass filters
// stay as they are.
func (k *Switch) RefreshApps() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := open(false)
	if err != nil {
		return err
	}
	defer s.Close()
	apps := k.apps()
	for i := range layers {
		if err := s.DeleteRule(ruleID(i, kindApps)); err != nil && !errors.Is(err, errFilterNotFound) {
			return fmt.Errorf("kill switch: %w", err)
		}
		r := appsRule(i, apps)
		if r == nil {
			continue
		}
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("kill switch: %s: %w", r.Name, err)
		}
	}
	return nil
}

// Close removes the pass filters: the block takes effect. Called when the
// packet engine fails; a dying process closes them the same way.
func (k *Switch) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.setPassLocked(false)
}

// The pass filters live in a dynamic session: Windows removes them when
// the session closes, including when the process dies.

func (k *Switch) setPassLocked(on bool) error {
	if !on {
		if k.pass == nil {
			return nil
		}
		err := k.pass.Close()
		k.pass = nil
		return err
	}
	if k.pass != nil {
		return nil
	}
	s, err := open(true)
	if err != nil {
		return err
	}
	for i := range layers {
		if err := s.AddRule(passRule(i)); err != nil {
			s.Close()
			return fmt.Errorf("kill switch: %w", err)
		}
	}
	k.pass = s
	return nil
}

func passRule(i int) *wf.Rule {
	return &wf.Rule{ID: ruleID(i, kindPass), Name: name + ": routing is up", Layer: layers[i].id, Sublayer: sublayerID,
		Weight: weightPass, Action: wf.ActionPermit}
}

// Release removes everything: the internet opens.
func (k *Switch) Release() error {
	if err := claim(); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := open(false)
	if err != nil {
		return err
	}
	defer s.Close()
	var errs []error
	for i := range layers {
		for _, kind := range blockKinds {
			if err := s.DeleteRule(ruleID(i, kind)); err != nil && !errors.Is(err, errFilterNotFound) {
				errs = append(errs, err)
			}
		}
	}
	k.setPassLocked(false)
	if err := s.DeleteSublayer(sublayerID); err != nil && !errors.Is(err, errSublayerNotFound) {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("kill switch: не все фильтры удалены: %w", errors.Join(errs...))
	}
	return nil
}

// Engaged reports whether the block is installed (possibly left by a
// previous run that crashed).
func (k *Switch) Engaged() (bool, error) {
	if err := claim(); err != nil {
		return false, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return installed()
}

func installed() (bool, error) {
	s, err := open(false)
	if err != nil {
		return false, err
	}
	defer s.Close()
	subs, err := s.Sublayers()
	if err != nil {
		return false, err
	}
	for _, sl := range subs {
		if sl.ID == sublayerID {
			return true, nil
		}
	}
	return false, nil
}

// Leftover reports whether the block is installed while no HyRoute runs
// to look after it: a run ended without Disconnect (a crash) and a
// shutdown with Fast Startup kept the filters. Unlike Engaged it takes
// nothing over, so a check at sign-in can end its process at once.
func Leftover() (bool, error) {
	n, err := windows.UTF16PtrFromString(ownerName)
	if err != nil {
		return false, err
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, n)
	switch {
	case err == nil:
		windows.CloseHandle(h)
		return false, nil // a running HyRoute shows its block itself
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return false, nil // one of another user's
	case !errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return false, fmt.Errorf("kill switch: %w", err)
	}
	return installed()
}

var procGetSystemMetrics = windows.NewLazySystemDLL("user32.dll").NewProc("GetSystemMetrics")

// SessionEnding reports that Windows is ending the session: shutting
// down, restarting or signing out.
func SessionEnding() bool {
	const smShuttingDown = 0x2000
	r, _, _ := procGetSystemMetrics.Call(smShuttingDown)
	return r != 0
}

func longPath(p string) string {
	short, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}
