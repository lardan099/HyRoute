//go:build windows

package netwatch

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Network List Manager (netlistmgr.h) through its vtables: the methods
// used take GUIDs and out pointers, which IDispatch does not carry. The
// indices count IUnknown (0–2) and IDispatch (3–6) first.
const (
	nlmGetNetworkConnections = 9 // INetworkListManager::GetNetworkConnections(IEnumNetworkConnections**)
	enumNext                 = 8 // IEnumNetworkConnections::Next(ULONG, INetworkConnection**, ULONG*)
	connGetNetwork           = 7 // INetworkConnection::GetNetwork(INetwork**)
	connIsConnected          = 9 // INetworkConnection::get_IsConnected(VARIANT_BOOL*)
	connGetAdapterID         = 12
	netGetName               = 7  // INetwork::GetName(BSTR*)
	netGetNetworkID          = 11 // INetwork::GetNetworkId(GUID*)
	netGetCategory           = 18 // INetwork::GetCategory(NLM_NETWORK_CATEGORY*)
	comRelease               = 2
)

var (
	clsidNetworkListManager = windows.GUID{Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B, Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
	iidINetworkListManager  = windows.GUID{Data1: 0xDCB00000, Data2: 0x570F, Data3: 0x4A9B, Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}

	modole32             = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = modole32.NewProc("CoCreateInstance")
	modoleaut32          = windows.NewLazySystemDLL("oleaut32.dll")
	procSysFreeString    = modoleaut32.NewProc("SysFreeString")
)

// nlmNet is what NLM says about the network of one connected adapter.
type nlmNet struct {
	id, name, cat string
}

// nlmConn is a thread's NetworkListManager instance.
type nlmConn struct {
	mgr unsafe.Pointer
}

// newNLMWorker: NLM runs on a dedicated COM thread; a hung call is
// abandoned after 3 s, the thread exits after a minute without requests.
func newNLMWorker() *worker[*nlmConn, struct{}, map[string]nlmNet] {
	return &worker[*nlmConn, struct{}, map[string]nlmNet]{
		open:         nlmOpen,
		call:         nlmCall,
		close:        nlmClose,
		timeout:      3 * time.Second,
		idle:         time.Minute,
		maxAbandoned: 3,
		lockThread:   true,
		timeoutErr:   errors.New("NLM не отвечает"),
	}
}

func hresultFailed(r uintptr) bool { return int32(r) < 0 }

// comCall calls method idx of the COM object obj. The callers pass out
// pointers converted to uintptr in the call: uintptrescapes moves what
// they point to to the heap and keeps it alive for the call (as
// LazyProc.Call does), so a stack copy while the method runs cannot leave
// COM writing into freed stack memory.
//
//go:uintptrescapes
func comCall(obj unsafe.Pointer, idx int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

func comReleaseObj(obj unsafe.Pointer) {
	if obj != nil {
		comCall(obj, comRelease)
	}
}

func nlmOpen() (*nlmConn, error) {
	// A new thread: S_FALSE (1) would mean COM was up already.
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil && err != syscall.Errno(1) {
		return nil, fmt.Errorf("COM: %w", err)
	}
	const clsctxAll = 0x17
	var mgr unsafe.Pointer
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNetworkListManager)), 0, clsctxAll,
		uintptr(unsafe.Pointer(&iidINetworkListManager)), uintptr(unsafe.Pointer(&mgr)))
	if hresultFailed(r) || mgr == nil {
		windows.CoUninitialize()
		return nil, fmt.Errorf("NetworkListManager: 0x%08X", uint32(r))
	}
	return &nlmConn{mgr: mgr}, nil
}

func nlmClose(c *nlmConn) {
	comReleaseObj(c.mgr)
	windows.CoUninitialize()
}

// nlmCall maps each connected adapter (GUID, upper-case) to its network.
func nlmCall(c *nlmConn, _ struct{}) (map[string]nlmNet, error) {
	var enum unsafe.Pointer
	if r := comCall(c.mgr, nlmGetNetworkConnections, uintptr(unsafe.Pointer(&enum))); hresultFailed(r) || enum == nil {
		return nil, fmt.Errorf("GetNetworkConnections: 0x%08X", uint32(r))
	}
	defer comReleaseObj(enum)
	out := map[string]nlmNet{}
	for i := 0; i < 256; i++ {
		var conn unsafe.Pointer
		var fetched uint32
		r := comCall(enum, enumNext, 1, uintptr(unsafe.Pointer(&conn)), uintptr(unsafe.Pointer(&fetched)))
		if r != 0 || fetched == 0 || conn == nil { // S_FALSE: no more
			if conn != nil {
				comReleaseObj(conn)
			}
			break
		}
		if ad, n, ok := nlmConnection(conn); ok {
			if _, dup := out[ad]; !dup {
				out[ad] = n
			}
		}
		comReleaseObj(conn)
	}
	return out, nil
}

// nlmConnection reads one INetworkConnection (released by the caller).
func nlmConnection(conn unsafe.Pointer) (adapter string, n nlmNet, ok bool) {
	var connected int16 // VARIANT_BOOL
	if r := comCall(conn, connIsConnected, uintptr(unsafe.Pointer(&connected))); hresultFailed(r) || connected == 0 {
		return "", n, false
	}
	var ad windows.GUID
	if r := comCall(conn, connGetAdapterID, uintptr(unsafe.Pointer(&ad))); hresultFailed(r) {
		return "", n, false
	}
	var net unsafe.Pointer
	if r := comCall(conn, connGetNetwork, uintptr(unsafe.Pointer(&net))); hresultFailed(r) || net == nil {
		return "", n, false
	}
	defer comReleaseObj(net)
	var id windows.GUID
	if r := comCall(net, netGetNetworkID, uintptr(unsafe.Pointer(&id))); !hresultFailed(r) {
		n.id = guidString(id.Data1, id.Data2, id.Data3, id.Data4)
	}
	var name *uint16 // BSTR
	if r := comCall(net, netGetName, uintptr(unsafe.Pointer(&name))); !hresultFailed(r) && name != nil {
		n.name = windows.UTF16PtrToString(name)
		procSysFreeString.Call(uintptr(unsafe.Pointer(name)))
	}
	var cat int32
	if r := comCall(net, netGetCategory, uintptr(unsafe.Pointer(&cat))); !hresultFailed(r) {
		n.cat = categoryName(uint32(cat))
	}
	return strings.ToUpper(guidString(ad.Data1, ad.Data2, ad.Data3, ad.Data4)), n, true
}
