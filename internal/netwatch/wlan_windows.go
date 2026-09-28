//go:build windows

package netwatch

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/netmode"
)

var (
	modwlanapi             = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = modwlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modwlanapi.NewProc("WlanCloseHandle")
	procWlanQueryInterface = modwlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = modwlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanClientVersion        = 2
	wlanOpcodeCurrentConnect = 7 // wlan_intf_opcode_current_connection
	errServiceNotActive      = syscall.Errno(1062)
	errInvalidState          = syscall.Errno(5023)
	errNotFound              = syscall.Errno(1168)
	errNotSupported          = syscall.Errno(50)
)

// querySSID is the Wi-Fi name of adapter adapterGUID now: "" when it is not
// connected to Wi-Fi or the WLAN service is absent; netmode.ErrSSIDDenied
// when Windows refuses it (location privacy). The handle is opened per
// call: calls are rare.
func querySSID(adapterGUID string) (string, error) {
	if modwlanapi.Load() != nil {
		return "", nil // no WLAN on this system
	}
	g, err := windows.GUIDFromString(adapterGUID)
	if err != nil {
		return "", nil
	}
	var ver uint32
	var h windows.Handle
	r, _, _ := procWlanOpenHandle.Call(wlanClientVersion, 0, uintptr(unsafe.Pointer(&ver)), uintptr(unsafe.Pointer(&h)))
	switch e := syscall.Errno(r); {
	case r == 0:
	case e == errServiceNotActive:
		return "", nil
	case e == windows.ERROR_ACCESS_DENIED:
		return "", netmode.ErrSSIDDenied
	default:
		return "", e
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	var size uint32
	var data unsafe.Pointer
	r, _, _ = procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), wlanOpcodeCurrentConnect, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
	switch e := syscall.Errno(r); {
	case r == 0:
	case e == windows.ERROR_ACCESS_DENIED:
		return "", netmode.ErrSSIDDenied
	case e == errInvalidState, e == errNotFound, e == errNotSupported, e == windows.ERROR_INVALID_PARAMETER:
		return "", nil // not connected to Wi-Fi, or not a Wi-Fi adapter
	default:
		return "", e
	}
	if data == nil {
		return "", nil
	}
	defer procWlanFreeMemory.Call(uintptr(data))
	ssid, ok := parseConnectionAttributes(unsafe.Slice((*byte)(data), size))
	if !ok {
		return "", nil
	}
	return netmode.SSIDString(ssid), nil
}
