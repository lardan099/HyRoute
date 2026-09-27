//go:build windows

package divert

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UINT64 arguments are passed in single registers: 64-bit Windows only.
const _ = uint(unsafe.Sizeof(uintptr(0)) - 8)

var (
	dllMu     sync.Mutex
	dllLoaded bool

	// Set once, by the first Load that succeeds.
	procOpen, procRecvEx, procSendEx, procShutdown, procClose, procSetParam, procGetParam *windows.LazyProc
)

// Load loads WinDivert.dll from dir (the directory of HyRoute.exe). An
// absolute path avoids DLL search-order hijacking; the DLL in turn finds
// WinDivert64.sys next to itself. A failure is not remembered: an
// antivirus may block the file for a while, and the next Connect tries
// again.
func Load(dir string) error {
	dllMu.Lock()
	defer dllMu.Unlock()
	if dllLoaded {
		return nil
	}
	path := filepath.Join(dir, "WinDivert.dll")
	dll := windows.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	procs := []*windows.LazyProc{
		dll.NewProc("WinDivertOpen"),
		dll.NewProc("WinDivertRecvEx"),
		dll.NewProc("WinDivertSendEx"),
		dll.NewProc("WinDivertShutdown"),
		dll.NewProc("WinDivertClose"),
		dll.NewProc("WinDivertSetParam"),
		dll.NewProc("WinDivertGetParam"),
	}
	for _, p := range procs {
		if err := p.Find(); err != nil {
			// Not the WinDivert we ship: unload it, or LoadLibrary would
			// hand the next Load this module even after the file is fixed.
			windows.FreeLibrary(windows.Handle(dll.Handle()))
			return err
		}
	}
	procOpen, procRecvEx, procSendEx, procShutdown, procClose, procSetParam, procGetParam =
		procs[0], procs[1], procs[2], procs[3], procs[4], procs[5], procs[6]
	dllLoaded = true
	return nil
}

// OpenError carries the Windows error code of a failed WinDivertOpen.
type OpenError struct {
	Code  uint32
	Layer Layer
}

func (e *OpenError) Error() string {
	return fmt.Sprintf("WinDivertOpen(layer %d): error %d", e.Layer, e.Code)
}

// Handle is an open WinDivert handle.
type Handle struct {
	h      uintptr
	mu     sync.Mutex
	closed bool
}

// Open opens a handle. Load must have been called.
func Open(filter string, layer Layer, priority int16, flags uint64) (*Handle, error) {
	if procOpen == nil {
		return nil, errors.New("divert: WinDivert.dll not loaded")
	}
	f, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r, _, e := procOpen.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), uintptr(int64(priority)), uintptr(flags))
	if r == uintptr(windows.InvalidHandle) {
		code := uint32(0)
		if en, ok := e.(windows.Errno); ok {
			code = uint32(en)
		}
		return nil, &OpenError{Code: code, Layer: layer}
	}
	return &Handle{h: r}, nil
}

// RecvEx receives up to len(addrs) packets into buf. It returns the bytes
// used in buf and the number of addresses filled.
func (h *Handle) RecvEx(buf []byte, addrs []Address) (int, int, error) {
	var recvLen uint32
	addrLen := uint32(len(addrs) * AddressSize)
	r, _, e := procRecvEx.Call(h.h,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)), 0,
		uintptr(unsafe.Pointer(&addrs[0])), uintptr(unsafe.Pointer(&addrLen)), 0)
	if r == 0 {
		return 0, 0, e
	}
	return int(recvLen), int(addrLen) / AddressSize, nil
}

// Recv receives a single packet or event.
func (h *Handle) Recv(buf []byte, addr *Address) (int, error) {
	var recvLen uint32
	addrLen := uint32(AddressSize)
	var bp uintptr
	if len(buf) > 0 {
		bp = uintptr(unsafe.Pointer(&buf[0]))
	}
	r, _, e := procRecvEx.Call(h.h, bp, uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)), 0,
		uintptr(unsafe.Pointer(addr)), uintptr(unsafe.Pointer(&addrLen)), 0)
	if r == 0 {
		return 0, e
	}
	return int(recvLen), nil
}

// Send injects one packet.
func (h *Handle) Send(pkt []byte, addr *Address) error {
	var sent uint32
	r, _, e := procSendEx.Call(h.h,
		uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sent)), 0,
		uintptr(unsafe.Pointer(addr)), uintptr(AddressSize), 0)
	if r == 0 {
		return e
	}
	return nil
}

// Shutdown stops receiving and/or sending; blocked Recv calls return.
func (h *Handle) Shutdown(how Shutdown) error {
	r, _, e := procShutdown.Call(h.h, uintptr(how))
	if r == 0 {
		return e
	}
	return nil
}

// Close closes the handle; the filter is removed from the kernel at once.
func (h *Handle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	r, _, e := procClose.Call(h.h)
	if r == 0 {
		return e
	}
	return nil
}

func (h *Handle) SetParam(p Param, v uint64) error {
	r, _, e := procSetParam.Call(h.h, uintptr(p), uintptr(v))
	if r == 0 {
		return e
	}
	return nil
}

func (h *Handle) GetParam(p Param) (uint64, error) {
	var v uint64
	r, _, e := procGetParam.Call(h.h, uintptr(p), uintptr(unsafe.Pointer(&v)))
	if r == 0 {
		return 0, e
	}
	return v, nil
}
