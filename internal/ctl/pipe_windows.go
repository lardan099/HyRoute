//go:build windows

package ctl

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The named pipe transport. The server side is HyRoute (elevated); the
// client is hyroutectl (the user's rights). Hand-written overlapped I/O is
// only ConnectNamedPipe on a handle not yet associated with the runtime:
// once connected, the handle goes to os.NewFile (Go ≥ 1.24 associates an
// overlapped handle with the runtime's I/O completion port, with
// deadlines, and Close cancels pending I/O).

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	procWaitNamedPipeW             = kernel32.NewProc("WaitNamedPipeW")
	// testAfterOverlappedResult (tests) runs when a cancelled
	// ConnectNamedPipe has completed, before its memory could go.
	testAfterOverlappedResult func()
)

const userRW = 0x12019b

// userRW (0x12019b) = FILE_GENERIC_READ | FILE_GENERIC_WRITE without
// FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE, 0x4): a user may connect
// and talk, never create an instance of the pipe.

// ListenConfig describes the server's pipe.
type ListenConfig struct {
	Name string
	// Users get read/write (no FILE_CREATE_PIPE_INSTANCE); SYSTEM and
	// Administrators full access. One or two SIDs (owner, token user).
	Users []*windows.SID
	// Owner is the SD owner: nil = BUILTIN\Administrators (production; the
	// process is elevated, BA is an assignable owner in its token). Tests pass
	// the current user's SID: always assignable, elevated or not. Owner
	// rights are neutralised by (A;;RC;;;OW).
	Owner *windows.SID
	// FullAccess get GA (incl. FILE_CREATE_PIPE_INSTANCE, which the server
	// itself needs for every later instance) besides SYSTEM and
	// Administrators. Tests add Authenticated Users so an unelevated test
	// server can create its later instances.
	FullAccess   []*windows.SID
	Allow        func(Identity) bool
	MaxInstances int // 8 when 0
}

// SDDL is the pipe's security descriptor.
func (cfg ListenConfig) SDDL() string {
	owner := "BA"
	if cfg.Owner != nil {
		owner = cfg.Owner.String()
	}
	var b strings.Builder
	b.WriteString("O:" + owner + "G:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, s := range cfg.FullAccess {
		b.WriteString("(A;;GA;;;" + s.String() + ")")
	}
	b.WriteString("(A;;RC;;;OW)")
	seen := map[string]bool{}
	for _, u := range cfg.Users {
		if u == nil || seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		fmt.Fprintf(&b, "(A;;0x%x;;;%s)", userRW, u.String())
	}
	b.WriteString("S:(ML;;NW;;;ME)")
	return b.String()
}

// Listener accepts clients of one pipe name.
type Listener struct {
	cfg      ListenConfig
	name     *uint16
	sa       *windows.SecurityAttributes
	owner    *windows.SID
	stop     windows.Handle // manual-reset: Close
	ev       windows.Handle // the pending ConnectNamedPipe's event
	ov       *windows.Overlapped
	acceptMu sync.Mutex // one Accept at a time; Close waits for it
	next     windows.Handle
	closed   atomic.Bool
}

// Listen creates the first instance of the pipe; a name another process
// holds is ErrNameTaken.
func Listen(cfg ListenConfig) (*Listener, error) {
	if cfg.MaxInstances <= 0 {
		cfg.MaxInstances = 8
	}
	if cfg.Allow == nil {
		return nil, errors.New("ctl: ListenConfig.Allow is required")
	}
	sd, err := windows.SecurityDescriptorFromString(cfg.SDDL())
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(cfg.Name)
	if err != nil {
		return nil, err
	}
	owner := cfg.Owner
	if owner == nil {
		if owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
			return nil, err
		}
	}
	l := &Listener{cfg: cfg, name: name, owner: owner,
		sa: &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}}
	h, err := l.create(true)
	if err != nil {
		return nil, err
	}
	l.next = h
	if l.stop, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if l.ev, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
		windows.CloseHandle(h)
		windows.CloseHandle(l.stop)
		return nil, err
	}
	// Heap memory owned by the listener: alive until the kernel is done
	// with a pending ConnectNamedPipe (Close waits for it).
	l.ov = &windows.Overlapped{HEvent: l.ev}
	return l, nil
}

// create makes an instance and checks it is ours: a later instance could
// otherwise join a pipe another process created after ours went away.
func (l *Listener) create(first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(l.name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		uint32(l.cfg.MaxInstances), 64<<10, 64<<10, 0, l.sa)
	if err != nil {
		if first && (errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY)) {
			return 0, ErrNameTaken
		}
		return 0, err
	}
	if o, err := handleOwner(h); err != nil || !o.Equals(l.owner) {
		windows.CloseHandle(h)
		return 0, ErrNameTaken
	}
	return h, nil
}

// Accept waits for the next client. allowed is cfg.Allow of its identity:
// the server, not the transport, tells a refused client why.
func (l *Listener) Accept() (net.Conn, Identity, bool, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	for {
		if l.closed.Load() {
			return nil, Identity{}, false, ErrClosed
		}
		if l.next == 0 {
			h, err := l.create(false)
			switch {
			case errors.Is(err, windows.ERROR_PIPE_BUSY):
				// Every instance is taken: wait for one to close.
				if l.sleep(200 * time.Millisecond) {
					return nil, Identity{}, false, ErrClosed
				}
				continue
			case err != nil:
				return nil, Identity{}, false, err
			}
			l.next = h
		}
		h := l.next
		connected, err := l.connect(h)
		if err != nil {
			return nil, Identity{}, false, err
		}
		if !connected {
			continue // the client left before we saw it: l.next was reset
		}
		l.next = 0
		// The next client finds an instance while this one is served.
		if nh, err := l.create(false); err == nil {
			l.next = nh
		}
		id := identify(h)
		f := os.NewFile(uintptr(h), l.cfg.Name)
		// A file in synchronous mode would have no deadlines: refuse.
		if f.SetDeadline(time.Time{}) != nil {
			f.Close()
			continue
		}
		return &fileConn{f: f, name: l.cfg.Name}, id, l.cfg.Allow(id), nil
	}
}

// connect waits for a client on h (ConnectNamedPipe with l.ov). false: the
// client went away at once (h was closed, l.next is 0).
func (l *Listener) connect(h windows.Handle) (bool, error) {
	windows.ResetEvent(l.ev)
	*l.ov = windows.Overlapped{HEvent: l.ev}
	err := windows.ConnectNamedPipe(h, l.ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return true, nil
	case errors.Is(err, windows.ERROR_NO_DATA):
		// Connected and closed before we looked: start over.
		windows.CloseHandle(h)
		l.next = 0
		return false, nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return false, err
	}
	ev, _ := windows.WaitForMultipleObjects([]windows.Handle{l.ev, l.stop}, false, windows.INFINITE)
	var n uint32
	if ev == windows.WAIT_OBJECT_0+1 {
		// Closing: cancel and wait for the kernel to let go of l.ov.
		windows.CancelIoEx(h, l.ov)
		windows.GetOverlappedResult(h, l.ov, &n, true)
		if testAfterOverlappedResult != nil {
			testAfterOverlappedResult()
		}
		windows.CloseHandle(h)
		l.next = 0
		return false, ErrClosed
	}
	if err := windows.GetOverlappedResult(h, l.ov, &n, false); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		windows.CloseHandle(h)
		l.next = 0
		if errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_BROKEN_PIPE) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// sleep waits d or until Close; true when closed.
func (l *Listener) sleep(d time.Duration) bool {
	ev, _ := windows.WaitForSingleObject(l.stop, uint32(d/time.Millisecond))
	return ev == windows.WAIT_OBJECT_0
}

// Close unblocks Accept at once; connections already accepted stay open.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	windows.SetEvent(l.stop)
	l.acceptMu.Lock()
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	windows.CloseHandle(l.ev)
	windows.CloseHandle(l.stop)
	l.acceptMu.Unlock()
	return nil
}

// identify reads the client's token by identification-level impersonation
// on a thread of its own. If RevertToSelf fails the thread is not unlocked:
// Go ends it, so no other code ever runs with the client's identity. Any
// failure is Identity{} (refused).
func identify(h windows.Handle) Identity {
	ch := make(chan Identity, 1)
	go func() {
		runtime.LockOSThread()
		id, ok := impersonated(h)
		ch <- id
		if ok {
			runtime.UnlockOSThread()
		}
	}()
	id := <-ch
	windows.GetNamedPipeClientProcessId(h, &id.PID)
	return id
}

// impersonated: ok is false when the thread could not revert.
func impersonated(h windows.Handle) (Identity, bool) {
	if r, _, _ := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		return Identity{}, true
	}
	var tok windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if windows.RevertToSelf() != nil {
		if err == nil {
			tok.Close()
		}
		return Identity{}, false
	}
	if err != nil {
		return Identity{}, true
	}
	defer tok.Close()
	return tokenIdentity(tok), true
}

// tokenIdentity reads what Allow needs from a token; Identity{} on any
// failure.
func tokenIdentity(tok windows.Token) Identity {
	u, err := tok.GetTokenUser()
	if err != nil {
		return Identity{}
	}
	rid, err := integrityRID(tok)
	if err != nil {
		return Identity{}
	}
	id := Identity{User: u.User.Sid.String(), IntegrityRID: rid, Elevated: tok.IsElevated()}
	id.System = id.User == "S-1-5-18"
	if gs, err := tok.GetTokenGroups(); err == nil {
		for _, g := range gs.AllGroups() {
			if g.Sid.String() == "S-1-5-32-544" && g.Attributes&windows.SE_GROUP_ENABLED != 0 &&
				g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
				id.Admin = true
			}
		}
	}
	return id
}

func integrityRID(tok windows.Token) (uint32, error) {
	n := uint32(64)
	for {
		buf := make([]byte, n)
		err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return 0, err
		}
		l := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
		// S-1-16-<RID>: parsed from the string form (SubAuthority's pointer
		// arithmetic into a Go buffer upsets checkptr).
		s := l.Label.Sid.String()
		i := strings.LastIndexByte(s, '-')
		rid, err := strconv.ParseUint(s[i+1:], 10, 32)
		if i < 0 || err != nil {
			return 0, errors.New("no integrity RID")
		}
		return uint32(rid), nil
	}
}

// handleOwner is the owner of a kernel object.
func handleOwner(h windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	o, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	return o.Copy()
}

// Trusted is who may own a genuine HyRoute pipe or run event:
// Administrators and SYSTEM (a process without admin rights cannot create
// an object owned by Administrators).
var Trusted = []string{"S-1-5-32-544", "S-1-5-18"}

// Dial connects to the pipe; the pipe's owner must be one of trusted (SID
// strings), else nothing is sent (ErrImpostor). A busy pipe is retried
// until timeout (ErrBusy). The server's PID comes back for
// AllowSetForegroundWindow.
func Dial(name string, timeout time.Duration, trusted []string) (net.Conn, uint32, error) {
	return dial(name, timeout, trusted, windows.SECURITY_IDENTIFICATION)
}

func dial(name string, timeout time.Duration, trusted []string, level uint32) (net.Conn, uint32, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, err
	}
	deadline := time.Now().Add(timeout)
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|level, 0)
		if err == nil {
			break
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, 0, ErrNotRunning
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, 0, ErrDenied
		case errors.Is(err, windows.ERROR_PIPE_BUSY):
			if !time.Now().Before(deadline) {
				return nil, 0, ErrBusy
			}
			procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(p)), 100)
			continue
		}
		return nil, 0, err
	}
	o, err := handleOwner(h)
	if err != nil || !trustedSID(o.String(), trusted) {
		windows.CloseHandle(h)
		return nil, 0, ErrImpostor
	}
	var pid uint32
	windows.GetNamedPipeServerProcessId(h, &pid)
	return &fileConn{f: os.NewFile(uintptr(h), name), name: name}, pid, nil
}

func trustedSID(s string, trusted []string) bool {
	for _, t := range trusted {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}

// FindPipes lists the SIDs of existing pipes named PipePrefix+SID.
func FindPipes() ([]string, error) {
	dir := strings.TrimSuffix(PipeName(""), PipePrefix)
	p, err := windows.UTF16PtrFromString(dir + "*")
	if err != nil {
		return nil, err
	}
	var d windows.Win32finddata
	h, err := windows.FindFirstFile(p, &d)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	defer windows.FindClose(h)
	var out []string
	for {
		if n := windows.UTF16ToString(d.FileName[:]); strings.HasPrefix(n, PipePrefix) {
			out = append(out, strings.TrimPrefix(n, PipePrefix))
		}
		if err := windows.FindNextFile(h, &d); err != nil {
			break
		}
	}
	return out, nil
}
