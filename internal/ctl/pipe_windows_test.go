//go:build windows

package ctl

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests pass unelevated (a developer's shell) and elevated (CI):
// every object has an explicit owner (the current user), and what "a
// non-admin" may do is checked under a restricted token.

func selfSID(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := u.User.Sid.Copy()
	return s
}

func wellKnown(t *testing.T, k windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	s, err := windows.CreateWellKnownSid(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func randName(t *testing.T) string {
	var b [6]byte
	rand.Read(b[:])
	return PipeName("S-1-5-21-test-" + hex.EncodeToString(b[:]))
}

// testListen listens as the tests do: owner and user = the current user,
// Authenticated Users with full access so the unelevated server can create
// its later instances.
func testListen(t *testing.T, name string, max int, allow func(Identity) bool) *Listener {
	t.Helper()
	me := selfSID(t)
	if allow == nil {
		allow = func(Identity) bool { return true }
	}
	l, err := Listen(ListenConfig{Name: name, Users: []*windows.SID{me}, Owner: me,
		FullAccess: []*windows.SID{wellKnown(t, windows.WinAuthenticatedUserSid)}, Allow: allow, MaxInstances: max})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

type accepted struct {
	c       net.Conn
	id      Identity
	allowed bool
	err     error
}

func acceptOne(l *Listener) chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		c, id, ok, err := l.Accept()
		ch <- accepted{c, id, ok, err}
	}()
	return ch
}

func trustedMe(t *testing.T) []string { return []string{selfSID(t).String()} }

func TestPipeRoundTrip(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	ch := acceptOne(l)
	c, pid, err := Dial(name, time.Second, trustedMe(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pid != uint32(os.Getpid()) {
		t.Fatal(pid)
	}
	a := <-ch
	if a.err != nil || !a.allowed {
		t.Fatal(a.err)
	}
	big := []byte(strings.Repeat("x", 1<<20))
	srvDone := make(chan struct{})
	defer func() { c.Close(); <-srvDone }() // the server side ends before the test
	go func() {
		defer close(srvDone)
		defer a.c.Close()
		WriteFrame(a.c, []byte(`{"hello":{}}`), MaxResponse)
		body, err := ReadFrame(a.c, MaxRequest)
		if err != nil || string(body) != `{"cmd":"status"}` {
			return
		}
		WriteFrame(a.c, big, MaxResponse)
		// Linger until the client hangs up, then close.
		io.Copy(io.Discard, a.c)
	}()
	if b, err := ReadFrame(c, MaxResponse); err != nil || string(b) != `{"hello":{}}` {
		t.Fatal(string(b), err)
	}
	if err := WriteFrame(c, []byte(`{"cmd":"status"}`), MaxRequest); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFrame(c, MaxResponse)
	if err != nil || len(b) != len(big) {
		t.Fatal(len(b), err)
	}
}

func TestPipeFirstInstance(t *testing.T) {
	name := randName(t)
	testListen(t, name, 0, nil)
	me := selfSID(t)
	_, err := Listen(ListenConfig{Name: name, Users: []*windows.SID{me}, Owner: me, Allow: func(Identity) bool { return true }})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatal(err)
	}
}

var procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")

// asRestricted runs fn on a thread impersonating a copy of the process
// token with Administrators and Authenticated Users deny-only.
func asRestricted(t *testing.T, fn func()) {
	t.Helper()
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &self); err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	disable := []windows.SIDAndAttributes{
		{Sid: wellKnown(t, windows.WinBuiltinAdministratorsSid)},
		{Sid: wellKnown(t, windows.WinAuthenticatedUserSid)},
	}
	var restricted windows.Token
	r, _, err := procCreateRestrictedToken.Call(uintptr(self), 0, uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])),
		0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		t.Fatal("CreateRestrictedToken:", err)
	}
	defer restricted.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	defer imp.Close()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, imp); err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		fn()
		if err := windows.RevertToSelf(); err != nil {
			done <- err // the thread is discarded (not unlocked)
			return
		}
		runtime.UnlockOSThread()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNoRogueInstance(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	p, _ := windows.UTF16PtrFromString(name)
	var rogueErr error
	asRestricted(t, func() {
		h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, 8, 4096, 4096, 0, nil)
		if err == nil {
			windows.CloseHandle(h)
		}
		rogueErr = err
	})
	if !errors.Is(rogueErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("a user created an instance of the pipe:", rogueErr)
	}
	// The listener's own next instance (unrestricted, via AU) works.
	h, err := l.create(false)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
}

func TestDialRejectsUntrustedOwner(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	ch := acceptOne(l)
	if _, _, err := Dial(name, time.Second, Trusted); !errors.Is(err, ErrImpostor) {
		t.Fatal(err)
	}
	// The server saw a client that sent nothing and left.
	select {
	case a := <-ch:
		if a.err == nil {
			a.c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := a.c.Read(make([]byte, 1)); err != io.EOF {
				t.Fatal("data from an impostor check:", err)
			}
			a.c.Close()
		}
	case <-time.After(2 * time.Second):
	}
}

func TestIdentity(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	ch := acceptOne(l)
	c, _, err := Dial(name, time.Second, trustedMe(t))
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	c.Close()
	a.c.Close()
	id := a.id
	if id.User != selfSID(t).String() || id.IntegrityRID < MediumRID || id.PID != uint32(os.Getpid()) ||
		id.Elevated != windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%+v", id)
	}
	// An anonymous client: nothing to identify.
	ch = acceptOne(l)
	c, _, err = dial(name, time.Second, trustedMe(t), windows.SECURITY_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	a = <-ch
	c.Close()
	a.c.Close()
	if a.id.User != "" || a.id.IntegrityRID != 0 {
		t.Fatalf("%+v", a.id)
	}
}

func TestSecurityDescriptor(t *testing.T) {
	me := selfSID(t)
	sd, err := windows.SecurityDescriptorFromString(ListenConfig{Users: []*windows.SID{me}}.SDDL())
	if err != nil {
		t.Fatal(err)
	}
	o, _, _ := sd.Owner()
	if o.String() != "S-1-5-32-544" {
		t.Fatal("owner", o)
	}
	ctl, _, err := sd.Control()
	if err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL not protected", ctl, err)
	}
	s := sd.String()
	if !strings.Contains(s, "(A;;RC;;;OW)") || !strings.Contains(s, "S:(ML;;NW;;;ME)") {
		t.Fatal(s)
	}
	// The ACE as SDDL writes it: well-known accounts get an alias (the
	// built-in Administrator of a CI runner is LA, not its SID).
	ace, err := windows.SecurityDescriptorFromString("D:(A;;0x12019b;;;" + me.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, strings.TrimPrefix(ace.String(), "D:")) || userRW&0x4 != 0 {
		t.Fatal("the user ACE may create instances:", s)
	}
}

func TestListenerClose(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	var completed atomic.Int32
	testAfterOverlappedResult = func() { completed.Add(1) }
	defer func() { testAfterOverlappedResult = nil }()
	ch := acceptOne(l)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	l.Close()
	select {
	case a := <-ch:
		if !errors.Is(a.err, ErrClosed) {
			t.Fatal(a.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Accept")
	}
	if time.Since(start) > time.Second || completed.Load() != 1 {
		t.Fatal(time.Since(start), completed.Load())
	}
	if _, _, _, err := l.Accept(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestBusy(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 1, nil)
	ch := acceptOne(l)
	c, _, err := Dial(name, time.Second, trustedMe(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a := <-ch
	defer a.c.Close()
	if _, _, err := Dial(name, 300*time.Millisecond, trustedMe(t)); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
}

func TestConnDeadline(t *testing.T) {
	name := randName(t)
	l := testListen(t, name, 0, nil)
	ch := acceptOne(l)
	c, _, err := Dial(name, time.Second, trustedMe(t))
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	s := a.c
	if err := s.SetDeadline(time.Time{}); err != nil {
		t.Fatal("no deadlines on an accepted conn:", err)
	}
	s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	s.SetReadDeadline(time.Time{})
	// Concurrent read and write on one conn (the server's hang-up watcher
	// reads while frames are written). Not under -race: internal/poll
	// keeps a file offset for pipes too and updates it after a Write
	// without the read lock, so a Read in flight races on it (Go's own,
	// harmless: a pipe ignores the offset). Without -race it is tested.
	got := make(chan string, 1)
	if !raceDetector {
		go func() {
			b, _ := ReadFrame(s, 100)
			got <- string(b)
		}()
	}
	if err := WriteFrame(s, []byte("ping"), 100); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFrame(c, 100); err != nil || string(b) != "ping" {
		t.Fatal(err)
	}
	WriteFrame(c, []byte("pong"), 100)
	if raceDetector {
		b, _ := ReadFrame(s, 100)
		got <- string(b)
	}
	if g := <-got; g != "pong" {
		t.Fatal(g)
	}
	// Close during a blocked Read returns quickly.
	done := make(chan error, 1)
	go func() { _, err := s.Read(make([]byte, 1)); done <- err }()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not end the Read")
	}
	// The client sees the server gone as EOF.
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	c.Close()

	// And the server sees a client that closed as EOF.
	ch = acceptOne(l)
	c, _, _ = Dial(name, time.Second, trustedMe(t))
	a = <-ch
	c.Close()
	if _, err := a.c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	a.c.Close()
}

func TestFindPipes(t *testing.T) {
	name := randName(t)
	testListen(t, name, 0, nil)
	sids, err := FindPipes()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(name, PipeName(""))
	for _, s := range sids {
		if s == want {
			return
		}
	}
	t.Fatal(want, sids)
}

func TestRunEvent(t *testing.T) {
	var b [6]byte
	rand.Read(b[:])
	name := strings.Replace(RunEventName("S-1-5-21-test-"+hex.EncodeToString(b[:])), "Global", "Local", 1)
	me := selfSID(t)
	h, err := CreateRunEvent(name, []*windows.SID{me}, me)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := ProbeRunEvent(name, trustedMe(t)); st != RunStarting || err != nil {
		t.Fatal(st, err)
	}
	windows.SetEvent(h)
	if st, _ := ProbeRunEvent(name, trustedMe(t)); st != RunSettled {
		t.Fatal(st)
	}
	windows.CloseHandle(h)
	if st, _ := ProbeRunEvent(name, trustedMe(t)); st != RunAbsent {
		t.Fatal(st)
	}

	// Foreign: an event someone else created first (owner: the user).
	h2, err := CreateRunEvent(name, []*windows.SID{me}, me)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h2)
	if _, err := CreateRunEvent(name, []*windows.SID{me}, nil); !errors.Is(err, ErrNameTaken) {
		t.Fatal(err)
	}
	if st, _ := ProbeRunEvent(name, Trusted); st != RunForeign {
		t.Fatal(st)
	}
}
