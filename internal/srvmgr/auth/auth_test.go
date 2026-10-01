package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// fastParams keep the tests quick; production uses DefaultParams.
var fastParams = Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Unix(1_700_000_000, 0)} }
func meta(ip string) Meta            { return Meta{IP: ip, UserAgent: "test"} }
func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newService(t *testing.T) (*Service, *sqlite.DB, *clock) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db)
	s.Params = fastParams
	c := newClock()
	s.Now = c.now
	return s, db, c
}

const goodPass = "correct horse battery"

func setupOwner(t *testing.T, s *Service) Issued {
	t.Helper()
	ctx := context.Background()
	tok, err := s.PrepareSetup(ctx)
	if err != nil || tok == "" {
		t.Fatalf("setup token %q %v", tok, err)
	}
	is, err := s.Setup(ctx, tok, "owner", goodPass, meta("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword(goodPass, fastParams)
	mustNoErr(t, err)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash %q", h)
	}
	ok, stale, err := VerifyPassword(h, goodPass, fastParams)
	if !ok || stale || err != nil {
		t.Fatalf("verify: %v %v %v", ok, stale, err)
	}
	if ok, _, _ := VerifyPassword(h, "wrong password", fastParams); ok {
		t.Fatal("wrong password accepted")
	}
	if _, stale, _ := VerifyPassword(h, goodPass, DefaultParams); !stale {
		t.Fatal("other parameters not reported as stale")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", strings.Replace(h, "m=64", "m=99999999", 1)} {
		if _, _, err := VerifyPassword(bad, goodPass, fastParams); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	h2, _ := HashPassword(goodPass, fastParams)
	if h == h2 {
		t.Fatal("salt is not random")
	}
}

func TestLimiter(t *testing.T) {
	l := &Limiter{Max: 3, Window: time.Minute}
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if l.Wait("k", now) != 0 {
			t.Fatalf("blocked after %d failures", i)
		}
		l.Fail("k", now.Add(time.Duration(i)*time.Second))
	}
	if w := l.Wait("k", now.Add(3*time.Second)); w != 57*time.Second {
		t.Fatalf("wait %v", w)
	}
	if l.Wait("other", now) != 0 {
		t.Fatal("keys are not independent")
	}
	if l.Wait("k", now.Add(61*time.Second)) != 0 {
		t.Fatal("still blocked after the window")
	}
	l.Fail("k", now)
	l.Reset("k")
	if l.Wait("k", now) != 0 {
		t.Fatal("reset did not clear")
	}
	// Forgive drops one attempt, the one recorded at that time.
	for i := 0; i < 3; i++ {
		l.Fail("k", now.Add(time.Duration(i)*time.Second))
	}
	l.Forgive("k", now.Add(time.Second))
	l.Forgive("k", now.Add(time.Hour)) // not there: nothing happens
	if w := l.Wait("k", now.Add(3*time.Second)); w != 0 {
		t.Fatalf("still blocked after forgive: %v", w)
	}
	l.Fail("k", now.Add(3*time.Second))
	if w := l.Wait("k", now.Add(3*time.Second)); w != 57*time.Second {
		t.Fatalf("wait after forgive %v", w)
	}
}

func TestAddrKey(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":             "10.0.0.1",
		"::ffff:10.0.0.1":      "10.0.0.1",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3:3:4:5:6": "2001:db8:1:3::/64",
		"fe80::1%eth0":         "fe80::/64",
		"::1":                  "::/64",
		"not an address":       "not an address",
	} {
		if got := addrKey(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestFirstRunSetup(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	if need, _ := s.SetupNeeded(ctx); !need {
		t.Fatal("setup not needed on a clean database")
	}
	tok, err := s.PrepareSetup(ctx)
	mustNoErr(t, err)
	if _, err := s.Setup(ctx, "wrong", "owner", goodPass, meta("10.0.0.1")); !errors.Is(err, ErrBadSetupToken) {
		t.Fatalf("wrong token: %v", err)
	}
	var inv *model.FieldError
	if _, err := s.Setup(ctx, tok, "owner", "short", meta("10.0.0.1")); !errors.As(err, &inv) || inv.Field != "password" {
		t.Fatalf("short password: %v", err)
	}
	if _, err := s.Setup(ctx, tok, "bad name!", goodPass, meta("10.0.0.1")); !errors.As(err, &inv) || inv.Field != "username" {
		t.Fatalf("bad username: %v", err)
	}
	is, err := s.Setup(ctx, tok, "owner", goodPass, meta("10.0.0.1"))
	mustNoErr(t, err)
	if is.User.Role != model.RoleOwner || is.Token == "" || is.CSRF != CSRFToken(is.Token) || !s.SetupDone() {
		t.Fatalf("%+v", is)
	}
	// The same token cannot be used twice, and no new token is issued.
	if _, err := s.Setup(ctx, tok, "second", goodPass, meta("10.0.0.1")); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("repeated setup: %v", err)
	}
	if tok2, _ := s.PrepareSetup(ctx); tok2 != "" {
		t.Fatal("setup token issued with an owner present")
	}
}

// A second controller process (restart) with a stale token in memory still
// cannot create a second owner: the database decides.
func TestSetupRepeatAfterRestart(t *testing.T) {
	s, db, _ := newService(t)
	ctx := context.Background()
	setupOwner(t, s)
	s2 := New(db)
	s2.Params = fastParams
	s2.setupHash = tokenHash("stale")
	if _, err := s2.Setup(ctx, "stale", "evil", goodPass, meta("1.2.3.4")); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("%v", err)
	}
	if n, _ := db.CountUsers(ctx); n != 1 {
		t.Fatalf("%d users", n)
	}
}

func TestLoginAndRateLimit(t *testing.T) {
	s, _, c := newService(t)
	ctx := context.Background()
	setupOwner(t, s)
	if _, err := s.Login(ctx, "owner", "wrong password!", meta("10.0.0.2")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Login(ctx, "nobody", goodPass, meta("10.0.0.2")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	is, err := s.Login(ctx, "OWNER", goodPass, meta("10.0.0.2"))
	mustNoErr(t, err)
	if is.User.Username != "owner" {
		t.Fatalf("%+v", is.User)
	}
	c.add(6 * time.Minute)
	// Five failures for one name from one address block the name for that
	// address, even with the right password.
	for i := 0; i < 5; i++ {
		if _, err := s.Login(ctx, "owner", "wrong password!", meta("10.0.0.3")); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); !errors.As(err, &rl) || rl.Wait != 5*time.Minute {
		t.Fatalf("not rate limited: %v", err)
	}
	c.add(6 * time.Minute)
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	// Many names from one address block the address.
	for i := 0; i < 20; i++ {
		s.Login(ctx, "user"+string(rune('a'+i)), "wrong password!", meta("10.0.0.9"))
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.9")); !errors.As(err, &rl) {
		t.Fatalf("address not rate limited: %v", err)
	}
}

// Anybody can hammer the owner's name, but not lock the owner out: a name
// under attack stays open to addresses without failures of their own.
func TestOwnerNotLockedOut(t *testing.T) {
	s, _, c := newService(t)
	ctx := context.Background()
	setupOwner(t, s)
	s.slots = make(chan struct{}, 64) // no ErrBusy here: only the limit counts
	for i := 0; i < 5; i++ {
		s.Login(ctx, "owner", "wrong password!", meta("10.0.0.3"))
	}
	c.add(time.Minute)
	var rl *RateLimitedError
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); !errors.As(err, &rl) {
		t.Fatalf("guesser not rate limited: %v", err)
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.4")); err != nil {
		t.Fatalf("owner locked out: %v", err)
	}
	// The owner's login gives the guesser no new tries.
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); !errors.As(err, &rl) {
		t.Fatalf("guesser forgiven by the owner's login: %v", err)
	}
	// Another address gets one try while the name is under attack, also
	// when it sends many at once.
	if _, err := s.Login(ctx, "owner", "wrong password!", meta("10.0.0.5")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("fresh address: %v", err)
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.5")); !errors.As(err, &rl) {
		t.Fatalf("second try of a fresh address: %v", err)
	}
	r := burst(s, 30, func(int) (string, string, string) { return "owner", "wrong password!", "10.0.0.6" })
	if r.bad != 1 || r.limited != 29 {
		t.Fatalf("burst from a fresh address: %+v", r)
	}
	// All of it ends with the window.
	c.add(5 * time.Minute)
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

// IPv6 clients are counted by /64: hopping addresses inside one network
// gives no new tries.
func TestIPv6CountedByNetwork(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	setupOwner(t, s)
	for i := 1; i <= 5; i++ {
		if _, err := s.Login(ctx, "owner", "wrong password!", meta(fmt.Sprintf("2001:db8::%x", i))); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, err := s.Login(ctx, "owner", goodPass, meta("2001:db8::ffff:1")); !errors.As(err, &rl) {
		t.Fatalf("same /64 not rate limited: %v", err)
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("2001:db8:0:1::1")); err != nil {
		t.Fatalf("another /64: %v", err)
	}
	for i := 0; i < 20; i++ {
		s.Login(ctx, fmt.Sprintf("user%d", i), "wrong password!", meta(fmt.Sprintf("2001:db8:2::%x", i+1)))
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("2001:db8:2::abcd")); !errors.As(err, &rl) {
		t.Fatalf("address limit by /64: %v", err)
	}
}

// burstResult counts the outcomes of concurrent logins.
type burstResult struct{ ok, bad, limited, busy, other int }

// burst runs n logins at once; arg gives the name, password and address
// of each.
func burst(s *Service, n int, arg func(i int) (name, password, ip string)) burstResult {
	var (
		mu    sync.Mutex
		r     burstResult
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for i := 0; i < n; i++ {
		name, password, ip := arg(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Login(context.Background(), name, password, meta(ip))
			var rl *RateLimitedError
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				r.ok++
			case errors.Is(err, ErrBadCredentials):
				r.bad++
			case errors.As(err, &rl):
				r.limited++
			case errors.Is(err, ErrBusy):
				r.busy++
			default:
				r.other++
			}
		}()
	}
	close(start)
	wg.Wait()
	return r
}

// Concurrent attempts cannot pass the limit together: each one is counted
// before its password is hashed.
func TestConcurrentLoginsCounted(t *testing.T) {
	s, _, _ := newService(t)
	setupOwner(t, s)
	s.slots = make(chan struct{}, 200) // no ErrBusy here: only the limit counts
	r := burst(s, 100, func(int) (string, string, string) { return "owner", "wrong password!", "10.0.0.3" })
	if r.bad != 5 || r.limited != 95 {
		t.Fatalf("one name: %+v", r)
	}
	r = burst(s, 100, func(i int) (string, string, string) { return fmt.Sprintf("user%d", i), "wrong password!", "10.0.0.4" })
	if r.bad != 20 || r.limited != 80 {
		t.Fatalf("one address: %+v", r)
	}
}

// No more than MaxHashing argon2id runs overlap, whatever comes at once:
// known names and unknown ones (the dummy hash) from many addresses.
func TestHashingBounded(t *testing.T) {
	s, _, _ := newService(t)
	setupOwner(t, s)
	if cap(s.slots) != MaxHashing {
		t.Fatalf("%d slots", cap(s.slots))
	}
	var cur, peak atomic.Int32
	idKey = func(password, salt []byte, passes, memory uint32, threads uint8, keyLen uint32) []byte {
		n := cur.Add(1)
		defer cur.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		return argon2.IDKey(password, salt, passes, memory, threads, keyLen)
	}
	t.Cleanup(func() { idKey = argon2.IDKey })
	r := burst(s, 40, func(i int) (string, string, string) {
		name := "owner"
		if i%2 == 1 {
			name = "nobody"
		}
		return name, goodPass, fmt.Sprintf("10.1.0.%d", i)
	})
	if p := peak.Load(); p < 1 || p > MaxHashing {
		t.Fatalf("%d argon2id runs at once", p)
	}
	if r.ok == 0 || r.limited != 0 || r.other != 0 || r.ok+r.bad+r.busy != 40 {
		t.Fatalf("%+v", r)
	}
}

// With every hashing slot taken, logins are refused at once and not
// counted; logged-in users creating accounts wait for a slot.
func TestBusy(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	owner, err := s.Authenticate(ctx, setupOwner(t, s).Token)
	mustNoErr(t, err)
	for i := 0; i < MaxHashing; i++ {
		s.slots <- struct{}{}
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Login(ctx, "owner", "wrong password!", meta("10.0.0.3")); !errors.Is(err, ErrBusy) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); !errors.Is(err, ErrBusy) {
		t.Fatalf("right password: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := s.CreateUser(short, owner, "viewer", goodPass, model.RoleReadOnly); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("create user without a slot: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateUser(ctx, owner, "viewer", goodPass, model.RoleReadOnly)
		done <- err
	}()
	<-s.slots
	mustNoErr(t, <-done)
	for i := 1; i < MaxHashing; i++ {
		<-s.slots
	}
	// The refused attempts were not counted: the address has all its tries.
	for i := 0; i < 5; i++ {
		if _, err := s.Login(ctx, "owner", "wrong password!", meta("10.0.0.3")); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.3")); !errors.As(err, &rl) {
		t.Fatalf("not rate limited: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s, db, c := newService(t)
	ctx := context.Background()
	is := setupOwner(t, s)
	p, err := s.Authenticate(ctx, is.Token)
	if err != nil || p.User.ID != is.User.ID {
		t.Fatalf("%+v %v", p, err)
	}
	for _, tok := range []string{"", "garbage", strings.Repeat("x", 500)} {
		if _, err := s.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%q: %v", tok, err)
		}
	}
	// Idle: a session unused for longer than IdleTimeout ends.
	c.add(s.IdleTimeout + time.Minute)
	if _, err := s.Authenticate(ctx, is.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("idle session accepted: %v", err)
	}
	// Absolute: used every hour, it still ends after MaxAge.
	is2, _ := s.Login(ctx, "owner", goodPass, meta("127.0.0.1"))
	for d := time.Duration(0); d < s.MaxAge; d += time.Hour {
		c.add(time.Hour)
		if _, err := s.Authenticate(ctx, is2.Token); err != nil {
			if d < s.MaxAge-time.Hour {
				t.Fatalf("ended early at %v: %v", d, err)
			}
		}
	}
	if _, err := s.Authenticate(ctx, is2.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session accepted: %v", err)
	}
	// Logout and revoke.
	is3, _ := s.Login(ctx, "owner", goodPass, meta("127.0.0.1"))
	p3, _ := s.Authenticate(ctx, is3.Token)
	mustNoErr(t, s.Logout(ctx, p3))
	if _, err := s.Authenticate(ctx, is3.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("logged out session accepted")
	}
	// A disabled user loses their sessions.
	is4, _ := s.Login(ctx, "owner", goodPass, meta("127.0.0.1"))
	if _, err := db.UserByID(ctx, is4.User.ID); err != nil {
		t.Fatal(err)
	}
	u := model.User{Username: "ro", Role: model.RoleReadOnly}
	u.PasswordHash, _ = HashPassword(goodPass, fastParams)
	db.CreateUser(ctx, &u)
	isRO, _ := s.Login(ctx, "ro", goodPass, meta("127.0.0.1"))
	disable(t, db, u.ID)
	if _, err := s.Authenticate(ctx, isRO.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("disabled user's session accepted")
	}
	if _, err := s.Login(ctx, "ro", goodPass, meta("127.0.0.1")); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("disabled user logged in")
	}
}

func disable(t *testing.T, db *sqlite.DB, id int64) {
	t.Helper()
	if err := db.SetUserDisabled(context.Background(), id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCSRF(t *testing.T) {
	a, b := CSRFToken("token-a"), CSRFToken("token-b")
	if a == b || !CheckCSRF("token-a", a) || CheckCSRF("token-a", b) || CheckCSRF("token-a", "") {
		t.Fatal("CSRF token check")
	}
}

func TestRoles(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	is := setupOwner(t, s)
	owner, _ := s.Authenticate(ctx, is.Token)
	ro, err := s.CreateUser(ctx, owner, "viewer", goodPass, model.RoleReadOnly)
	mustNoErr(t, err)
	if _, err := s.CreateUser(ctx, owner, "boss", goodPass, model.RoleOwner); err == nil {
		t.Fatal("second owner created")
	}
	if _, err := s.CreateUser(ctx, owner, "viewer", goodPass, model.RoleOperator); err == nil {
		t.Fatal("duplicate name")
	}
	isRO, _ := s.Login(ctx, "viewer", goodPass, meta("127.0.0.1"))
	pRO, _ := s.Authenticate(ctx, isRO.Token)
	if pRO.User.ID != ro.ID || pRO.User.Role.CanWrite() {
		t.Fatalf("%+v", pRO.User)
	}
	if _, err := s.CreateUser(ctx, pRO, "x", goodPass, model.RoleReadOnly); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly created a user: %v", err)
	}
	if err := s.RevokeSession(ctx, pRO, owner.Session.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("readonly revoked the owner's session: %v", err)
	}
	if _, err := s.Sessions(ctx, pRO, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("readonly listed all sessions")
	}
	// Owners may revoke anyone's session; everyone may revoke their own.
	mustNoErr(t, s.RevokeSession(ctx, pRO, pRO.Session.ID))
	if err := s.RevokeSession(ctx, owner, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing session: %v", err)
	}
	all, err := s.Sessions(ctx, owner, true)
	if err != nil || len(all) != 1 {
		t.Fatalf("owner sees %d sessions, %v", len(all), err)
	}
}
