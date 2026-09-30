package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	var inv *InvalidError
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
	// Five failures for one name block it, even with the right password
	// and from another address.
	for i := 0; i < 5; i++ {
		s.Login(ctx, "owner", "wrong password!", meta("10.0.0.3"))
	}
	var rl *RateLimitedError
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.4")); !errors.As(err, &rl) || rl.Wait <= 0 {
		t.Fatalf("not rate limited: %v", err)
	}
	c.add(6 * time.Minute)
	if _, err := s.Login(ctx, "owner", goodPass, meta("10.0.0.4")); err != nil {
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
