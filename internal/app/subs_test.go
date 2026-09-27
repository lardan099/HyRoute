package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

const subURL = "https://panel.example/sub/SECRETTOKEN123?key=anothersecret99"

func TestSubscriptionLifecycle(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@de1.example:443#DE%20%231\nhy2://a@de2.example:443#DE%20%232\nvless://x@h:1\n"
	var fail error
	c.Fetch = func(_ context.Context, u string) (FetchResult, error) {
		if u != subURL {
			t.Fatalf("fetched %q", u)
		}
		return FetchResult{Body: []byte(body), Title: "My VPN", UserInfo: "upload=1073741824; download=1073741824; total=10737418240; expire=1893456000"}, fail
	}
	pv, err := c.PreviewSubscription(subURL)
	if err != nil || pv.Count != 2 || pv.IgnoredN != 1 || pv.Title != "My VPN" || !strings.Contains(pv.Traffic, "2.0 ГБ из 10.0 ГБ") {
		t.Fatalf("%+v %v", pv, err)
	}
	v, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "24h"})
	if err != nil || v.Name != "My VPN" || v.Profiles != 2 || v.URLMasked != "https://panel.example/…" || v.URL != "" {
		t.Fatalf("%+v %v", v, err)
	}
	ps := c.Profiles()
	if len(ps) != 2 || ps[0].SourceName != "My VPN" || !ps[0].Main {
		t.Fatalf("%+v", ps)
	}
	de2 := ps[1].ID
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "yt", Domain: &rules.DomainMatch{Pattern: ".youtube.com"}, Action: rules.Tunnel, Profile: de2}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}

	// A failed update keeps everything.
	fail = errors.New("boom")
	if _, err := c.UpdateSubscription(v.ID); err == nil {
		t.Fatal("want error")
	}
	fail = nil
	body = "<html>login</html>"
	if _, err := c.UpdateSubscription(v.ID); err == nil || !strings.Contains(err.Error(), "веб-страницу") {
		t.Fatalf("%v", err)
	}
	if len(c.Profiles()) != 2 || c.Subscriptions()[0].LastError == "" {
		t.Fatal("bad update changed the profiles")
	}

	// DE #2 disappears: the rule keeps its profile, marked missing.
	body = "aHkyOi8vYUBkZTEuZXhhbXBsZTo0NDMjREUlMjAlMjMx" // base64 of the DE #1 link
	ms, err := c.UpdateSubscription(v.ID)
	if err != nil || ms.MissingKept != 1 || ms.Updated != 1 {
		t.Fatalf("%+v %v", ms, err)
	}
	if w := c.RuleWarnings(); len(w) != 1 || w[0].Kind != "missing" {
		t.Fatalf("%+v", w)
	}
	// Rollback brings it back with the same ID.
	if _, err := c.RollbackSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if w := c.RuleWarnings(); len(w) != 0 {
		t.Fatalf("after rollback: %+v", w)
	}
	found := false
	for _, p := range c.Profiles() {
		found = found || (p.ID == de2 && !p.Missing)
	}
	if !found {
		t.Fatal("rollback lost the profile ID")
	}

	// The URL never shows up in logs.
	c.Log.Info("test", "url", subURL)
	for _, e := range c.Logs("engine", 0) {
		if strings.Contains(e.Msg, "SECRETTOKEN123") || strings.Contains(e.Msg, "anothersecret99") {
			t.Fatalf("secret in log: %s", e.Msg)
		}
	}

	// Reload: URL decrypted, profiles still linked.
	c2 := New(c.Store, c.Start, c.Base, nil)
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	c2.mu.Lock()
	got := c2.subs[0].URL
	c2.mu.Unlock()
	if got != subURL || c2.Profiles()[0].SourceName != "My VPN" {
		t.Fatalf("reload: %q", got)
	}

	// Deleting keeps the used profile as a manual one.
	if err := c.DeleteSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	ps = c.Profiles()
	if len(ps) != 2 || ps[0].Source != "" || ps[1].Source != "" {
		t.Fatalf("%+v", ps)
	}
}

func TestParseSubscriptionErrors(t *testing.T) {
	for body, want := range map[string]string{
		"":                           "пустая",
		`{"outbounds":[]}`:           "JSON",
		"proxies:\n  - name: x":      "Clash",
		"vless://a@b:1\nvmess://abc": "только другие протоколы",
	} {
		if _, err := parseSubscription([]byte(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", body, err)
		}
	}
}

// addSub adds a subscription whose body the test controls.
func addSub(t *testing.T, c *Controller, body *string) SubView {
	t.Helper()
	c.Fetch = func(context.Context, string) (FetchResult, error) { return FetchResult{Body: []byte(*body)}, nil }
	pv, err := c.PreviewSubscription(subURL)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A server a local proxy goes through is kept (marked missing) like one a
// rule uses: dropping it would lose its ID and break the proxy for good.
func TestSubscriptionKeepsProxyServer(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\nhy2://a@two.example:443#TWO\n"
	v := addSub(t, c, &body)
	two := c.Profiles()[1].ID
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "P", Profile: two, Port: 10801}}); err != nil {
		t.Fatal(err)
	}
	body = "hy2://a@one.example:443#ONE\n"
	if ms, err := c.UpdateSubscription(v.ID); err != nil || ms.MissingKept != 1 || ms.Removed != 0 {
		t.Fatalf("%+v %v", ms, err)
	}
	if ps := c.Profiles(); len(ps) != 2 || ps[1].ID != two || !ps[1].Missing {
		t.Fatalf("%+v", ps)
	}
	if err := c.DeleteProfile(two); err == nil || !strings.Contains(err.Error(), "прокси «P»") {
		t.Fatalf("%v", err)
	}
	body = "hy2://a@one.example:443#ONE\nhy2://a@two.example:443#TWO\n"
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if ps := c.Profiles(); len(ps) != 2 || ps[1].ID != two || ps[1].Missing {
		t.Fatalf("came back under another ID: %+v", ps)
	}
	if err := c.DeleteSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if ps := c.Profiles(); len(ps) != 2 || ps[1].ID != two || ps[1].Source != "" {
		t.Fatalf("%+v", ps)
	}
}

// The same body again must not push the version before it out: after a
// bad list arrives twice, rollback still returns to the good one.
func TestSubscriptionRollbackAfterRepeatedUpdate(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@g1.example:443#G1\nhy2://a@g2.example:443#G2\n"
	v := addSub(t, c, &body)
	body = "hy2://a@bad.example:443#BAD\n"
	for range 2 {
		if _, err := c.UpdateSubscription(v.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.RollbackSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range c.Profiles() {
		names = append(names, p.Name)
		if p.Missing {
			t.Fatalf("%s still missing", p.Name)
		}
	}
	if strings.Join(names, ",") != "G1,G2" {
		t.Fatalf("after rollback: %v", names)
	}
}

// A subscription that cannot be stored imports nothing, and one whose
// profiles cannot be stored is not stored either.
func TestAddSubscriptionLeavesNoOrphans(t *testing.T) {
	c, _ := newCtl(t)
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte("hy2://a@one.example:443#ONE\n")}, nil
	}
	add := func() error {
		pv, err := c.PreviewSubscription(subURL)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "manual"})
		return err
	}
	snaps := func() int {
		e, _ := os.ReadDir(filepath.Join(c.Store.Dir, "subs"))
		return len(e)
	}
	c.mu.Lock()
	c.subsBroken = errors.New("broken")
	c.mu.Unlock()
	if err := add(); err == nil || len(c.Profiles()) != 0 || snaps() != 0 {
		t.Fatalf("%v %+v %d", err, c.Profiles(), snaps())
	}
	c.mu.Lock()
	c.subsBroken, c.profilesBroken = nil, errors.New("broken")
	c.mu.Unlock()
	if err := add(); err == nil || len(c.Subscriptions()) != 0 || snaps() != 0 {
		t.Fatalf("%v %+v %d", err, c.Subscriptions(), snaps())
	}
	if l, err := c.Store.LoadSubscriptions(); err != nil || len(l) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
}

// A failed "startup" update (no network yet at logon) is retried like a
// failed interval one, until an update succeeds.
func TestSchedulerRetriesStartupUpdate(t *testing.T) {
	c, _ := newCtl(t)
	start := time.Now()
	s := store.Subscription{Enabled: true, Interval: "startup", LastUpdate: start.Add(-48 * time.Hour),
		LastAttempt: start.Add(time.Second), LastError: "сервер подписки недоступен"}
	if c.due(s, start.Add(time.Minute), start) {
		t.Fatal("retried sooner than 15 minutes")
	}
	if !c.due(s, start.Add(16*time.Minute), start) {
		t.Fatal("failed startup update is never retried")
	}
	// A retry succeeded, then a manual update failed: done for this run.
	s.LastUpdate, s.LastAttempt = start.Add(20*time.Minute), start.Add(30*time.Minute)
	if c.due(s, start.Add(time.Hour), start) {
		t.Fatal("retried after this run's update succeeded")
	}
	s.LastUpdate, s.Enabled = time.Time{}, false
	if c.due(s, start.Add(time.Hour), start) {
		t.Fatal("disabled subscription updated")
	}
	iv := store.Subscription{Enabled: true, Interval: "6h", LastAttempt: start.Add(-7 * time.Hour)}
	if !c.due(iv, start, start) || c.due(store.Subscription{Enabled: true, Interval: "manual"}, start, start) {
		t.Fatal("interval subscriptions broke")
	}
}

// «Сменить ссылку»: the new link is checked first and its checked body
// applied, with no second download; a link that did not check out (no
// token, or a stale one) never replaces the working one.
func TestEditSubscriptionChangesURLByPreview(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@old.example:443#OLD\n"
	v := addSub(t, c, &body)
	const newURL = "https://panel2.example/sub/NEWTOKEN4567"
	fetches := map[string]int{}
	c.Fetch = func(_ context.Context, u string) (FetchResult, error) {
		fetches[u]++
		switch u {
		case newURL:
			return FetchResult{Body: []byte("hy2://a@new1.example:443#NEW1\nhy2://a@new2.example:443#NEW2\n")}, nil
		case "https://panel2.example/dashboard":
			return FetchResult{Body: []byte("<html>login</html>")}, nil
		}
		return FetchResult{Body: []byte(body)}, nil
	}
	cur := func() string {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.subs[0].URL
	}
	edit := func(token string) error {
		return c.EditSubscription(SubInput{ID: v.ID, Token: token, Name: v.Name, Enabled: true, Interval: "manual"})
	}

	// A web page instead of a subscription: no token, nothing to apply.
	if _, err := c.PreviewSubscription("https://panel2.example/dashboard"); err == nil {
		t.Fatal("web page previewed")
	}
	if err := edit("no-such-token"); err == nil || cur() != subURL {
		t.Fatalf("stale token: %v, url %q", err, cur())
	}

	pv, err := c.PreviewSubscription(newURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := edit(pv.Token); err != nil {
		t.Fatal(err)
	}
	if cur() != newURL || fetches[newURL] != 1 {
		t.Fatalf("url %q, fetched %d times", cur(), fetches[newURL])
	}
	// OLD is the main server: kept, marked as gone from the subscription.
	var names []string
	for _, p := range c.Profiles() {
		names = append(names, fmt.Sprintf("%s:%v", p.Name, p.Missing))
	}
	if strings.Join(names, ",") != "NEW1:false,NEW2:false,OLD:true" {
		t.Fatalf("profiles after the change: %v", names)
	}
	if s := c.Subscriptions()[0]; s.LastError != "" || s.Count != 2 || !s.HasPrevious {
		t.Fatalf("%+v", s)
	}
	// The token is used up, and a plain edit keeps the link.
	if err := edit(pv.Token); err == nil {
		t.Fatal("token used twice")
	}
	if err := c.EditSubscription(SubInput{ID: v.ID, Name: "Renamed", Enabled: false, Interval: "24h"}); err != nil || cur() != newURL {
		t.Fatalf("%v, url %q", err, cur())
	}
	// Neither link shows up in logs.
	c.Log.Info("test", "old", subURL, "new", newURL)
	for _, e := range c.Logs("engine", 0) {
		if strings.Contains(e.Msg, "SECRETTOKEN123") || strings.Contains(e.Msg, "NEWTOKEN4567") {
			t.Fatalf("secret in log: %s", e.Msg)
		}
	}
}

// Updates of one subscription (the scheduler and the button) run one at a
// time, a rollback waits for a running update, and another subscription
// updates meanwhile.
func TestSubscriptionUpdatesOneAtATime(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\n"
	a := addSub(t, c, &body)
	const otherURL = "https://other.example/sub/OTHERTOKEN456"
	pv, err := c.PreviewSubscription(otherURL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	running := map[string]int{}
	entered := make(chan string, 10)
	// slow serves body once release is closed and notes overlapping
	// downloads of one link.
	slow := func(body string, release chan struct{}) func(context.Context, string) (FetchResult, error) {
		return func(_ context.Context, u string) (FetchResult, error) {
			mu.Lock()
			running[u]++
			if running[u] > 1 {
				t.Errorf("two downloads of %s at once", u)
			}
			mu.Unlock()
			entered <- u
			<-release
			mu.Lock()
			running[u]--
			mu.Unlock()
			return FetchResult{Body: []byte(body)}, nil
		}
	}
	var wg sync.WaitGroup
	update := func(id string) {
		wg.Go(func() {
			if _, err := c.UpdateSubscription(id); err != nil {
				t.Error(err)
			}
		})
	}

	release := make(chan struct{})
	c.Fetch = slow("hy2://a@two.example:443#TWO\n", release)
	update(a.ID)
	update(a.ID)
	update(b.ID)
	got := map[string]bool{<-entered: true, <-entered: true}
	if !got[subURL] || !got[otherURL] {
		t.Fatalf("downloading: %v", got)
	}
	select {
	case u := <-entered:
		t.Fatalf("%s downloaded twice at once", u)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if len(entered) != 1 {
		t.Fatalf("the waiting update did not download again: %d", len(entered))
	}
	<-entered

	// A rollback during an update goes after it: back to TWO, not to ONE
	// with THREE applied over it.
	release = make(chan struct{})
	c.Fetch = slow("hy2://a@three.example:443#THREE\n", release)
	update(a.ID)
	<-entered
	rolled := make(chan error, 1)
	go func() {
		_, err := c.RollbackSubscription(a.ID)
		rolled <- err
	}()
	select {
	case err := <-rolled:
		t.Fatalf("rollback did not wait for the update: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if err := <-rolled; err != nil {
		t.Fatal(err)
	}
	listed := func() string {
		var names []string
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, p := range c.profiles.List {
			if p.Source == "sub:"+a.ID && !p.Missing {
				names = append(names, p.Name)
			}
		}
		return strings.Join(names, ",")
	}
	if n := listed(); n != "TWO" {
		t.Fatalf("after rollback: %v", n)
	}

	// «Сменить ссылку» during an update goes after it: the old link's list
	// does not land over the new one.
	const newURL = "https://panel.example/sub/NEWTOKEN789"
	release = make(chan struct{})
	slowOld := slow("hy2://a@five.example:443#FIVE\n", release)
	c.Fetch = func(ctx context.Context, u string) (FetchResult, error) {
		if u == newURL {
			return FetchResult{Body: []byte("hy2://a@four.example:443#FOUR\n")}, nil
		}
		return slowOld(ctx, u)
	}
	update(a.ID)
	<-entered
	pv, err = c.PreviewSubscription(newURL)
	if err != nil {
		t.Fatal(err)
	}
	edited := make(chan error, 1)
	go func() {
		edited <- c.EditSubscription(SubInput{ID: a.ID, Token: pv.Token, Enabled: true, Interval: "manual"})
	}()
	select {
	case err := <-edited:
		t.Fatalf("link change did not wait for the update: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if err := <-edited; err != nil {
		t.Fatal(err)
	}
	if n := listed(); n != "FOUR" {
		t.Fatalf("after link change: %v", n)
	}

	c.subMu.Lock()
	left := len(c.subLocks)
	c.subMu.Unlock()
	if left != 0 {
		t.Fatalf("%d subscription locks left", left)
	}
}
