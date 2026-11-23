package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
)

func subBody(n int, prefix string) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "hy2://a@%s%d.example:443#%s%d\n", prefix, i, prefix, i)
	}
	return b.String()
}

// A group that follows a subscription gets its new servers and loses the
// removed ones; deleting the subscription makes the servers kept for a
// used group its own members.
func TestGroupFollowsSubscription(t *testing.T) {
	c, _ := newCtl(t)
	body := subBody(3, "s")
	v := addSub(t, c, &body)
	gv, err := c.SaveGroup(groups.Group{Name: "Подписка", Strategy: groups.Latency, Subs: []string{v.ID, "gone"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(gv.Views) != 3 || !slices.Equal(gv.Subs, []string{v.ID}) || len(gv.Members) != 0 {
		t.Fatalf("%+v", gv)
	}
	body = subBody(4, "s")
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if gv, _ = c.groupView(gv.ID, nil); len(gv.Views) != 4 {
		t.Fatalf("a new server did not join: %d", len(gv.Views))
	}
	body = subBody(2, "s")
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if gv, _ = c.groupView(gv.ID, nil); len(gv.Views) != 2 {
		t.Fatalf("removed servers stayed: %d", len(gv.Views))
	}
	// Used as the main target: deleting the subscription keeps a server
	// so the group is not emptied (here the active server, kept anyway),
	// and the kept servers become the group's own.
	if err := c.SetMain(gv.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	gv, _ = c.groupView(gv.ID, nil)
	if len(gv.Subs) != 0 || len(gv.Members) != 1 || len(gv.Views) != 1 || c.profiles.Find(gv.Members[0]) == nil {
		t.Fatalf("%+v", gv)
	}
}

func TestGroupExcludesServersFromFollowedSubscriptions(t *testing.T) {
	c, started := newCtl(t)
	body := subBody(2, "primary")
	first := addSub(t, c, &body)
	const secondURL = "https://backup.example/s"
	c.Fetch = func(_ context.Context, url string) (FetchResult, error) {
		if url == secondURL {
			return FetchResult{Body: []byte(subBody(2, "backup"))}, nil
		}
		return FetchResult{Body: []byte(body)}, nil
	}
	preview, err := c.PreviewSubscription(secondURL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AddSubscription(SubInput{Token: preview.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	skip := c.Profiles()[0].ID
	g, err := c.SaveGroup(groups.Group{Name: "Две подписки", Strategy: groups.Latency,
		Subs: []string{first.ID, second.ID}, Excluded: []string{skip, skip}})
	if err != nil || len(g.Views) != 3 || !slices.Equal(g.Excluded, []string{skip}) {
		t.Fatalf("save: views=%v, excluded=%v, err=%v", g.Views, g.Excluded, err)
	}
	if err := c.SetMain(g.ID); err != nil {
		t.Fatal(err)
	}
	st := c.Settings()
	st.DefaultAction = rules.Tunnel
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	running := (*started)[0].cfg.Profiles
	if len(running) != 3 || slices.ContainsFunc(running, func(p hysteria.Profile) bool { return p.ID == skip }) {
		t.Fatal("the group started an excluded server")
	}

	body = subBody(3, "primary")
	if _, err := c.UpdateSubscription(first.ID); err != nil {
		t.Fatal(err)
	}
	g, err = c.groupView(g.ID, nil)
	if err != nil || len(g.Views) != 4 || slices.ContainsFunc(g.Views, func(m MemberView) bool { return m.ID == skip }) {
		t.Fatalf("refresh lost exclusion or did not include the new server: %v, %v", g.Views, err)
	}
	other, err := c.SaveGroup(groups.Group{Name: "Вся подписка", Strategy: groups.Latency, Subs: []string{first.ID}})
	if err != nil || !slices.ContainsFunc(other.Views, func(m MemberView) bool { return m.ID == skip }) {
		t.Fatal("exclusion affected another group")
	}
	if err := c.DeleteSubscription(first.ID); err != nil {
		t.Fatal(err)
	}
	g, err = c.groupView(g.ID, nil)
	if err != nil || len(g.Excluded) != 0 || slices.ContainsFunc(g.Views, func(m MemberView) bool { return m.ID == skip }) {
		t.Fatal("deleted subscription reintroduced an excluded server")
	}
}

// A group of more members than groups.MaxRunning runs only its chosen
// ones; rechoosing takes the fastest measured, keeps a running member
// against one within the tolerance and passes over failed ones.
func TestLargeGroupRunsChosen(t *testing.T) {
	c, started := newCtl(t)
	body := subBody(15, "m")
	v := addSub(t, c, &body)
	gv, err := c.SaveGroup(groups.Group{Name: "Большая", Strategy: groups.Latency, Subs: []string{v.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetMain(gv.ID); err != nil {
		t.Fatal(err)
	}
	st := c.Settings()
	st.DefaultAction = rules.Tunnel // everything through the main group
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	if n := len(f.cfg.Profiles); n != groups.MaxRunning {
		t.Fatalf("%d members run", n)
	}
	c.mu.Lock()
	g := c.groupLocked(gv.ID)
	all := c.membersLocked(g)
	cur := c.chosenLocked(gv.ID, all)
	c.mu.Unlock()
	if !slices.Equal(cur, all[:groups.MaxRunning]) {
		t.Fatalf("not the first ones: %v", cur)
	}
	// Measured: the last member is fast, the running ones slow; one
	// running member failed.
	for i, m := range all {
		c.groupsRT.NoteProbe(m, time.Duration(300+i)*time.Millisecond, nil)
	}
	c.groupsRT.NoteProbe(all[14], 20*time.Millisecond, nil)
	c.groupsRT.NoteProbe(all[13], 290*time.Millisecond, nil) // faster than the running ones, within the tolerance
	c.mu.Lock()
	c.scanned = map[string]scanResult{all[0]: {at: time.Now(), ok: false}}
	next := c.rechooseLocked(g, all, nil)
	c.mu.Unlock()
	if len(next) != groups.MaxRunning || next[0] != all[14] || slices.Contains(next, all[0]) || slices.Contains(next, all[13]) {
		t.Fatalf("%v", next)
	}
	// Two faster ones measured: one swap a round.
	c.groupsRT.NoteProbe(all[12], 100*time.Millisecond, nil)
	c.groupsRT.NoteProbe(all[11], 120*time.Millisecond, nil)
	c.mu.Lock()
	c.groupRun = map[string][]string{gv.ID: next}
	next2 := c.rechooseLocked(g, all, nil)
	c.mu.Unlock()
	swapped := 0
	for _, m := range next2 {
		if !slices.Contains(next, m) {
			swapped++
		}
	}
	if swapped != 1 || !slices.Contains(next2, all[12]) {
		t.Fatalf("swapped %d: %v", swapped, next2)
	}
}
