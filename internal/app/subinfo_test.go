package app

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/store"
)

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
	gib = int64(1) << 30
	tib = int64(1) << 40
)

func TestParseUserInfo(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // canonical form; "" = not ok
	}{
		{"upload=1; download=2; total=3; expire=4", "upload=1; download=2; total=3; expire=4"},
		{"  Upload = 1 ;DOWNLOAD=2;  Total=3 ", "upload=1; download=2; total=3"},
		{"upload=1,download=2,total=3", "upload=1; download=2; total=3"},
		{"total=100", "total=100"},
		{"upload=5; expire=", "upload=5"},
		{"expire=0", "expire=0"},
		{"upload=1.5e9; download=1712345678.0", "upload=1500000000; download=1712345678"},
		{"upload=-1; download=2", "download=2"},
		{"upload=9223372036854775807; total=5", "total=5"},
		{"upload=4611686018427387904; download=4611686018427387905", "upload=4611686018427387904"},
		{"upload=NaN; download=1e400; total=inf; expire=7", "expire=7"},
		{"upload=1; upload=2", "upload=1"},
		{"upload=x; upload=3", "upload=3"},
		{"expire=1791612000000", "expire=1791612000"},
		{"expire=253402300799; total=5", "total=5"},
		{"expire=946684799999; expire=7", "expire=7"},
		{"expire=946684800000", "expire=946684800"},
		{"garbage", ""},
		{"", ""},
		{"foo=1; bar=2", ""},
		{"upload=1;" + strings.Repeat(" ", maxInfoHeader-8), ""},
	} {
		got := normalizeUserInfo(tc.in)
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		if got != "" && normalizeUserInfo(got) != got {
			t.Errorf("%q: canonical form %q does not read back", tc.in, got)
		}
	}
	if _, ok := parseUserInfo("upload=1;" + strings.Repeat(" ", maxInfoHeader-9)); !ok {
		t.Error("a header of exactly maxInfoHeader bytes refused")
	}
}

func FuzzParseUserInfo(f *testing.F) {
	for _, s := range []string{"upload=1; download=2; total=3; expire=4", "expire=1791612000000", "total=1e400", "a=b,c=d;;=;", "upload=1.9;upload=2", "expire=199999999999999", "expire=253402300799", "expire=946684799999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := normalizeUserInfo(s)
		if normalizeUserInfo(n) != n {
			t.Fatalf("%q: %q is not canonical", s, n)
		}
		if u, ok := parseUserInfo(s); ok {
			newSubInfo(u, time.Unix(1_700_000_000, 0), time.Unix(1_700_000_000, 0))
		}
	})
}

var bigYear = regexp.MustCompile(`\d\d\.\d\d\.\d{5}`)

func FuzzSubInfo(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3), int64(4), true, true, true, true, int64(1_700_000_000))
	f.Add(maxInfoValue, maxInfoValue, maxInfoValue, int64(253402300799), true, true, true, true, int64(0))
	f.Add(int64(0), int64(0), unlimitedTotal-1, msExpire-1, false, true, true, true, int64(-1))
	f.Add(int64(0), int64(0), int64(0), int64(253402300), false, false, false, true, int64(1_790_000_000))
	f.Add(int64(-5), int64(math.MaxInt64), int64(math.MinInt64), int64(math.MaxInt64), true, true, true, true, int64(math.MaxInt64))
	f.Fuzz(func(t *testing.T, up, down, total, expire int64, hu, hd, ht, he bool, now int64) {
		u := userInfo{Upload: up, Download: down, Total: total, Expire: expire, HasUpload: hu, HasDownload: hd, HasTotal: ht, HasExpire: he}
		if now < 0 {
			now = -(now + 1)
		}
		at := time.Unix(now%(1<<40), 0)
		info := newSubInfo(u, at, at)
		if info == nil {
			return
		}
		if info.Percent != -1 && (info.Percent < 0 || info.Percent > 100) {
			t.Fatalf("percent %d", info.Percent)
		}
		if info.UsedPct < 0 || info.UsedPct > 100 || info.Left < 0 || info.Used < 0 {
			t.Fatalf("%+v", info)
		}
		for _, l := range []string{info.Level, info.trafficLevel, info.expireLevel} {
			if l != "" && l != "low" && l != "out" {
				t.Fatalf("level %q", l)
			}
		}
		if info.Summary == "" {
			t.Fatalf("empty summary: %+v", info)
		}
		for _, s := range []string{info.Summary, info.Details, info.Warning, info.UpDown} {
			if bigYear.MatchString(s) {
				t.Fatalf("year > 9999: %q", s)
			}
		}
		if a, ok := subAlertFor(store.Subscription{ID: "x"}, info, at.Add(100*time.Hour)); ok && bigYear.MatchString(a.Text) {
			t.Fatalf("year > 9999: %q", a.Text)
		}
	})
}

func info(t *testing.T, header string, at, now time.Time) *SubInfo {
	t.Helper()
	u, ok := parseUserInfo(header)
	if !ok {
		t.Fatalf("%q does not parse", header)
	}
	return newSubInfo(u, at, now)
}

func hdr(up, down, total, expire int64) string {
	s := "upload=" + strconv.FormatInt(up, 10) + "; download=" + strconv.FormatInt(down, 10)
	if total >= 0 {
		s += "; total=" + strconv.FormatInt(total, 10)
	}
	if expire >= 0 {
		s += "; expire=" + strconv.FormatInt(expire, 10)
	}
	return s
}

func TestSubInfoBigValues(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	i := info(t, hdr(1, 0, unlimitedTotal-1, -1), now, now)
	if i.Total != unlimitedTotal-1 || i.Unlimited || i.Percent != 99 || i.Level != "" {
		t.Fatalf("%+v", i)
	}
	for _, total := range []int64{unlimitedTotal, maxInfoValue} {
		i := info(t, hdr(5*gib, 0, total, -1), now, now)
		if !i.Unlimited || i.Total != 0 || !strings.HasPrefix(i.Summary, "Трафик без лимита") || i.trafficLevel != "" || i.Percent != -1 || i.UsedPct != 0 {
			t.Fatalf("total %d: %+v", total, i)
		}
	}
	T := int64(1) << 49
	if i := info(t, hdr(T-(T/10-1), 0, T, -1), now, now); i.Level != "low" {
		t.Fatalf("2^49: %+v", i)
	}
	if i := info(t, hdr(1001-100, 0, 1001, -1), now, now); i.Level != "low" {
		t.Fatalf("left = T/10 with a remainder: %+v", i)
	}
	if i := info(t, hdr(9, 0, 10, -1), now, now); i.Level != "" {
		t.Fatalf("10 %% left: %+v", i)
	}
	for _, e := range []int64{maxInfoValue, maxInfoValue / 1000 * 1000} {
		i := info(t, hdr(1, 1, 10*gib, e), now, now)
		if i.Expire != 0 || strings.Contains(i.Summary, "/") || strings.Contains(i.Details, "до ") {
			t.Fatalf("expire %d: %+v", e, i)
		}
	}
	// A far-future seconds value meaning "never" is not read as a 1978
	// date in milliseconds.
	if u, ok := parseUserInfo("expire=253402300799"); ok || u.HasExpire {
		t.Fatalf("%+v", u)
	}
	if i := info(t, "total=10; expire=253402300799", now, now); i == nil || i.Expire != 0 || i.Level != "" {
		t.Fatalf("%+v", i)
	}
}

func TestFmtSize(t *testing.T) {
	for n, want := range map[int64]string{
		0:                     "0 ГБ",
		500 * kib:             "<1 МБ",
		512 * mib:             "512 МБ",
		8 * gib:               "8.0 ГБ",
		frac(9.96, gib):       "9.9 ГБ",
		10*gib - 1:            "9.9 ГБ",
		frac(86.9, gib):       "86 ГБ",
		frac(1023.9, gib):     "1023 ГБ",
		tib + tib/2:           "1.5 ТБ",
		frac(12.7, tib):       "12 ТБ",
		maxInfoValue:          "4194304 ТБ",
		frac(1.25, gib):       "1.2 ГБ",
		frac(12.8, gib):       "12 ГБ",
		frac(1023.99, mib):    "1023 МБ",
		frac(9.999, tib) + 1:  "9.9 ТБ",
		frac(10.01, tib) + 1:  "10 ТБ",
		frac(0.999, mib) + 17: "<1 МБ",
	} {
		if got := fmtSize(n); got != want {
			t.Errorf("fmtSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestSubInfoText(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	day := int64(86400)
	e := func(d time.Duration) int64 { return now.Add(d).Unix() }

	i := info(t, hdr(4*gib, 10*gib, 100*gib, e(12*24*time.Hour+time.Hour)), now, now)
	if i.Summary != "Осталось 86 ГБ / 12 дней" || i.Level != "" || i.Percent != 86 || i.UsedPct != 14 || i.Warning != "" ||
		i.Details != "использовано 14 ГБ из 100 ГБ, до "+fmtDate(i.Expire) || i.UpDown != "↑ 4.0 ГБ ↓ 10 ГБ" || i.Left != 86*gib {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 92*gib, 100*gib, -1), now, now)
	if i.Level != "low" || i.Warning != "осталось 8.0 ГБ из 100 ГБ (8 %)" || i.Summary != "Осталось 8.0 ГБ" {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 100*gib-gib/2, 100*gib, -1), now, now)
	if i.Warning != "осталось 512 МБ из 100 ГБ (<1 %)" {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(gib, 100*gib, 100*gib, e(3*24*time.Hour+time.Hour)), now, now)
	if i.Level != "out" || i.Summary != "Трафик закончился / осталось 3 дня" || i.Warning != "трафик закончился (использовано 101 ГБ из 100 ГБ)" || i.Percent != 0 || i.UsedPct != 100 {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 100*gib, e(2*24*time.Hour+time.Minute)), now, now)
	if i.Level != "low" || i.Warning != "срок заканчивается через 2 дня, "+fmtDateHour(i.Expire) || !strings.Contains(i.Warning, " в ") {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 14*gib, 100*gib, e(5*time.Hour+time.Minute)), now, now)
	if i.Summary != "Осталось 86 ГБ / 5 ч" || i.Warning != "срок заканчивается через 5 ч, "+fmtDateHour(i.Expire) {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 14*gib, 100*gib, e(20*time.Minute)), now, now)
	if i.Summary != "Осталось 86 ГБ / меньше часа" || i.Warning != "срок заканчивается меньше чем через час, "+fmtDateHour(i.Expire) {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 100*gib, e(-3*24*time.Hour)), now, now)
	end := fmtDate(i.Expire)
	if i.Level != "out" || i.Summary != "Осталось 86 ГБ / срок истёк "+end || i.Warning != "срок истёк "+end ||
		i.Details != "использовано 14 ГБ из 100 ГБ, закончилась "+end || i.SecondsLeft >= 0 {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 0, e(30*24*time.Hour+time.Hour)), now, now)
	if i.Summary != "Трафик без лимита / осталось 30 дней" || !i.Unlimited || i.Level != "" {
		t.Fatalf("%+v", i)
	}
	i = info(t, "expire="+strconv.FormatInt(e(12*24*time.Hour+time.Hour), 10), now, now)
	if i.Summary != "Осталось 12 дней" || i.UpDown != "" {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(4*gib, 10*gib, -1, -1), now, now)
	if i.Summary != "Использовано 14 ГБ" || i.Details != "использовано 14 ГБ" || i.Percent != -1 {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(4*gib, 10*gib, 100*gib, 0), now, now)
	if i.Summary != "Осталось 86 ГБ" || i.Details != "использовано 14 ГБ из 100 ГБ" || i.Expire != 0 || i.SecondsLeft != 0 {
		t.Fatalf("%+v", i)
	}
	if i := info(t, "expire=0", now, now); i != nil {
		t.Fatalf("nothing to show: %+v", i)
	}

	for n, want := range map[int64]string{1: "1 день", 2: "2 дня", 5: "5 дней", 11: "11 дней", 21: "21 день", 22: "22 дня", 112: "112 дней"} {
		if got := fmtLeft(n*day + 5); got != want {
			t.Errorf("%d days: %q", n, got)
		}
	}
}

func TestSubAlertKey(t *testing.T) {
	now := time.Now()
	s := store.Subscription{ID: "a", Name: "A"}
	key := func(h string) string {
		a, ok := subAlertFor(s, info(t, h, now, now), now)
		if !ok {
			t.Fatalf("%q: no alert", h)
		}
		return a.Key
	}
	exp := now.Add(40 * 24 * time.Hour).Unix()
	low1 := key(hdr(0, 92*gib, 100*gib, exp))
	low2 := key(hdr(0, 95*gib, 100*gib, exp))
	out := key(hdr(0, 100*gib, 100*gib, exp))
	renewed := key(hdr(0, 92*gib, 100*gib, exp+30*86400))
	if low1 != low2 || low1 == out || low1 == renewed || low1 != "low|tlow|e|"+strconv.FormatInt(100*gib, 10)+"|"+strconv.FormatInt(exp, 10) {
		t.Fatal(low1, low2, out, renewed)
	}
	// A new reason at the same level is a new situation, both ways: a
	// dismissed traffic-low alert must not hide a later expiry-low one.
	soon := now.Add(100 * time.Hour).Unix()
	later := now.Add(40 * time.Hour) // 60 h left: expiry low as well
	keyAt := func(h string, at time.Time) string {
		a, ok := subAlertFor(s, info(t, h, now, at), at)
		if !ok {
			t.Fatalf("%q at %v: no alert", h, at)
		}
		return a.Key
	}
	trafficLow := keyAt(hdr(0, 92*gib, 100*gib, soon), now)
	bothLow := keyAt(hdr(0, 92*gib, 100*gib, soon), later)
	bothLow2 := keyAt(hdr(0, 95*gib, 100*gib, soon), later)
	expiryLow := keyAt(hdr(0, 10*gib, 100*gib, soon), later)
	if trafficLow == bothLow || expiryLow == bothLow || expiryLow == trafficLow || bothLow != bothLow2 || !strings.HasPrefix(bothLow, "low|tlow|elow|") {
		t.Fatal(trafficLow, bothLow, bothLow2, expiryLow)
	}
	// Traffic that does not count (time unknown) is not in the key.
	a, ok := subAlertFor(s, info(t, hdr(0, 92*gib, 100*gib, soon), time.Time{}, later), later)
	if !ok || a.Key != "low|t|elow|"+strconv.FormatInt(100*gib, 10)+"|"+strconv.FormatInt(soon, 10) {
		t.Fatal(a, ok)
	}
}

func TestSubAlertsPolicy(t *testing.T) {
	now := time.Now()
	far := now.Add(90 * 24 * time.Hour).Unix()
	alert := func(s store.Subscription) (SubAlert, bool) { return subAlertFor(s, subInfoAt(s, now), now) }

	// (a) Enabled only switches auto-update.
	for _, iv := range []string{"24h", "manual"} {
		s := store.Subscription{ID: "a", Name: "A", Interval: iv, UserInfo: hdr(0, 100*gib, 100*gib, far), InfoAt: now}
		if a, ok := alert(s); !ok || a.Level != "out" || a.Name != "A" || a.ID != "a" {
			t.Fatalf("%s: %+v %v", iv, a, ok)
		}
	}
	// (b) The time of the figures unknown: traffic raises nothing.
	s := store.Subscription{ID: "b", UserInfo: hdr(0, 100*gib, 100*gib, far)}
	if a, ok := alert(s); ok {
		t.Fatalf("%+v", a)
	}
	if i := subInfoAt(s, now); i.Level != "out" || !i.At.IsZero() {
		t.Fatalf("%+v", i)
	}
	s.UserInfo = hdr(0, 100*gib, 100*gib, now.Add(-time.Hour).Unix())
	if a, ok := alert(s); !ok || a.Level != "out" || a.Text != "срок истёк "+fmtDate(now.Add(-time.Hour).Unix()) {
		t.Fatalf("%+v %v", a, ok)
	}
	// (c) Stale figures carry their date, fresh ones do not; expiry never.
	s = store.Subscription{ID: "c", UserInfo: hdr(0, 92*gib, 100*gib, now.Add(48*time.Hour).Unix()), InfoAt: now.Add(-72 * time.Hour)}
	a, ok := alert(s)
	want := "осталось 8.0 ГБ из 100 ГБ (8 %, данные сервиса на " + now.Add(-72*time.Hour).Format("02.01.2006") + "); срок заканчивается через"
	if !ok || !strings.HasPrefix(a.Text, want) || strings.Count(a.Text, "данные сервиса") != 1 {
		t.Fatalf("%+v", a)
	}
	s.InfoAt = now.Add(-time.Hour)
	if a, _ := alert(s); strings.Contains(a.Text, "данные сервиса") {
		t.Fatalf("%+v", a)
	}
	// v1.0.0 file: lastUpdate is the time of the figures.
	s.InfoAt, s.LastUpdate = time.Time{}, now.Add(-72*time.Hour)
	if a, _ := alert(s); !strings.Contains(a.Text, "данные сервиса") {
		t.Fatalf("%+v", a)
	}
	// (d) Both halves, traffic first, the worse level.
	s = store.Subscription{ID: "d", UserInfo: hdr(0, 92*gib, 100*gib, now.Add(-time.Hour).Unix()), InfoAt: now}
	if a, ok := alert(s); !ok || a.Level != "out" || !strings.HasPrefix(a.Text, "осталось 8.0 ГБ") || !strings.Contains(a.Text, "; срок истёк") {
		t.Fatalf("%+v", a)
	}
	// Nothing to warn about.
	s = store.Subscription{ID: "e", UserInfo: hdr(0, gib, 100*gib, far), InfoAt: now}
	if a, ok := alert(s); ok {
		t.Fatalf("%+v", a)
	}
}

// fetchSeq serves the given results in turn to c.Fetch (the last one
// repeats).
type fetchSeq struct {
	mu  sync.Mutex
	res FetchResult
	err error
}

func (f *fetchSeq) set(r FetchResult, err error) {
	f.mu.Lock()
	f.res, f.err = r, err
	f.mu.Unlock()
}

func (f *fetchSeq) fetch(context.Context, string) (FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.res, f.err
}

const twoServers = "hy2://a@de1.example:443#DE1\nhy2://a@de2.example:443#DE2\n"

func addSubWith(t *testing.T, c *Controller, f *fetchSeq, r FetchResult) SubView {
	t.Helper()
	f.set(r, nil)
	c.Fetch = f.fetch
	pv, err := c.PreviewSubscription(subURL)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSubscriptionInfoLifecycle(t *testing.T) {
	c, _ := newCtl(t)
	f := &fetchSeq{}
	far := time.Now().Add(40*24*time.Hour + time.Hour).Unix()
	f.set(FetchResult{Body: []byte(twoServers), UserInfo: "Download=1073741824 , upload=0, total=10737418240, expire=" + strconv.FormatInt(far*1000, 10),
		Support: "https://t.me/some_support", UpdateHours: 12, Title: "Panel\u202e"}, nil)
	c.Fetch = f.fetch
	pv, err := c.PreviewSubscription(subURL)
	if err != nil || pv.Info == nil || pv.UpdateHours != 12 || pv.Title != "Panel" || pv.Info.At.IsZero() {
		t.Fatalf("%+v %v", pv, err)
	}
	v, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "24h"})
	if err != nil || v.Name != "Panel" {
		t.Fatal(v, err)
	}
	sv := c.Subscriptions()[0]
	if sv.Info == nil || sv.Info.Summary != "Осталось 9.0 ГБ / "+fmtLeft(far-time.Now().Unix()) || sv.InfoAt.IsZero() ||
		sv.Support != "https://t.me/some_support" || sv.UserInfo != "upload=0; download=1073741824; total=10737418240; expire="+strconv.FormatInt(far, 10) {
		t.Fatalf("%+v %+v", sv, sv.Info)
	}
	if st := c.Status(); len(st.SubAlerts) != 0 || !st.SubsOK {
		t.Fatalf("%+v", st.SubAlerts)
	}

	// Low numbers: one alert with the name.
	f.set(FetchResult{Body: []byte(twoServers), UserInfo: hdr(0, 9*gib+gib/2, 10*gib, far)}, nil)
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if len(st.SubAlerts) != 1 || st.SubAlerts[0].Name != "Panel" || st.SubAlerts[0].Level != "low" || st.SubAlerts[0].Text != "осталось 512 МБ из 10 ГБ (5 %)" {
		t.Fatalf("%+v", st.SubAlerts)
	}
	if c.Subscriptions()[0].Support != "" {
		t.Fatal("support link kept after an update without it")
	}
	at := c.Subscriptions()[0].InfoAt

	// A failed download keeps the figures and their time.
	f.set(FetchResult{}, errBoom)
	if _, err := c.UpdateSubscription(v.ID); err == nil {
		t.Fatal("want error")
	}
	if sv := c.Subscriptions()[0]; sv.Info == nil || sv.Info.Level != "low" || !sv.InfoAt.Equal(at) {
		t.Fatalf("%+v", sv)
	}

	// A successful update without the header clears them.
	f.set(FetchResult{Body: []byte(twoServers), Support: "https://t.me/x"}, nil)
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if sv := c.Subscriptions()[0]; sv.Info != nil || !sv.InfoAt.IsZero() || sv.UserInfo != "" || sv.Support != "https://t.me/x" {
		t.Fatalf("%+v", sv)
	}
	f.set(FetchResult{Body: []byte(twoServers), UserInfo: hdr(0, 10*gib, 10*gib, far)}, nil)
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); len(st.SubAlerts) != 1 || st.SubAlerts[0].Level != "out" {
		t.Fatalf("%+v", st.SubAlerts)
	}
	if err := c.DeleteSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); len(st.SubAlerts) != 0 {
		t.Fatalf("%+v", st.SubAlerts)
	}
}

var errBoom = errors.New("boom")

func TestRollbackKeepsInfoTime(t *testing.T) {
	c, _ := newCtl(t)
	f := &fetchSeq{}
	v := addSubWith(t, c, f, FetchResult{Body: []byte(twoServers), UserInfo: hdr(0, gib, 10*gib, -1)})
	f.set(FetchResult{Body: []byte("hy2://a@de3.example:443#DE3\n"), UserInfo: hdr(0, 2*gib, 10*gib, -1)}, nil)
	if _, err := c.UpdateSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	// As v1.0.0 left it: figures without infoAt.
	t0 := time.Now().Add(-20 * 24 * time.Hour).Truncate(time.Second)
	c.mu.Lock()
	c.subs[0].InfoAt, c.subs[0].LastUpdate = time.Time{}, t0
	c.mu.Unlock()
	if _, err := c.RollbackSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	sv := c.Subscriptions()[0]
	if !sv.InfoAt.Equal(t0) || sv.Info == nil || !sv.Info.At.Equal(t0) || sv.UserInfo != hdr(0, 2*gib, 10*gib, -1) {
		t.Fatalf("%+v", sv)
	}
	// Figures that have their time keep it.
	if _, err := c.RollbackSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if sv := c.Subscriptions()[0]; !sv.InfoAt.Equal(t0) {
		t.Fatalf("%+v", sv)
	}
}

func TestSubAlertKeysStableAcrossLoad(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newCtlAt(t, st)
	f := &fetchSeq{}
	exp := time.Now().Add(24 * time.Hour).Unix()
	addSubWith(t, c, f, FetchResult{Body: []byte(twoServers), UserInfo: hdr(0, 95*gib, 100*gib, exp)})
	keys := func(c *Controller) []string {
		var out []string
		for _, a := range c.Status().SubAlerts {
			out = append(out, a.Key)
		}
		return out
	}
	before := keys(c)
	c2, _ := newCtlAt(t, st)
	if after := keys(c2); len(before) != 1 || !slices.Equal(before, after) {
		t.Fatalf("%v != %v", before, after)
	}
}

func TestStatusSubsOK(t *testing.T) {
	c, _ := newCtl(t)
	if st := c.Status(); !st.SubsOK || st.SubAlerts == nil {
		t.Fatalf("%+v", st)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subscriptions.json"), []byte("[{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c = New(s, nil, c.Base, slog.LevelInfo)
	if err := c.Load(); err == nil {
		t.Fatal("broken subscriptions.json loaded")
	}
	if st := c.Status(); st.SubsOK || st.SubAlerts == nil || len(st.SubAlerts) != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestHTTPFetchPanelHeaders(t *testing.T) {
	var mu sync.Mutex
	var handler http.HandlerFunc
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := handler
		mu.Unlock()
		h(w, r)
	}))
	defer srv.Close()
	serve := func(h http.HandlerFunc) {
		mu.Lock()
		handler = h
		mu.Unlock()
	}
	c, _ := newCtl(t)
	ctx := context.Background()
	past := time.Now().Add(-3 * 24 * time.Hour).Unix()

	// (a) ms expire, mixed case, duplicates; (b) a title to clean; (g) the
	// support link.
	title := "A\x01B\u202eC\u2066D\u200bE\xffF\tG"
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "Upload=1; DOWNLOAD=2; upload=9; total=3; expire="+strconv.FormatInt(1791612000123, 10))
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(title)))
		w.Header().Set("Profile-Update-Interval", "12")
		w.Header().Set("Support-Url", "https://t.me/some_support")
		w.Write([]byte(twoServers))
	})
	res, err := c.fetch(ctx, srv.URL)
	if err != nil || res.UserInfo != "upload=1; download=2; total=3; expire=1791612000" || res.Title != "ABCDEF G" || res.UpdateHours != 12 ||
		res.Support != "https://t.me/some_support" || res.At.IsZero() {
		t.Fatalf("%+v %v", res, err)
	}
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Support-Url", "javascript:alert(1)")
		w.Write([]byte(twoServers))
	})
	if res, err := c.fetch(ctx, srv.URL); err != nil || res.Support != "" {
		t.Fatalf("%+v %v", res, err)
	}

	// (c) oversized values are dropped.
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1;"+strings.Repeat("x", maxInfoHeader+1-9))
		w.Header().Set("Support-Url", "https://t.me/"+strings.Repeat("a", maxLinkLen+1-13))
		w.Header().Set("Profile-Title", strings.Repeat("T", 4*maxInfoHeader+1))
		w.Write([]byte(twoServers))
	})
	if res, err := c.fetch(ctx, srv.URL); err != nil || res.UserInfo != "" || res.Support != "" || res.Title != "" {
		t.Fatalf("%+v %v", res, err)
	}

	// (d) headers over 64 KiB are refused by the transport.
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("x", 70<<10))
		w.Write([]byte(twoServers))
	})
	if _, err := c.fetch(ctx, srv.URL); err == nil || !strings.Contains(err.Error(), "недоступен") {
		t.Fatalf("%v", err)
	}

	// Add a subscription on the server.
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", hdr(0, gib, 10*gib, -1))
		w.Write([]byte(twoServers))
	})
	pv, err := c.PreviewSubscription(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	before := c.Subscriptions()[0]

	// (e) an error status: v1.0.0's text, its headers not read.
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", hdr(0, 10*gib, 10*gib, past))
		w.WriteHeader(http.StatusForbidden)
	})
	if _, err := c.UpdateSubscription(v.ID); err == nil || err.Error() != "сервер подписки ответил 403 Forbidden" {
		t.Fatalf("%v", err)
	}
	if sv := c.Subscriptions()[0]; sv.UserInfo != before.UserInfo || !sv.InfoAt.Equal(before.InfoAt) {
		t.Fatalf("%+v", sv)
	}

	// (f) 200 with an empty body: the error, and the panel's figures.
	serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", hdr(0, gib, 10*gib, past))
	})
	if _, err := c.UpdateSubscription(v.ID); err == nil || !strings.Contains(err.Error(), "пустая") {
		t.Fatalf("%v", err)
	}
	sv := c.Subscriptions()[0]
	if sv.LastError == "" || sv.Profiles != 2 || sv.Info == nil || sv.Info.Level != "out" || !sv.InfoAt.After(before.InfoAt) {
		t.Fatalf("%+v %+v", sv, sv.Info)
	}
	if _, err := c.PreviewSubscription(srv.URL); err == nil || err.Error() != "подписка пустая. Сервис сообщает: срок истёк "+fmtDate(past) {
		t.Fatalf("%v", err)
	}
}

func TestCleanTitleAndUpdateHours(t *testing.T) {
	for in, want := range map[string]string{
		"My VPN":                               "My VPN",
		"  a\r\n\tb  ":                         "a b",
		"x\x00\x07\x1by\u0085z":                "xy z", // NEL is a line break
		"ok\xff\xfe!":                          "ok!",
		"a\u202ab\u202bc\u202cd\u202de\u202ef": "abcdef",
		"a\u2066b\u2067c\u2068d\u2069e":        "abcde",
		"a\u200bb\u200cc\u200dd\u200ee\u200ff": "abcdef",
		"\ufeffBOM\u00adx":                     "BOMx",
		"p\ue000q\U000F0000r":                  "pqr",
		"a \u00a0\u3000 b":                     "a b",
	} {
		if got := cleanTitle(in); got != want {
			t.Errorf("cleanTitle(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("я", 150)
	if got := cleanTitle(long); got != strings.Repeat("я", maxTitleRunes) {
		t.Errorf("%d runes", len([]rune(got)))
	}
	for in, want := range map[string]int{"12": 12, " 6 ": 6, "8760": 8760, "0": 0, "-1": 0, "abc": 0, "9999": 0, "1.5": 0, "": 0} {
		if got := parseUpdateHours(in); got != want {
			t.Errorf("%q: %d", in, got)
		}
	}
}

func TestSafeLink(t *testing.T) {
	for in, want := range map[string]string{
		"https://t.me/some_support":          "https://t.me/some_support",
		"http://panel.example:8080/help?x=1": "http://panel.example:8080/help?x=1",
		"HTTPS://Example.com/a b":            "",
		"https://example.com/путь":           "https://example.com/%D0%BF%D1%83%D1%82%D1%8C",
	} {
		if got := safeLink(in); got != want {
			t.Errorf("safeLink(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"", "javascript:alert(1)", "file:///C:/x.exe", "tg://resolve?domain=x", "data:text/html,x", "ms-settings:network",
		`\\host\share`, `C:\x.exe`, "/relative/path", "t.me/x", "https:///path", "https://user:pw@example.com/",
		"https://example.com/a b", `https://example.com/"x"`, "https://example.com/<x>", "https://example.com/\r\nX: y",
		"https://example.com/\u202e", "https://example.com/{x}", "https://example.com/a|b", "https://example.com/a^b", "https://example.com/`",
		"https://t.me/" + strings.Repeat("a", maxLinkLen), "https://example.com/\xff",
	} {
		if got := safeLink(bad); got != "" {
			t.Errorf("safeLink(%q) = %q", bad, got)
		}
	}
}

func TestSupportLinkTampered(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSubscriptions([]store.Subscription{
		{ID: "bad", Name: "bad", URL: subURL, Interval: "manual", Support: "file:///C:/x.exe"},
		{ID: "none", Name: "none", URL: subURL, Interval: "manual"},
		{ID: "good", Name: "good", URL: subURL, Interval: "manual", Support: "https://t.me/ok"},
	}); err != nil {
		t.Fatal(err)
	}
	c, _ := newCtlAt(t, st)
	if v := c.Subscriptions(); v[0].Support != "" || v[2].Support != "https://t.me/ok" {
		t.Fatalf("%+v", v)
	}
	for id, want := range map[string]string{"bad": "небезопасна", "none": "не указал", "gone": "не найдена"} {
		if _, err := c.SupportLink(id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if u, err := c.SupportLink("good"); err != nil || u != "https://t.me/ok" {
		t.Fatal(u, err)
	}
}

// The support link is public and not a Redactor group: a word of it must
// not be masked everywhere.
func TestSupportLinkNotRedacted(t *testing.T) {
	c, _ := newCtl(t)
	addSubWith(t, c, &fetchSeq{}, FetchResult{Body: []byte(twoServers), Support: "https://site.example/contacts/telegram"})
	c.Log.Info("resolving", "host", "api.telegram.org")
	found := false
	for _, e := range c.Logs("engine", 0) {
		found = found || strings.Contains(e.Msg, "api.telegram.org")
	}
	if !found {
		t.Fatal("support link words redacted in logs")
	}
}

func TestDiagnosticsSubInfo(t *testing.T) {
	c, _ := newCtl(t)
	c.Version = "test"
	addSubWith(t, c, &fetchSeq{}, FetchResult{Body: []byte(twoServers), UserInfo: hdr(0, 14*gib, 100*gib, -1), Support: "https://t.me/some_support"})
	d := c.Diagnostics(nil, false)
	sv := c.Subscriptions()[0]
	want := " | Осталось 86 ГБ (использовано 14 ГБ из 100 ГБ, данные на " + fmtTime(sv.InfoAt) + ")"
	if !strings.Contains(d, want) || strings.Contains(d, "some_support") || strings.Contains(d, "SECRETTOKEN123") {
		t.Fatal(d)
	}
	// Without a time: no «данные на».
	if s := subDiagSuffix(SubView{Info: &SubInfo{Summary: "Осталось 12 дней", Details: "до 10.10.2026"}}); s != " | Осталось 12 дней (до 10.10.2026)" {
		t.Fatal(s)
	}
	if s := subDiagSuffix(SubView{}); s != "" {
		t.Fatal(s)
	}
}

// With the feature unused nothing new is written: no new file, and no new
// key in subscriptions.json.
func TestSubInfoUnusedWritesNothing(t *testing.T) {
	c, _ := newCtl(t)
	list := func() []string {
		var out []string
		filepath.WalkDir(c.Store.Dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out = append(out, p)
			}
			return nil
		})
		return out
	}
	before := list()
	c.Status()
	c.Subscriptions()
	c.SupportLink("x")
	c.Diagnostics(nil, true)
	if after := list(); !slices.Equal(before, after) {
		t.Fatalf("%v -> %v", before, after)
	}
	addSubWith(t, c, &fetchSeq{}, FetchResult{Body: []byte(twoServers)})
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "infoAt") || strings.Contains(string(b), "supportUrl") {
		t.Fatalf("%s", b)
	}
}

// frac is x units in bytes, truncated.
func frac(x float64, unit int64) int64 { return int64(x * float64(unit)) }
