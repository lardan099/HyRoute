package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
)

// Subscription intervals.
var intervals = map[string]time.Duration{"6h": 6 * time.Hour, "12h": 12 * time.Hour, "24h": 24 * time.Hour}

func validInterval(s string) bool {
	_, ok := intervals[s]
	return ok || s == "manual" || s == "startup"
}

const maxSubBody = 5 << 20

// FetchResult is a downloaded subscription.
type FetchResult struct {
	Body     []byte
	Title    string // profile-title header
	UserInfo string // subscription-userinfo header
	// subinfo: after clean, Title is cleanTitle'd and UserInfo canonical or
	// "". profile-update-interval in hours (0 = not sent), support-url
	// (safeLink'ed or ""), and when it was downloaded.
	UpdateHours int
	Support     string
	At          time.Time
	// ViaVPN: the direct download failed and this one went through the
	// main server's tunnel.
	ViaVPN bool
}

// directTransport is http.DefaultTransport without a proxy: HyRoute's own
// requests go straight to the server, never through the HTTP_PROXY or
// HTTPS_PROXY of the user's environment (a proxy that is not running yet
// at logon, or another VPN, which would also see an http:// link whole).
// dns: InstallOwnDial makes it dial through OwnDial; a new direct HTTP
// client must use it, http.DefaultTransport or OwnDial.
var directTransport = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	// subinfo: the panel's headers are read, so all of them are bounded.
	tr.MaxResponseHeaderBytes = 64 << 10
	return tr
}()

// maxSubErrors bounds the parse errors a subscription keeps of its last
// update.
const maxSubErrors = 5

// subClient is the client of subscription downloads. A redirect from
// https to http would send the token in the link and the servers'
// passwords in the body in clear text: it is refused, as for the rule
// databases.
func subClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: directTransport, CheckRedirect: geodata.NoDowngrade}
}

// subTunnelClient downloads a subscription through tun (the main
// server's tunnel), for a panel the network blocks: as subClient, with
// the same header bound.
func subTunnelClient(tun interface {
	Dial(context.Context, socks5.Addr) (net.Conn, error)
}) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: geodata.NoDowngrade, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			pn, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			return tun.Dial(ctx, socks5.Addr{Host: host, Port: uint16(pn)})
		},
		TLSHandshakeTimeout:    20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}}
}

// httpFetch downloads a subscription. HyRoute's own traffic is never
// routed, so this goes straight to the subscription server (dns: through
// directTransport, whose OwnDial registers each host it dials, a redirect's
// too, as HyRoute's own name).
func (c *Controller) httpFetch(ctx context.Context, rawURL string) (FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return FetchResult{}, errors.New("ссылка подписки должна начинаться с https:// (или http://)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", "HyRoute/"+c.Version)
	req.Header.Set("Accept", "text/plain, */*")
	resp, err := subClient().Do(req)
	viaVPN := false
	if failed := err != nil || resp.StatusCode >= 500; failed && u.Scheme == "https" {
		// A panel the network blocks: once more through the main server's
		// tunnel, as the rule databases do (https only: the VPN server
		// must not see the token).
		if tun := c.mainEndpoint(); tun != nil {
			if r2, err2 := subTunnelClient(tun).Do(req.Clone(ctx)); err2 == nil {
				if resp != nil {
					resp.Body.Close()
				}
				resp, err, viaVPN = r2, nil, true
			} else if err != nil {
				err = err2 // both failed: the tunnel's error is as good
			}
		}
	}
	if err != nil {
		// The error text contains the URL: never show it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return FetchResult{}, fmt.Errorf("сервер подписки недоступен: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("сервер подписки ответил %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubBody+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("ответ подписки оборван: %v", err)
	}
	if len(body) > maxSubBody {
		return FetchResult{}, errors.New("ответ подписки больше 5 МБ")
	}
	res := panelHeaders(resp.Header)
	res.Body, res.ViaVPN = body, viaVPN
	return res, nil
}

// decodeTitle handles "base64:..." titles used by common panels.
func decodeTitle(s string) string {
	if rest, ok := strings.CutPrefix(s, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return string(b)
		}
	}
	return s
}

func (c *Controller) fetch(ctx context.Context, u string) (FetchResult, error) {
	fetch := c.httpFetch
	if c.Fetch != nil {
		fetch = c.Fetch
	}
	res, err := fetch(ctx, u)
	if err == nil {
		res = res.clean()
		res.At = time.Now()
	}
	return res, err
}

// parseSubscription turns a body into profiles or an error that explains
// what came instead.
func parseSubscription(body []byte) (Links, error) {
	l := ParseLinks(string(body))
	if len(l.Profiles) > 0 {
		return l, nil
	}
	t := strings.TrimSpace(string(body))
	switch {
	case t == "":
		return l, errors.New("подписка пустая")
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		return l, errors.New("похоже на JSON-конфиг (sing-box/Xray): нужна подписка со списком ссылок hysteria2://")
	case strings.Contains(t, "proxies:") || strings.HasPrefix(t, "port:") || strings.HasPrefix(t, "mixed-port:"):
		return l, errors.New("похоже на конфиг Clash: нужна подписка со списком ссылок hysteria2://")
	case strings.HasPrefix(strings.ToLower(t), "<!doctype") || strings.HasPrefix(strings.ToLower(t), "<html"):
		return l, errors.New("сервер вернул веб-страницу, а не подписку: проверьте ссылку")
	case len(l.Errors) > 0:
		// Its own links come first: the other protocols are not the issue.
		msg := fmt.Sprintf("ни одна ссылка Hysteria 2 не разобрана (%d): %s", len(l.Errors), l.Errors[0])
		if l.IgnoredTotal() > 0 {
			msg += "; других протоколов: " + ignoredText(l.Ignored)
		}
		return l, errors.New(msg)
	case l.IgnoredTotal() > 0:
		return l, fmt.Errorf("в подписке нет профилей Hysteria 2, только другие протоколы (%s)", ignoredText(l.Ignored))
	case !strings.ContainsAny(t, "\r\n") && utf8.RuneCountInString(t) <= 200:
		// A panel's short answer in words ("подписка истекла…") says more
		// than any guess.
		return l, fmt.Errorf("сервер подписки ответил текстом, а не ссылками: «%s»", t)
	}
	return l, errors.New("в ответе нет ссылок hysteria2:// или hy2://")
}

func ignoredText(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s: %d", k, v))
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

// MaskURL shows only the scheme and host: path and query usually carry the
// token.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// urlSecrets are the redactor entries for a subscription URL: the URL and
// every path segment and query value long enough to be a token.
func urlSecrets(raw string) []string {
	out := []string{raw}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if len(seg) >= 8 {
			out = append(out, seg)
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			if len(v) >= 8 {
				out = append(out, v)
			}
		}
	}
	if u.User != nil {
		out = append(out, u.User.String())
	}
	return out
}

// SubView is a subscription for the UI (URL masked).
type SubView struct {
	store.Subscription
	URLMasked string    `json:"url"`
	Profiles  int       `json:"profiles"` // profiles currently from it
	Missing   int       `json:"missing"`
	NextAt    time.Time `json:"nextAt"`
	Info      *SubInfo  `json:"info"` // subinfo: nil when the panel reports nothing
}

func (c *Controller) Subscriptions() []SubView {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []SubView{}
	now := time.Now()
	for _, s := range c.subs {
		v := SubView{Subscription: s, URLMasked: MaskURL(s.URL), Info: subInfoAt(s, now)}
		v.URL = ""
		v.Support = safeLink(s.Support) // subinfo: the file is user-writable
		for _, p := range c.profiles.List {
			if p.Source == "sub:"+s.ID {
				v.Profiles++
				if p.Missing {
					v.Missing++
				}
			}
		}
		if d, ok := intervals[s.Interval]; ok && s.Enabled {
			v.NextAt = s.LastAttempt.Add(d)
		}
		out = append(out, v)
	}
	return out
}

func (c *Controller) sourceNameLocked(source string) string {
	id, ok := strings.CutPrefix(source, "sub:")
	if !ok {
		return ""
	}
	for _, s := range c.subs {
		if s.ID == id {
			return s.Name
		}
	}
	return "удалённая подписка"
}

// Preview is shown before a subscription is added.
type Preview struct {
	Token    string         `json:"token"`
	Title    string         `json:"title"`
	Count    int            `json:"count"`
	Names    []string       `json:"names"`
	Ignored  map[string]int `json:"ignored"`
	IgnoredN int            `json:"ignoredTotal"`
	Warnings []string       `json:"warnings"`
	Errors   []string       `json:"errors"`
	Base64   bool           `json:"base64"`
	// subinfo: the panel's figures (nil: none) and its advised interval.
	Info        *SubInfo `json:"info"`
	UpdateHours int      `json:"updateHours"`
}

type pendingSub struct {
	url string
	res FetchResult
	at  time.Time
}

// PreviewSubscription downloads and parses a subscription without saving
// anything. AddSubscription then uses exactly this body.
func (c *Controller) PreviewSubscription(rawURL string) (Preview, error) {
	rawURL = strings.TrimSpace(rawURL)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := c.fetch(ctx, rawURL)
	if err != nil {
		return Preview{}, err
	}
	l, err := parseSubscription(res.Body)
	if err != nil {
		return Preview{}, previewInfoErr(err, res)
	}
	pv := Preview{Token: newID(), Title: res.Title, Count: len(l.Profiles), Ignored: l.Ignored, IgnoredN: l.IgnoredTotal(),
		Warnings: l.Warnings, Errors: l.Errors, Base64: l.Base64, Names: []string{}}
	pv.Info, pv.UpdateHours = fetchedInfo(res), res.UpdateHours
	if strings.HasPrefix(strings.ToLower(rawURL), "http://") {
		// The link usually carries the account token; over plain HTTP the
		// provider and anyone on the network can read and reuse it.
		pv.Warnings = append([]string{"Ссылка без шифрования (http://): токен подписки видят провайдер и все в сети. Если панель поддерживает https://, используйте его."}, pv.Warnings...)
	}
	for i, p := range l.Profiles {
		if i == 100 {
			break
		}
		pv.Names = append(pv.Names, p.Name)
	}
	c.mu.Lock()
	if c.pending == nil {
		c.pending = map[string]pendingSub{}
	}
	for k, v := range c.pending {
		if time.Since(v.at) > 15*time.Minute {
			delete(c.pending, k)
		}
	}
	c.pending[pv.Token] = pendingSub{url: rawURL, res: res, at: time.Now()}
	c.mu.Unlock()
	return pv, nil
}

// subURLTakenLocked refuses a link another subscription (not except) has:
// a second copy would duplicate every server, and both would be fetched.
func (c *Controller) subURLTakenLocked(link, except string) error {
	for _, s := range c.subs {
		if s.ID != except && sameSubURL(s.URL, link) {
			return fmt.Errorf("эта подписка уже добавлена: «%s»", s.Name)
		}
	}
	return nil
}

// sameSubURL: two spellings of one link (the scheme and host in any case).
func sameSubURL(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return true
	}
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	ua.Scheme, ua.Host = strings.ToLower(ua.Scheme), strings.ToLower(ua.Host)
	ub.Scheme, ub.Host = strings.ToLower(ub.Scheme), strings.ToLower(ub.Host)
	return ua.String() == ub.String()
}

// SubInput creates or edits a subscription. Token is a preview's
// (PreviewSubscription): the link to add, or on edit the subscription's
// new link (empty = keep). A link is never taken unchecked.
type SubInput struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
}

// AddSubscription saves a previewed subscription and imports its profiles.
func (c *Controller) AddSubscription(in SubInput) (SubView, error) {
	if !validInterval(in.Interval) {
		return SubView{}, fmt.Errorf("неизвестный интервал %q", in.Interval)
	}
	c.mu.Lock()
	pend, ok := c.pending[in.Token]
	delete(c.pending, in.Token)
	c.mu.Unlock()
	if !ok {
		return SubView{}, errors.New("предпросмотр устарел: нажмите «Проверить» ещё раз")
	}
	c.mu.Lock()
	err := c.subURLTakenLocked(pend.url, "")
	c.mu.Unlock()
	if err != nil {
		return SubView{}, err
	}
	sub := store.Subscription{ID: newID(), Name: strings.TrimSpace(in.Name), URL: pend.url, Enabled: in.Enabled, Interval: in.Interval}
	if sub.Name == "" {
		sub.Name = pend.res.Title
	}
	if sub.Name == "" {
		if u, err := url.Parse(pend.url); err == nil {
			sub.Name = u.Hostname()
		}
	}
	c.Redactor.SetGroup("sub:"+sub.ID, urlSecrets(sub.URL)...)
	// The scheduler sees the subscription once it is in c.subs: its update
	// waits until the first import is done or taken back.
	defer c.lockSub(sub.ID)()
	// subscriptions.json first: profiles of a subscription that never
	// reached it would be orphans that nothing updates or deletes.
	c.mu.Lock()
	subs := append(slices.Clone(c.subs), sub)
	if err := c.saveSubsLocked(subs); err != nil {
		c.mu.Unlock()
		return SubView{}, err
	}
	c.subs = subs
	c.mu.Unlock()
	if _, err := c.applyFetched(sub.ID, pend.res, false, time.Time{}); err != nil {
		// Nothing imported: take the subscription back out. Once its
		// profiles are saved it stays (only its snapshot or status was not
		// saved).
		c.mu.Lock()
		imported := slices.ContainsFunc(c.profiles.List, func(p hysteria.Profile) bool { return p.Source == "sub:"+sub.ID })
		if !imported {
			subs := slices.DeleteFunc(slices.Clone(c.subs), func(s store.Subscription) bool { return s.ID == sub.ID })
			if c.saveSubsLocked(subs) == nil {
				c.subs = subs
			}
		}
		c.mu.Unlock()
		if !imported {
			c.Store.DeleteSnapshots(sub.ID)
		}
		c.changed()
		return SubView{}, err
	}
	for _, v := range c.Subscriptions() {
		if v.ID == sub.ID {
			return v, nil
		}
	}
	return SubView{}, nil
}

// EditSubscription changes name, interval or enabled, and the link when
// in.Token is the preview of a new one: the previewed body is applied as
// the update, so the new link is not downloaded twice, and one that did
// not download or parse never replaces a working one (there is no token).
// A link change is an update: it waits for a running one, which would
// otherwise apply the old link's list over the new one.
func (c *Controller) EditSubscription(in SubInput) error {
	if !validInterval(in.Interval) {
		return fmt.Errorf("неизвестный интервал %q", in.Interval)
	}
	if in.Token != "" {
		defer c.lockSub(in.ID)()
	}
	c.mu.Lock()
	next := slices.Clone(c.subs)
	i := slices.IndexFunc(next, func(s store.Subscription) bool { return s.ID == in.ID })
	if i < 0 {
		c.mu.Unlock()
		return errors.New("подписка не найдена")
	}
	var pend pendingSub
	if in.Token != "" {
		var ok bool
		pend, ok = c.pending[in.Token]
		delete(c.pending, in.Token)
		if !ok {
			c.mu.Unlock()
			return errors.New("проверка ссылки устарела: смените ссылку ещё раз")
		}
		if err := c.subURLTakenLocked(pend.url, in.ID); err != nil {
			c.mu.Unlock()
			return err
		}
		// The old link stays masked too: its token may still work, and it
		// stays in use if the save fails.
		c.Redactor.SetGroup("sub:"+in.ID, slices.Concat(urlSecrets(pend.url), urlSecrets(next[i].URL))...)
		next[i].URL = pend.url
	}
	if n := strings.TrimSpace(in.Name); n != "" {
		next[i].Name = n
	}
	next[i].Enabled, next[i].Interval = in.Enabled, in.Interval
	if err := c.saveSubsLocked(next); err != nil {
		c.mu.Unlock()
		return err
	}
	c.subs = next
	c.mu.Unlock()
	if in.Token == "" {
		return nil
	}
	_, err := c.applyFetched(in.ID, pend.res, false, time.Time{})
	return err
}

// subLock is one subscription's lock; n counts its holder and waiters, so
// the entry goes once nobody needs it.
type subLock struct {
	mu sync.Mutex
	n  int
}

// lockSub takes subscription id's lock and returns its unlock. An update,
// a rollback, a link change and the first import each change the snapshots,
// the profiles and the status in several steps: one at a time per
// subscription, while different subscriptions go in parallel. Not with mu
// held.
func (c *Controller) lockSub(id string) (unlock func()) {
	c.subMu.Lock()
	if c.subLocks == nil {
		c.subLocks = map[string]*subLock{}
	}
	l := c.subLocks[id]
	if l == nil {
		l = &subLock{}
		c.subLocks[id] = l
	}
	l.n++
	c.subMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		c.subMu.Lock()
		if l.n--; l.n == 0 {
			delete(c.subLocks, id)
		}
		c.subMu.Unlock()
	}
}

// UpdateSubscription downloads the subscription and replaces its profiles
// only when the new list parses; errors leave the old list untouched.
// A second update of the same subscription (the scheduler and the button)
// waits for the running one and then downloads again: it answers for the
// subscription as it is then (an edited link included).
func (c *Controller) UpdateSubscription(id string) (MergeStats, error) {
	return c.updateSubscription(id, time.Time{})
}

// updateSubscription is UpdateSubscription; a non-zero tag marks the
// refresh a backup's restore started (backup.go refreshAfterRestore).
func (c *Controller) updateSubscription(id string, tag time.Time) (MergeStats, error) {
	defer c.lockSub(id)()
	c.mu.Lock()
	i := slices.IndexFunc(c.subs, func(s store.Subscription) bool { return s.ID == id })
	if i < 0 {
		c.mu.Unlock()
		return MergeStats{}, errors.New("подписка не найдена")
	}
	sub := c.subs[i]
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := c.fetch(ctx, sub.URL)
	if err != nil {
		c.recordSubError(id, err, tag)
		return MergeStats{}, err
	}
	return c.applyFetched(id, res, false, tag)
}

// RollbackSubscription re-applies the previous successful body (after an
// update in progress). The snapshots swap only once its profiles are
// saved: a rollback that failed leaves them as they were.
func (c *Controller) RollbackSubscription(id string) (MergeStats, error) {
	defer c.lockSub(id)()
	body, err := c.Store.PreviousSnapshot(id)
	if err != nil {
		return MergeStats{}, err
	}
	st, err := c.applyFetched(id, FetchResult{Body: body}, true, time.Time{})
	if err == nil {
		c.Log.Info("subscription rolled back to the previous version", "subscription", c.subName(id))
	}
	return st, err
}

func (c *Controller) subName(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.subs {
		if s.ID == id {
			return s.Name
		}
	}
	return id
}

// recordSubError stores a failed update as the subscription's last error
// (tag: as in updateSubscription).
func (c *Controller) recordSubError(id string, err error, tag time.Time) {
	c.recordSubErrorInfo(id, err, "", time.Time{}, tag)
}

// recordSubErrorInfo is recordSubError that also stores the panel's
// figures from an answer whose body did not parse (an expired account
// answered 200 with an empty list or a web page). Empty userInfo keeps the
// old figures.
func (c *Controller) recordSubErrorInfo(id string, err error, userInfo string, at time.Time, tag time.Time) {
	c.mu.Lock()
	restoreHashes := c.restoreHashesLocked(tag) // backup: a post-restore refresh that failed
	next := slices.Clone(c.subs)
	if i := slices.IndexFunc(next, func(s store.Subscription) bool { return s.ID == id }); i >= 0 {
		next[i].LastAttempt, next[i].LastError = time.Now(), err.Error()
		if userInfo != "" {
			next[i].UserInfo, next[i].InfoAt = userInfo, at
		}
		// Kept even when subscriptions.json cannot be saved: the error
		// shows, and the scheduler retries at its pace, not every minute.
		c.saveSubsLocked(next)
		c.restoreHashesAfterLocked(tag, restoreHashes) // backup
		c.subs = next
	}
	c.mu.Unlock()
	c.Log.Warn("subscription update failed, previous profiles kept", "subscription", c.subName(id), "err", err)
	c.changed()
}

// applyFetched parses res and, only if that succeeds, merges the profiles
// and then stores the body as the current snapshot (rollback: res is the
// previous snapshot, and the two swap). A failure is the subscription's
// last error.
func (c *Controller) applyFetched(id string, res FetchResult, rollback bool, tag time.Time) (MergeStats, error) {
	l, err := parseSubscription(res.Body)
	if err != nil {
		c.recordSubErrorInfo(id, err, res.UserInfo, res.At, tag)
		return MergeStats{}, err
	}
	source := "sub:" + id
	c.mu.Lock()
	i := slices.IndexFunc(c.subs, func(s store.Subscription) bool { return s.ID == id })
	if i < 0 {
		c.mu.Unlock()
		return MergeStats{}, errors.New("подписка не найдена")
	}
	list, st := c.mergeKeepingGroupsLocked(source, l.Profiles)
	next := &store.Profiles{Active: c.profiles.Active, List: list}
	if next.Find(next.Active) == nil {
		next.Active = ""
		if len(list) > 0 {
			next.Active = list[0].ID
		}
	}
	restoreHashes := c.restoreHashesLocked(tag) // backup: a post-restore refresh
	// Profiles first: the snapshots follow only a list that was applied,
	// so a failed save leaves them, and what a rollback returns to, as
	// they were.
	if err := c.saveProfilesLocked(next); err != nil {
		c.mu.Unlock()
		c.recordSubError(id, err, tag)
		return st, err
	}
	var snapErr error
	if rollback {
		snapErr = c.Store.SwapSnapshots(id)
	} else {
		// The same servers again (other names, another order) keep the
		// version a rollback returns to.
		snapErr = c.Store.PushSnapshot(id, res.Body, func(cur []byte) bool {
			return sameServers(ParseLinks(string(cur)).Profiles, l.Profiles)
		})
	}
	subs := slices.Clone(c.subs)
	s := &subs[i]
	now := time.Now()
	if rollback && s.UserInfo != "" && s.InfoAt.IsZero() {
		// subinfo: a rollback keeps the old figures; date them by the
		// download they came with, not by now (v1.0.0 files have no infoAt).
		s.InfoAt = s.LastUpdate
	}
	s.LastUpdate, s.LastAttempt, s.LastError = now, now, ""
	if snapErr != nil {
		// The profiles are applied; a rollback may now return to an older
		// version than the one before them.
		snapErr = fmt.Errorf("не удалось сохранить снимок подписки: %w", snapErr)
		s.LastError = snapErr.Error()
	}
	s.Count, s.Ignored, s.Warnings = len(l.Profiles), l.Ignored, l.Warnings
	s.Errors, s.ErrorCount = l.Errors[:min(len(l.Errors), maxSubErrors)], len(l.Errors)
	if res.UserInfo != "" || !rollback {
		s.UserInfo, s.InfoAt = res.UserInfo, res.At // "" clears, and InfoAt with it
		if res.UserInfo == "" {
			s.InfoAt = time.Time{}
		}
	}
	if !rollback {
		s.Support = res.Support // subinfo: "" clears (the panel stopped sending it)
		s.ViaVPN = res.ViaVPN
	}
	s.HasPrevious = c.Store.HasPrevious(id)
	err = c.saveSubsLocked(subs)
	c.restoreHashesAfterLocked(tag, restoreHashes) // backup
	// The status is kept even when it cannot be saved (see recordSubError).
	c.subs = subs
	c.mu.Unlock()
	if err == nil {
		err = snapErr
	}
	c.Log.Info("subscription updated", "subscription", s.Name, "profiles", len(l.Profiles), "added", st.Added,
		"updated", st.Updated, "removed", st.Removed, "missingKept", st.MissingKept, "ignored", l.IgnoredTotal(),
		"unreadable", len(l.Errors))
	c.changed()
	return st, err
}

// profileUsedLocked reports whether profile id must outlive its
// subscription dropping it: it is the main one, or a rule or a local proxy
// names it (its ID would be lost, and they would refuse their traffic).
// While settings.json, proxies.json or groups.json is not loaded their
// references are unknown, and every profile counts as used. (A group's
// members are kept only so that a used group is never emptied:
// groupPinsLocked.)
func (c *Controller) profileUsedLocked(id string) bool {
	return id == c.profiles.Active || c.refsUnknownLocked() != nil || c.groupsBroken != nil ||
		len(c.explicitRefsLocked(id)) > 0 || len(c.proxyRefsLocked(id)) > 0
}

// proxyRefsLocked lists local proxies that name profile id explicitly.
func (c *Controller) proxyRefsLocked(id string) []string {
	var out []string
	for _, p := range c.proxies {
		if p.Profile == id {
			out = append(out, "прокси «"+p.Name+"»")
		}
	}
	return out
}

// DeleteSubscription removes the subscription. Its profiles that rules or
// proxies use become manual profiles (so they keep working); the rest go.
// It does not wait for an update in progress: that one finds the
// subscription gone (under mu) and stores nothing. subscriptions.json goes
// first and is put back when the profiles cannot be saved: a subscription
// never stays without its profiles, snapshots and masked link.
func (c *Controller) DeleteSubscription(id string) error {
	source := "sub:" + id
	c.mu.Lock()
	subs := slices.DeleteFunc(slices.Clone(c.subs), func(s store.Subscription) bool { return s.ID == id })
	if err := c.saveSubsLocked(subs); err != nil {
		c.mu.Unlock()
		return err
	}
	var list []hysteria.Profile
	pins := c.subDeletePinsLocked(source)
	for _, p := range c.profiles.List {
		if p.Source != source {
			list = append(list, p)
			continue
		}
		if c.profileUsedLocked(p.ID) || pins[p.ID] {
			p.Source, p.Missing = "", false
			list = append(list, p)
		}
	}
	next := &store.Profiles{Active: c.profiles.Active, List: list}
	err := c.saveProfilesLocked(next)
	if err != nil && c.saveSubsLocked(c.subs) == nil {
		c.mu.Unlock()
		return err
	}
	// Gone from subscriptions.json: when its profiles could not be saved
	// either, they stay as those of a deleted subscription.
	c.subs = subs
	c.mu.Unlock()
	c.Store.DeleteSnapshots(id)
	c.Redactor.SetGroup("sub:" + id)
	c.changed()
	return err
}

// RunScheduler updates enabled subscriptions: "startup" ones once now
// (retried until that succeeds), interval ones when due. It returns when
// ctx ends.
func (c *Controller) RunScheduler(ctx context.Context) {
	started := time.Now()
	c.mu.Lock()
	var startup []string
	for _, s := range c.subs {
		if s.Enabled && s.Interval != "manual" {
			startup = append(startup, s.ID)
		}
	}
	c.mu.Unlock()
	for _, id := range startup {
		c.mu.Lock()
		i := slices.IndexFunc(c.subs, func(s store.Subscription) bool { return s.ID == id })
		due := i >= 0 && (c.subs[i].Interval == "startup" || c.due(c.subs[i], time.Now(), started))
		c.mu.Unlock()
		if due {
			c.UpdateSubscription(id)
		}
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.mu.Lock()
			var ids []string
			for _, s := range c.subs {
				if c.due(s, now, started) {
					ids = append(ids, s.ID)
				}
			}
			c.mu.Unlock()
			for _, id := range ids {
				c.UpdateSubscription(id)
			}
		}
	}
}

// due reports whether s should be updated at now; started is when the
// scheduler started.
func (c *Controller) due(s store.Subscription, now, started time.Time) bool {
	// Retry failures sooner, but not more than every 15 minutes.
	const retry = 15 * time.Minute
	if s.Enabled && s.Interval == "startup" {
		// The update at start failed (at logon the network is often not
		// up yet): retry until one succeeds.
		return s.LastError != "" && s.LastUpdate.Before(started) && now.Sub(s.LastAttempt) >= retry
	}
	d, ok := intervals[s.Interval]
	if !s.Enabled || !ok {
		return false
	}
	// A try stamped while the clock was well ahead: waiting for that time
	// could take a year. Once tried, LastAttempt is right again. (A tick
	// read late may be a little older than a try made meanwhile.)
	if s.LastAttempt.Sub(now) > retry {
		return true
	}
	if s.LastError != "" && now.Sub(s.LastAttempt) >= retry && now.Sub(s.LastUpdate) >= d {
		return true
	}
	return now.Sub(s.LastAttempt) >= d
}

func (c *Controller) saveSubsLocked(list []store.Subscription) error {
	if c.subsBroken != nil {
		return fmt.Errorf("subscriptions.json не загружен, изменения не сохраняются: %v", c.subsBroken)
	}
	return c.Store.SaveSubscriptions(list)
}
