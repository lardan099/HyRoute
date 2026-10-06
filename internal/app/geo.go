package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
)

// Rule databases: geosite.dat and geoip.dat in <data>\geo, behind
// "geosite:youtube" and "geoip:ru" in rules. They are downloaded when a
// rule needs them and kept up to date in the background.

type geoState struct {
	mu       sync.Mutex
	db       *geodata.DB
	up       *geodata.Updater
	busy     bool
	progress [2]float64 // 0..1 per database while downloading
	lastErr  string
	viaVPN   bool
	poke     chan struct{}
}

// geoAdapter serves rules.Geo from the database.
type geoAdapter struct{ db *geodata.DB }

func (g geoAdapter) Site(name string) (rules.DomainMatcher, error) {
	d, err := g.db.Site(name)
	if errors.Is(err, geodata.ErrNoData) {
		return nil, rules.ErrGeoNoData
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (g geoAdapter) IP(name string) (rules.IPMatcher, error) {
	s, err := g.db.IP(name)
	if errors.Is(err, geodata.ErrNoData) {
		return nil, rules.ErrGeoNoData
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// initGeo installs the databases as the rules' category resolver. It runs
// before settings are compiled.
func (c *Controller) initGeo() {
	if c.geo.db != nil || c.Store == nil {
		return
	}
	c.geo.db = &geodata.DB{Dir: filepath.Join(c.Store.Dir, "geo")}
	c.geo.up = &geodata.Updater{DB: c.geo.db, Download: c.geoDownload}
	c.geo.up.Progress = func(k geodata.Kind, done, total int64) {
		if total <= 0 {
			return
		}
		c.geo.mu.Lock()
		c.geo.progress[k] = float64(done) / float64(total)
		c.geo.mu.Unlock()
		c.changed()
	}
	c.geo.poke = make(chan struct{}, 1)
	rules.SetGeo(geoAdapter{c.geo.db})
}

// GeoInfo is the "Базы правил" section of the settings.
type GeoInfo struct {
	Sources     []geodata.Source   `json:"sources"`
	Source      string             `json:"source"`
	Custom      geodata.Source     `json:"custom"`
	Auto        bool               `json:"auto"`
	Hours       int                `json:"hours"`
	Site        *geodata.FileState `json:"site"`
	IP          *geodata.FileState `json:"ip"`
	Checked     time.Time          `json:"checked"`
	Error       string             `json:"error"`
	Busy        bool               `json:"busy"`
	Progress    [2]float64         `json:"progress"`
	HasPrevious bool               `json:"hasPrevious"`
	Used        []string           `json:"used"`     // categories in enabled rules
	Warnings    []string           `json:"warnings"` // unusable categories
	ViaVPN      bool               `json:"viaVPN"`   // last download went through the VPN
	// SourceName is the short name of the source in use ("runetfreedom"),
	// shown next to every list so it is clear where it comes from.
	SourceName string       `json:"sourceName"`
	Popular    []GeoPopular `json:"popular"`
}

// GeoPopular is a well-known category and whether the source in use has
// it (nil: unknown, e.g. custom URLs before the download).
type GeoPopular struct {
	geodata.Category
	InSource *bool `json:"inSource"`
}

func (c *Controller) geoSource() geodata.Source {
	p := c.Prefs()
	if p.GeoSource == "custom" {
		return geodata.Source{ID: "custom", Name: "Свои ссылки", Site: p.GeoSiteURL, IP: p.GeoIPURL}
	}
	if s, ok := geodata.FindSource(p.GeoSource); ok {
		return s
	}
	s, _ := geodata.FindSource(geodata.DefaultSource)
	return s
}

// GeoInfo reports the databases.
func (c *Controller) GeoInfo() GeoInfo {
	c.initGeo()
	p := c.Prefs()
	st := c.geo.up.State()
	info := GeoInfo{
		Sources: geodata.Sources, Source: c.geoSource().ID,
		Custom: geodata.Source{ID: "custom", Site: p.GeoSiteURL, IP: p.GeoIPURL},
		Auto:   p.GeoAutoUpdate(), Hours: p.GeoHours(),
		Site: st.Site, IP: st.IP, Checked: st.Checked, Error: st.LastError,
		HasPrevious: c.geo.up.HasPrevious(),
	}
	src := c.geoSource()
	info.SourceName = src.Short
	if src.ID == "custom" {
		info.SourceName = "свои ссылки"
	}
	if err := geoLinksErr(src); err != nil {
		info.Error = err.Error()
	}
	for _, cat := range geodata.Popular {
		gp := GeoPopular{Category: cat}
		k := geodata.Site
		if cat.Kind == "ip" {
			k = geodata.IP
		}
		// The downloaded file decides when it belongs to this source;
		// otherwise the preset's known list.
		if has, ok := c.geo.db.Has(k, cat.Name); ok && st.From(k, src.URL(k)) {
			gp.InSource = &has
		} else if src.ID != "custom" {
			in := slices.Contains(cat.Sources, src.ID) || (k == geodata.IP && cat.Name == "private")
			gp.InSource = &in
		}
		info.Popular = append(info.Popular, gp)
	}
	c.geo.mu.Lock()
	info.Busy, info.Progress, info.ViaVPN = c.geo.busy, c.geo.progress, c.geo.viaVPN
	if c.geo.lastErr != "" {
		info.Error = c.geo.lastErr
	}
	c.geo.mu.Unlock()
	c.mu.Lock()
	info.Used = geoCategories(c.settings.Config)
	info.Warnings = append([]string{}, c.set.Warnings...)
	c.mu.Unlock()
	if info.Used == nil {
		info.Used = []string{}
	}
	return info
}

// geoCategories lists geosite:/geoip: items of enabled rules (geoip:private
// is built in and needs no database).
func geoCategories(cfg rules.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range cfg.Rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		for _, d := range r.AllDomains() {
			l := strings.ToLower(strings.TrimSpace(d))
			if (strings.HasPrefix(l, "geosite:") || strings.HasPrefix(l, "geoip:")) && l != "geoip:private" && !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// geoKinds reports which databases enabled rules use.
func geoKinds(cfg rules.Config) (site, ip bool) {
	for _, c := range geoCategories(cfg) {
		if strings.HasPrefix(c, "geosite:") {
			site = true
		} else {
			ip = true
		}
	}
	return site, ip
}

// checkGeoURL accepts https links only: the checksum comes from the same
// host, so over http anyone on the network could swap both the database
// (and with it the routing) and its checksum.
func checkGeoURL(u string) error {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" || pu.Host == "" {
		return fmt.Errorf("неверная ссылка %q: нужна https://…", u)
	}
	return nil
}

// geoLinksErr checks custom links. Links saved before http:// was refused
// are not downloaded either.
func geoLinksErr(src geodata.Source) error {
	if src.ID != "custom" {
		return nil
	}
	for _, u := range []string{src.Site, src.IP} {
		if u == "" {
			continue
		}
		if err := checkGeoURL(u); err != nil {
			return err
		}
	}
	return nil
}

var errGeoHours = errors.New("интервал обновления: от 1 часа до 14 дней")

// validateGeoPrefs is the check of SetGeoPrefs (a backup's «Базы правил»
// too): source "" (the default preset) and hours 0 (the default interval)
// are what a file without those keys holds.
func validateGeoPrefs(source, siteURL, ipURL string, hours int) error {
	if source == "custom" {
		if err := geoLinksErr(geodata.Source{ID: "custom", Site: siteURL, IP: ipURL}); err != nil {
			return err
		}
		if siteURL == "" && ipURL == "" {
			return errors.New("укажите хотя бы одну ссылку: на geosite.dat или geoip.dat")
		}
	} else if _, ok := geodata.FindSource(source); !ok && source != "" {
		return fmt.Errorf("неизвестный источник %q", source)
	}
	if hours < 0 || hours > 24*14 {
		return errGeoHours
	}
	return nil
}

// SetGeoPrefs changes the source and the schedule.
func (c *Controller) SetGeoPrefs(source, siteURL, ipURL string, auto bool, hours int) error {
	if source == "" {
		return fmt.Errorf("неизвестный источник %q", source)
	}
	if err := validateGeoPrefs(source, siteURL, ipURL, hours); err != nil {
		return err
	}
	if hours < 1 {
		return errGeoHours
	}
	changedSource := false
	if err := c.UpdatePrefs(func(p *store.Prefs) error {
		changedSource = p.GeoSource != source || p.GeoSiteURL != siteURL || p.GeoIPURL != ipURL
		p.GeoSource, p.GeoSiteURL, p.GeoIPURL = source, siteURL, ipURL
		off := !auto
		p.GeoAutoOff = &off
		p.GeoIntervalHours = hours
		return nil
	}); err != nil {
		return err
	}
	if changedSource {
		c.pokeGeo()
	}
	return nil
}

// UpdateGeo downloads the databases now (force: even when unchanged).
func (c *Controller) UpdateGeo(ctx context.Context, force bool) (geodata.Result, error) {
	c.initGeo()
	c.mu.Lock()
	broken := c.prefsBroken
	c.mu.Unlock()
	if broken != nil {
		// The source in memory is the default, not the user's.
		return geodata.Result{}, fmt.Errorf("prefs.json не загружен: источник баз неизвестен, базы не обновляются, чтобы не заменить ваши. Исправьте или удалите файл и перезапустите HyRoute. Ошибка: %v", broken)
	}
	return c.updateGeo(ctx, c.geoSource(), force, false)
}

// updateGeo downloads the databases of src that have a URL. scheduled:
// the background update, which keeps a rollback.
func (c *Controller) updateGeo(ctx context.Context, src geodata.Source, force, scheduled bool) (geodata.Result, error) {
	c.geo.mu.Lock()
	if c.geo.busy {
		c.geo.mu.Unlock()
		return geodata.Result{}, errors.New("базы уже обновляются")
	}
	c.geo.busy, c.geo.progress, c.geo.lastErr, c.geo.viaVPN = true, [2]float64{}, "", false
	c.geo.mu.Unlock()
	c.changed()
	var res geodata.Result
	err := geoLinksErr(src)
	switch {
	case err != nil:
	case scheduled:
		res, err = c.geo.up.UpdateScheduled(ctx, src)
	default:
		res, err = c.geo.up.Update(ctx, src, force)
	}
	c.geo.mu.Lock()
	c.geo.busy = false
	if err != nil {
		c.geo.lastErr = err.Error()
	}
	c.geo.mu.Unlock()
	if err != nil {
		c.Log.Warn("rule databases: update failed", "source", src.ID, "err", err)
	}
	if res.Changed {
		c.Log.Info("rule databases updated", "source", src.ID, "notes", strings.Join(res.Notes, "; "))
		c.recompileRules()
	}
	c.changed()
	return res, err
}

// RollbackGeo returns to the previous databases.
func (c *Controller) RollbackGeo() error {
	c.initGeo()
	err := c.geo.up.Rollback()
	if err == nil {
		c.Log.Info("rule databases rolled back")
	}
	// A failed rollback that could not undo a swap left new files too.
	c.recompileRules()
	c.changed()
	return err
}

// GeoCategories suggests category names for the rule editor ("site" or
// "ip"), best matches first.
func (c *Controller) GeoCategories(kind, query string, limit int) []string {
	c.initGeo()
	k := geodata.Site
	if kind == "ip" {
		k = geodata.IP
	}
	names, err := c.geo.db.Names(k)
	if err != nil {
		names = nil
		for _, p := range geodata.Popular {
			if (p.Kind == "ip") == (k == geodata.IP) {
				names = append(names, p.Name)
			}
		}
	}
	if limit <= 0 {
		limit = 30
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var pre, sub []string
	for _, n := range names {
		switch {
		case q == "" || strings.HasPrefix(n, q):
			pre = append(pre, n)
		case strings.Contains(n, q):
			sub = append(sub, n)
		}
	}
	out := append(pre, sub...)
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// recompileRules rebuilds the compiled rules with the current databases
// and pushes them to the session. It runs after a save in progress, in
// the same lock order: that save compiled its rules with the old
// databases and would otherwise publish them last.
func (c *Controller) recompileRules() {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.settings == nil {
		return
	}
	set, err := rules.Compile(c.settings.Config)
	if err != nil {
		c.Log.Warn("rules: recompile failed", "err", err)
		return
	}
	set.ExactWeb = c.settings.ExactWeb()
	c.set = set
	c.applyRoutingLocked()
}

func (c *Controller) pokeGeo() {
	if c.geo.poke == nil {
		return
	}
	select {
	case c.geo.poke <- struct{}{}:
	default:
	}
}

// geoDue reports whether the scheduler should update now, and what: the
// source without the URL of a database no rule uses.
func (c *Controller) geoDue() (geodata.Source, bool) {
	var site, ip bool
	c.mu.Lock()
	if c.settings != nil {
		site, ip = c.geoKindsLocked() // rulesets: every rule profile
	}
	broken := c.prefsBroken != nil
	c.mu.Unlock()
	if !site && !ip {
		return geodata.Source{}, false // nothing uses the databases: no 90 MB downloads
	}
	st := c.geo.up.State()
	src := c.geoSource()
	if broken {
		// prefs.json did not load: the source in memory is the default,
		// not the user's. Only a database a rule needs and none is there
		// is downloaded; the user's are not replaced.
		if !site || st.Site != nil && !c.geo.db.Missing(geodata.Site) {
			src.Site = ""
		}
		if !ip || st.IP != nil && !c.geo.db.Missing(geodata.IP) {
			src.IP = ""
		}
		return src, (src.Site != "" || src.IP != "") && geoLinksErr(src) == nil
	}
	// A database no rule uses is neither downloaded nor kept fresh; it is
	// only replaced once when left from another source, since lists are
	// shown everywhere under the name of the source in use.
	if !site && (st.Site == nil || st.From(geodata.Site, src.Site) || st.Held(geodata.Site, src.Site)) {
		src.Site = ""
	}
	if !ip && (st.IP == nil || st.From(geodata.IP, src.IP) || st.Held(geodata.IP, src.IP)) {
		src.IP = ""
	}
	if (src.Site == "" && src.IP == "") || geoLinksErr(src) != nil {
		return src, false // nothing to download, or http:// links (GeoInfo says so)
	}
	for _, k := range []geodata.Kind{geodata.Site, geodata.IP} {
		// Not downloaded, or from another source or old custom links (a
		// file the user rolled back to is kept for this source).
		// Or the file is gone (geo.json alone does not show it).
		if u := src.URL(k); u != "" && (!st.From(k, u) && !st.Held(k, u) || c.geo.db.Missing(k)) {
			return src, true // a rule waits for data: even with auto-update off
		}
	}
	p := c.Prefs()
	if !p.GeoAutoUpdate() {
		return src, false
	}
	// A failed update is retried: RunGeoUpdates backs off.
	return src, st.LastError != "" || time.Since(st.Checked) >= time.Duration(p.GeoHours())*time.Hour
}

// RunGeoUpdates keeps the databases fresh until ctx ends: at start, when
// rules begin to use a category, and every GeoHours.
func (c *Controller) RunGeoUpdates(ctx context.Context) {
	c.initGeo()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	first := time.After(20 * time.Second)
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-first:
		case <-t.C:
		case <-c.geo.poke:
		}
		c.trimGeoCache()
		src, due := c.geoDue()
		if !due {
			continue
		}
		c.geo.mu.Lock()
		lastFail := c.geo.lastErr != ""
		c.geo.mu.Unlock()
		if lastFail && failures > 0 {
			// Back off after failures: 10 min, 20, 40 … up to 6 h.
			wait := min(time.Duration(1<<min(failures-1, 5))*10*time.Minute, 6*time.Hour)
			if time.Since(c.geo.up.State().Checked) < wait {
				continue
			}
		}
		uctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		_, err := c.updateGeo(uctx, src, false, true)
		cancel()
		if err != nil {
			failures++
		} else {
			failures = 0
		}
	}
}

// trimGeoCache frees the decoded categories no enabled rule uses: tried in
// the rule editor, or gone from the rules (ru-blocked-all alone is tens of
// megabytes).
func (c *Controller) trimGeoCache() {
	var cats []string
	c.mu.Lock()
	if c.settings != nil {
		cats = geoCategories(c.settings.Config)
	}
	c.mu.Unlock()
	site, ip := []string{}, []string{"private"}
	for _, cat := range cats {
		if n, ok := strings.CutPrefix(cat, "geosite:"); ok {
			site = append(site, n)
		} else if n, ok := strings.CutPrefix(cat, "geoip:"); ok {
			ip = append(ip, n)
		}
	}
	c.geo.db.Retain(geodata.Site, site)
	c.geo.db.Retain(geodata.IP, ip)
}

// geoDownload fetches directly and, when that fails while a VPN tunnel is
// up, through the main profile (GitHub downloads are often slow or cut
// off without it). attempt 1 is the retry after a broken download: it
// goes through the VPN when it can.
func (c *Controller) geoDownload(ctx context.Context, rawURL string, attempt int) (*http.Response, error) {
	direct := &http.Client{Timeout: 20 * time.Minute, Transport: directTransport, CheckRedirect: geodata.NoDowngrade}
	tun := c.mainEndpoint()
	if attempt == 0 || tun == nil {
		resp, err := doGet(ctx, direct, rawURL)
		if (err == nil && resp.StatusCode < 500) || tun == nil {
			return resp, err
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	c.geo.mu.Lock()
	c.geo.viaVPN = true
	c.geo.mu.Unlock()
	viaVPN := &http.Client{Timeout: 20 * time.Minute, CheckRedirect: geodata.NoDowngrade, Transport: &http.Transport{
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
		TLSHandshakeTimeout: 30 * time.Second,
	}}
	return doGet(ctx, viaVPN, rawURL)
}

func doGet(ctx context.Context, cl *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HyRoute")
	return cl.Do(req)
}

// mainEndpoint is the running main target's tunnel, or nil. A group main
// commits a member only when the download dials (mainGroupEndpoint).
func (c *Controller) mainEndpoint() interface {
	Dial(context.Context, socks5.Addr) (net.Conn, error)
} {
	c.mu.Lock()
	sess, main := c.sess, c.mainTargetLocked()
	c.mu.Unlock()
	if sess == nil || main == "" {
		return nil
	}
	if groups.IsGroupID(main) {
		return c.mainGroupEndpoint(sess, main)
	}
	ep := sess.Endpoint(main)
	if ep == nil || !ep.Available() {
		return nil
	}
	return ep
}
