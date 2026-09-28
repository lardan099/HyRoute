package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/rules"
)

// The list inspector: which geosite/geoip
// lists contain a site or an address, what a list contains, and Hysteria
// ACL conversion.

// InspectHit is one list that contains the query.
type InspectHit struct {
	Tag      string   `json:"tag"` // "geosite:openai"
	Title    string   `json:"title"`
	Entry    string   `json:"entry"` // matching entry: "domain:chatgpt.com"
	Attrs    string   `json:"attrs"`
	Size     int      `json:"size"`
	Priority int      `json:"priority"`
	Broad    bool     `json:"broad"` // aggregate list (whole registry, a region)
	IP       string   `json:"ip"`    // geoip: the address that matched
	UsedBy   []string `json:"usedBy"`
}

type InspectResult struct {
	Query  string       `json:"query"`
	Host   string       `json:"host"`
	IPs    []string     `json:"ips"` // resolved (or given) addresses
	Site   []InspectHit `json:"site"`
	IP     []InspectHit `json:"ip"`
	Errors []string     `json:"errors"`
	// Route is what HyRoute does with the host now.
	Route      *Explanation `json:"route"`
	SourceName string       `json:"sourceName"`
	// List is set when the query is a tag (geosite:x / geoip:x).
	List *geodata.Listing `json:"list"`
}

// listPriority orders matches the way ACL rules should be ordered: the
// first match wins, so specific service lists go above broad categories.
var listPriority = map[string]int{
	"geosite:anthropic":            1000,
	"geosite:telegram":             1000,
	"geoip:telegram":               1000,
	"geosite:openai":               900,
	"geosite:category-ai-chat-!cn": 800,
	"geosite:category-geoblock-ru": 100,
	"geosite:category-ru":          50,
	"geoip:ru":                     50,
}

// broadPrefixes are aggregate lists: registries and regions.
var broadPrefixes = []string{"geolocation-", "tld-", "gfw", "greatfire", "refilter", "re-filter", "antifilter", "ru-blocked", "ru-available", "category-companies"}

var broadNames = map[string]bool{"cn": true, "private": true, "direct": true, "whitelist": true}

func tagPriority(tag string) (int, bool) {
	if p, ok := listPriority[tag]; ok {
		return p, p <= 100
	}
	kind, name, _ := strings.Cut(tag, ":")
	if broadNames[name] {
		return 40, true
	}
	for _, b := range broadPrefixes {
		if strings.HasPrefix(name, b) {
			return 40, true
		}
	}
	switch {
	case kind == "geoip":
		if len(name) == 2 { // a country
			return 50, true
		}
		return 80, false
	case strings.HasPrefix(name, "category-"):
		return 100, false
	}
	return 700, false
}

func sortHits(h []InspectHit) {
	sort.SliceStable(h, func(i, j int) bool {
		if h[i].Priority != h[j].Priority {
			return h[i].Priority > h[j].Priority
		}
		if h[i].Size != h[j].Size {
			return h[i].Size < h[j].Size // smaller = more specific
		}
		return h[i].Tag < h[j].Tag
	})
}

// usage maps "geosite:x" to the enabled rules that use it.
func usage(cfg rules.Config, profileName func(string) string) map[string][]string {
	out := map[string][]string{}
	for i, r := range cfg.Rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("правило %d", i+1)
		}
		to := "напрямую"
		switch r.Action {
		case rules.Block:
			to = "блок"
		case rules.Tunnel:
			to = "VPN"
			if r.Profile != "" {
				to = profileName(r.Profile)
			}
		}
		for _, d := range r.AllDomains() {
			l := strings.ToLower(strings.TrimSpace(d))
			if strings.HasPrefix(l, "geosite:") || strings.HasPrefix(l, "geoip:") {
				out[l] = append(out[l], "«"+name+"» → "+to)
			}
		}
	}
	return out
}

func popularTitle(kind, name string) string {
	for _, p := range geodata.Popular {
		if p.Kind == kind && p.Name == name {
			return p.Title
		}
	}
	return ""
}

// Inspect finds the lists that contain a site, a URL, an IP or shows a
// list when the query is a tag.
func (c *Controller) Inspect(query string) (InspectResult, error) {
	c.initGeo()
	res := InspectResult{Query: strings.TrimSpace(query), IPs: []string{}, Site: []InspectHit{}, IP: []InspectHit{}, Errors: []string{}}
	res.SourceName = c.GeoInfo().SourceName
	q := strings.ToLower(res.Query)
	if q == "" {
		return res, errors.New("введите сайт, IP или список: geosite:… / geoip:…")
	}
	if kind, name, ok := strings.Cut(q, ":"); ok && (kind == "geosite" || kind == "geoip") {
		k := geodata.Site
		if kind == "geoip" {
			k = geodata.IP
		}
		l, err := c.geo.db.List(k, name, "", 0, 500)
		if err != nil {
			return res, geoErr(err)
		}
		res.List = &l
		return res, nil
	}

	c.mu.Lock()
	use := usage(c.settings.Config, c.profileName)
	c.mu.Unlock()

	target, _ := cleanTarget(res.Query)
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		res.Host = rules.NormalizeDomain(target)
		hits, err := c.geo.db.FindSite(res.Host)
		if err != nil {
			res.Errors = append(res.Errors, "Списки сайтов: "+geoErr(err).Error())
		}
		for _, h := range hits {
			tag := "geosite:" + h.Category
			p, broad := tagPriority(tag)
			res.Site = append(res.Site, InspectHit{Tag: tag, Title: popularTitle("site", h.Category), Entry: h.Entry, Attrs: h.Attrs,
				Size: h.Size, Priority: p, Broad: broad, UsedBy: use[tag]})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", res.Host)
		cancel()
		if err != nil {
			res.Errors = append(res.Errors, "DNS: не удалось узнать IP сайта ("+err.Error()+"), списки IP не проверены")
		}
		seen := map[netip.Addr]bool{}
		for _, a := range addrs {
			if a = a.Unmap(); !seen[a] {
				seen[a] = true
				ips = append(ips, a)
			}
		}
	}
	byTag := map[string]int{}
	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.String())
		hits, err := c.geo.db.FindIP(ip)
		if err != nil {
			res.Errors = append(res.Errors, "Списки IP: "+geoErr(err).Error())
			break
		}
		for _, h := range hits {
			tag := "geoip:" + h.Category
			if i, ok := byTag[tag]; ok { // one row per list, all addresses
				res.IP[i].IP += ", " + ip.String()
				continue
			}
			p, broad := tagPriority(tag)
			byTag[tag] = len(res.IP)
			res.IP = append(res.IP, InspectHit{Tag: tag, Title: popularTitle("ip", h.Category), Entry: h.Entry, Size: h.Size,
				Priority: p, Broad: broad, IP: ip.String(), UsedBy: use[tag]})
		}
	}
	sortHits(res.Site)
	sortHits(res.IP)
	if res.Host != "" || len(ips) > 0 {
		ex := c.Explain(ExplainQuery{Target: res.Query}, nil) // with its port, if any
		res.Route = &ex
	}
	return res, nil
}

// SiteLists lists the geosite lists that hold a site, the most specific
// first, without the DNS lookups of Inspect: for a rule made from a
// connection. Nothing when the database is not downloaded.
func (c *Controller) SiteLists(domain string) []InspectHit {
	out := []InspectHit{}
	host := rules.NormalizeDomain(domain)
	if host == "" {
		return out
	}
	c.initGeo()
	hits, err := c.geo.db.FindSite(host)
	if err != nil {
		return out
	}
	c.mu.Lock()
	use := usage(c.settings.Config, c.profileName)
	c.mu.Unlock()
	for _, h := range hits {
		tag := "geosite:" + h.Category
		p, broad := tagPriority(tag)
		used := use[tag]
		if used == nil {
			used = []string{}
		}
		out = append(out, InspectHit{Tag: tag, Title: popularTitle("site", h.Category), Entry: h.Entry, Attrs: h.Attrs,
			Size: h.Size, Priority: p, Broad: broad, UsedBy: used})
	}
	sortHits(out)
	return out
}

func geoErr(err error) error {
	if errors.Is(err, geodata.ErrNoData) {
		return errors.New("база правил ещё не скачана: «Настройки → Базы правил» → «Скачать»")
	}
	return err
}

// GeoList pages through a list for the viewer.
func (c *Controller) GeoList(kind, name, filter string, offset, limit int) (geodata.Listing, error) {
	c.initGeo()
	k := geodata.Site
	if kind == "ip" {
		k = geodata.IP
	}
	l, err := c.geo.db.List(k, name, filter, offset, min(max(limit, 1), 5000))
	return l, geoErr(err)
}

// ---- Hysteria ACL conversion ----

// ConvertResult is the converter output.
type ConvertResult struct {
	Text     string   `json:"text"`
	Count    int      `json:"count"`
	Warnings []string `json:"warnings"`
}

var aclLine = regexp.MustCompile(`^\s*(?:-\s*)?([A-Za-z0-9_-]+)\s*\(([^)]*)\)`)

type aclRule struct {
	line     int
	action   string
	resource string
	extra    string // protocol/port argument
}

func parseACL(text string) []aclRule {
	var out []aclRule
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(raw); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := aclLine.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		args := strings.Split(m[2], ",")
		r := aclRule{line: i + 1, action: strings.ToLower(strings.TrimSpace(m[1])), resource: strings.ToLower(strings.TrimSpace(args[0]))}
		if len(args) > 1 {
			r.extra = strings.ToLower(strings.TrimSpace(args[1]))
		}
		out = append(out, r)
	}
	return out
}

// Second-level labels of country domains (co.uk, com.au …).
var countrySecond = map[string]bool{"ac": true, "co": true, "com": true, "edu": true, "gov": true, "mil": true, "net": true, "ne": true, "nom": true, "or": true, "org": true}

func rootDomain(d string) string {
	d = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."), "*.")
	var labels []string
	for _, l := range strings.Split(d, ".") {
		if l != "" {
			labels = append(labels, l)
		}
	}
	n := len(labels)
	if n < 2 {
		return ""
	}
	if n >= 3 && len(labels[n-1]) == 2 && countrySecond[labels[n-2]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// ConvertACL converts Hysteria ACL lines ("- proxy(geosite:openai)").
// mode "domains": root-domain lines "*.example.com <suffix>", geosite
// lists expanded from the rule database. mode "rules": HyRoute rules text.
// actions filters ACL actions (comma-separated, empty = all).
func (c *Controller) ConvertACL(text, mode, suffix, actions string) (ConvertResult, error) {
	c.initGeo()
	want := map[string]bool{}
	for _, a := range strings.Split(actions, ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			want[a] = true
		}
	}
	var list []aclRule
	for _, r := range parseACL(text) {
		if len(want) == 0 || want[r.action] {
			list = append(list, r)
		}
	}
	if len(list) == 0 {
		return ConvertResult{Warnings: []string{}}, errors.New("правил ACL не найдено: вставьте строки вида «- proxy(geosite:openai)»")
	}
	if mode == "rules" {
		return aclToRules(list), nil
	}
	return c.aclToDomains(list, strings.TrimSpace(suffix)), nil
}

func (c *Controller) aclToDomains(list []aclRule, suffix string) ConvertResult {
	res := ConvertResult{Warnings: []string{}}
	seen := map[string]bool{}
	var lines []string
	add := func(d string) {
		if r := rootDomain(d); r != "" {
			l := strings.TrimSpace("*." + r + " " + suffix)
			if !seen[l] {
				seen[l] = true
				lines = append(lines, l)
			}
		}
	}
	for _, r := range list {
		kind, val, typed := strings.Cut(r.resource, ":")
		switch {
		case typed && kind == "geosite":
			doms, skipped, err := c.geo.db.Expand(val)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %s пропущен: %v", r.line, r.resource, geoErr(err)))
				continue
			}
			for _, d := range doms {
				add(d)
			}
			if skipped > 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: в %s пропущено %d записей keyword:/regexp: (их нельзя превратить в домены)", r.line, r.resource, skipped))
			}
		case typed && (kind == "suffix" || kind == "domain" || kind == "full"):
			add(val)
		case typed && kind == "geoip":
			res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %s пропущен: диапазоны IP нельзя превратить в домены", r.line, r.resource))
		case !typed && strings.Contains(r.resource, ".") && !rules.IsAddressItem(r.resource):
			add(r.resource)
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %s пропущен: это не домен", r.line, r.resource))
		}
	}
	res.Text = strings.Join(lines, "\n")
	res.Count = len(lines)
	return res
}

// aclToRules maps ACL actions: direct -> напрямую, reject/block -> блок,
// any other outbound -> vpn. Consecutive rules with the same action and
// protocol become one line; order is kept, since both evaluate top down.
func aclToRules(list []aclRule) ConvertResult {
	res := ConvertResult{Warnings: []string{}}
	type group struct {
		action, target, proto, ports string
		items                        []string
	}
	var groups []*group
	def := ""
	var all *aclRule
	for i, r := range list {
		if all != nil {
			// Hysteria stops at the first match: nothing below is reached.
			res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %s(all) ловит весь остальной трафик, строки ниже неё (%d) в Hysteria не действуют и пропущены", all.line, all.action, len(list)-i))
			break
		}
		target := "vpn"
		switch r.action {
		case "direct":
			target = "напрямую"
		case "reject", "block":
			target = "блок"
		}
		if (r.resource == "all" || r.resource == "*") && r.extra != "" {
			msg := fmt.Sprintf("строка %d: %s(all, %s) пропущено: «всё остальное» в HyRoute задаётся без протокола и порта", r.line, r.action, r.extra)
			if r.extra == "udp/443" && target == "блок" {
				msg = fmt.Sprintf("строка %d: reject(all, udp/443) — это блокировка QUIC; в HyRoute она включается в «Настройки → Маршрутизация»", r.line)
			}
			res.Warnings = append(res.Warnings, msg)
			continue
		}
		proto, ports := "", ""
		if r.extra != "" {
			p, port, _ := strings.Cut(r.extra, "/")
			switch p {
			case "tcp", "udp":
				proto = p
			case "*":
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: непонятный протокол %q, правило без него", r.line, r.extra))
			}
			if port != "" && port != "*" {
				if _, err := rules.ParsePorts(port); err != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %v, правило действует на все порты", r.line, err))
				} else {
					ports = rules.FormatPorts(port)
				}
			}
		}
		item := ""
		kind, val, typed := strings.Cut(r.resource, ":")
		switch {
		case r.resource == "all" || r.resource == "*":
			def, all = target, &list[i]
			continue
		case typed && (kind == "geosite" || kind == "geoip"):
			item = r.resource
		case typed && (kind == "suffix" || kind == "domain"):
			item = val
		case typed && kind == "full":
			item = "=" + val
		case rules.IsAddressItem(r.resource):
			item = r.resource
		case strings.HasPrefix(r.resource, "*."):
			item = r.resource
		case strings.Contains(r.resource, "."):
			item = "=" + r.resource // a bare domain in Hysteria ACL is exact
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf("строка %d: %s пропущен: не понимаю", r.line, r.resource))
			continue
		}
		if n := len(groups); n > 0 && groups[n-1].action == r.action && groups[n-1].proto == proto && groups[n-1].ports == ports {
			groups[n-1].items = append(groups[n-1].items, item)
			continue
		}
		groups = append(groups, &group{action: r.action, target: target, proto: proto, ports: ports, items: []string{item}})
	}
	var b strings.Builder
	b.WriteString("# Из Hysteria ACL. direct → напрямую, reject → блок, остальные выходы → vpn (поменяйте на нужный сервер)\n")
	for _, g := range groups {
		line := "ACL " + g.action + ": " + strings.Join(g.items, " ") + " -> " + g.target
		switch {
		case g.proto != "" && g.ports != "":
			line += " | " + g.proto + " " + g.ports
		case g.ports != "":
			line += " | порт " + g.ports
		case g.proto != "":
			line += " | " + g.proto
		}
		b.WriteString(line + "\n")
		res.Count++
	}
	if def != "" {
		b.WriteString("* -> " + def + "\n")
	}
	res.Text = b.String()
	return res
}
