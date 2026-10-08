package routing

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
)

// The rule builder by services (P4-09): a catalog of popular services,
// each a set of geo categories and domains, and the group of rules the
// «По сервисам» tab builds from an outbound chosen per service. The group
// is the builder's own: it is rebuilt whole, the rules around it are
// never touched, and a group changed by hand is reported before it is
// overwritten.

// ServicesVersion is the version of the catalog. The group records the
// version it was built from; a change of the catalog that changes the
// rules of a service raises it, and a group of another version reads as
// changed.
const ServicesVersion = 1

// ServicesGroup is the rule group the builder owns.
const ServicesGroup = "По сервисам"

// servicesMark begins the comment line under the group's header that says
// who built the group and from which catalog version.
const servicesMark = "# hyroute:services v"

func servicesMarkLine() string {
	return servicesMark + strconv.Itoa(ServicesVersion) + " — эту группу собирает вкладка «По сервисам»"
}

// CatalogService is a service of the catalog.
type CatalogService struct {
	// ID names the service in the API; the rules name its categories.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Sites are geosite categories, IPs geoip codes, Domains domains with
	// their subdomains (suffix:).
	Sites   []string `json:"sites,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Domains []string `json:"domains,omitempty"`
	// Sample is a domain of the service the dry run tries.
	Sample string `json:"sample"`
}

// ServiceSection is a section of the catalog.
type ServiceSection struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Services []CatalogService `json:"services"`
}

func svc(id, name, sample string, sites ...string) CatalogService {
	return CatalogService{ID: id, Name: name, Sample: sample, Sites: sites}
}

// withIPs adds geoip codes: for services whose apps connect by address,
// without a domain.
func (c CatalogService) withIPs(codes ...string) CatalogService {
	c.IPs = codes
	return c
}

// Catalog is the service catalog in the order the tab shows it and the
// group has the rules. The categories are those of the geo databases the
// controller downloads (Loyalsoldier/v2ray-rules-dat); no category
// belongs to two services, and categories made of many services (google,
// category-ai-!cn) are left out. Some categories still hold domains of
// another service (mailru: VK's, OK's and Dzen's; yandex: Kinopoisk's;
// category-bank-ru: Okko's; github: Copilot's): the narrower service comes
// first, so its rules take its domains before the broader one's do.
func Catalog() []ServiceSection {
	return []ServiceSection{
		{ID: "video", Name: "Видео и музыка", Services: []CatalogService{
			svc("youtube", "YouTube", "youtube.com", "youtube"),
			svc("netflix", "Netflix", "netflix.com", "netflix").withIPs("netflix"),
			svc("twitch", "Twitch", "twitch.tv", "twitch"),
			svc("tiktok", "TikTok", "tiktok.com", "tiktok"),
			svc("spotify", "Spotify", "spotify.com", "spotify"),
			svc("soundcloud", "SoundCloud", "soundcloud.com", "soundcloud"),
			svc("disney", "Disney+", "disneyplus.com", "disney"),
			svc("primevideo", "Prime Video", "primevideo.com", "primevideo"),
			svc("kinopoisk", "Кинопоиск", "kinopoisk.ru", "kinopoisk"),
			svc("okko", "Okko", "okko.tv", "okko"),
			svc("rutube", "Rutube", "rutube.ru", "rutube"),
			svc("wink", "Wink", "wink.ru", "wink"),
		}},
		{ID: "messengers", Name: "Мессенджеры и звонки", Services: []CatalogService{
			svc("telegram", "Telegram", "telegram.org", "telegram").withIPs("telegram"),
			svc("whatsapp", "WhatsApp", "whatsapp.com", "whatsapp"),
			svc("signal", "Signal", "signal.org", "signal"),
			svc("viber", "Viber", "viber.com", "viber"),
			svc("discord", "Discord", "discord.com", "discord"),
			svc("messenger", "Messenger", "messenger.com", "messenger"),
			svc("zoom", "Zoom", "zoom.us", "zoom"),
		}},
		{ID: "social", Name: "Соцсети", Services: []CatalogService{
			svc("facebook", "Facebook", "facebook.com", "facebook"),
			svc("instagram", "Instagram", "instagram.com", "instagram"),
			svc("threads", "Threads", "threads.net", "threads"),
			svc("x", "X (Twitter)", "x.com", "twitter").withIPs("twitter"),
			svc("linkedin", "LinkedIn", "linkedin.com", "linkedin"),
			svc("reddit", "Reddit", "reddit.com", "reddit"),
			svc("pinterest", "Pinterest", "pinterest.com", "pinterest"),
			svc("bluesky", "Bluesky", "bsky.app", "bluesky"),
			svc("ok", "Одноклассники", "ok.ru", "ok"),
			svc("vk", "ВКонтакте", "vk.com", "vk"),
		}},
		{ID: "ai", Name: "Нейросети", Services: []CatalogService{
			svc("chatgpt", "ChatGPT", "chatgpt.com", "openai"),
			svc("claude", "Claude", "claude.ai", "anthropic"),
			svc("gemini", "Gemini", "gemini.google.com", "google-gemini"),
			svc("grok", "Grok", "grok.com", "xai"),
			svc("deepseek", "DeepSeek", "deepseek.com", "deepseek"),
			svc("perplexity", "Perplexity", "perplexity.ai", "perplexity"),
			svc("copilot", "GitHub Copilot", "githubcopilot.com", "github-copilot"),
		}},
		{ID: "games", Name: "Игры", Services: []CatalogService{
			svc("steam", "Steam", "steampowered.com", "steam"),
			svc("epicgames", "Epic Games", "epicgames.com", "epicgames"),
			svc("playstation", "PlayStation", "playstation.com", "playstation"),
			svc("xbox", "Xbox", "xbox.com", "xbox"),
			svc("nintendo", "Nintendo", "nintendo.com", "nintendo"),
			svc("battlenet", "Battle.net", "battle.net", "blizzard"),
			svc("riot", "Riot Games", "riotgames.com", "riot"),
			svc("ea", "EA", "ea.com", "ea"),
			svc("ubisoft", "Ubisoft", "ubisoft.com", "ubisoft"),
			svc("roblox", "Roblox", "roblox.com", "roblox"),
		}},
		{ID: "russia", Name: "Российские сервисы", Services: []CatalogService{
			svc("yandex", "Яндекс", "ya.ru", "yandex"),
			svc("dzen", "Дзен", "dzen.ru", "dzen"),
			svc("mailru", "Mail.ru", "mail.ru", "mailru"),
			svc("ozon", "Ozon", "ozon.ru", "ozon"),
			svc("wildberries", "Wildberries", "wildberries.ru", "wildberries"),
			svc("avito", "Авито", "avito.ru", "avito"),
		}},
		{ID: "finance", Name: "Банки и госуслуги", Services: []CatalogService{
			svc("banks-ru", "Банки России", "sberbank.ru", "category-bank-ru"),
			svc("gov-ru", "Госуслуги и госсайты России", "gosuslugi.ru", "category-gov-ru"),
		}},
		{ID: "work", Name: "Работа и разработка", Services: []CatalogService{
			svc("github", "GitHub", "github.com", "github"),
			svc("docker", "Docker Hub", "docker.com", "docker"),
			svc("notion", "Notion", "notion.so", "notion"),
		}},
	}
}

// catalogServices are the services of the catalog in order.
func catalogServices() []CatalogService {
	var out []CatalogService
	for _, s := range Catalog() {
		out = append(out, s.Services...)
	}
	return out
}

// addrKey is an address as the catalog index has it.
func addrKey(a string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(a)), ".") }

// rules are the service's rules with outbound o: those by name (geosite,
// suffix) and those by address (geoip).
func (c CatalogService) rules(o string) (names, addrs []acl.Rule) {
	add := func(to *[]acl.Rule, a string) {
		*to = append(*to, acl.Rule{Outbound: o, Address: a, Comment: c.Name, Group: ServicesGroup})
	}
	for _, n := range c.Sites {
		add(&names, "geosite:"+n)
	}
	for _, d := range c.Domains {
		add(&names, "suffix:"+d)
	}
	for _, ip := range c.IPs {
		add(&addrs, "geoip:"+ip)
	}
	return names, addrs
}

// serviceRules are the group's rules for choices (service ID →
// outbound): the rules by name of the chosen services in catalog order,
// then those by address. A request for a domain is matched by the address
// it resolves to as well, so a domain meets its own service's rule before
// the address rule of another one.
func serviceRules(choices map[string]string) []acl.Rule {
	var names, addrs []acl.Rule
	for _, c := range catalogServices() {
		o, ok := choices[c.ID]
		if !ok || o == "" {
			continue
		}
		n, a := c.rules(o)
		names, addrs = append(names, n...), append(addrs, a...)
	}
	return append(names, addrs...)
}

// serviceIndex maps the addresses of the catalog's rules to their
// services.
func serviceIndex() map[string]CatalogService {
	m := map[string]CatalogService{}
	for _, c := range catalogServices() {
		n, a := c.rules("x")
		for _, r := range append(n, a...) {
			m[addrKey(r.Address)] = c
		}
	}
	return m
}

// ServicesState is the builder's group of a draft, read back.
type ServicesState struct {
	// Found: the rules have the group.
	Found bool `json:"found"`
	// Version is the catalog version the group was built from (0: the
	// builder's mark is not there).
	Version int `json:"version,omitempty"`
	// Choices are the outbounds of the services the group has rules of
	// (service ID → outbound as the rules name it).
	Choices map[string]string `json:"choices"`
	// Edited: building the group from Choices gives other rules or lines,
	// it was changed by hand or built from another catalog version.
	// Changes say what differs.
	Edited  bool     `json:"edited,omitempty"`
	Changes []string `json:"changes,omitempty"`
}

// maxChanges bounds the differences a state lists.
const maxChanges = 8

// ReadServices reads the builder's group of doc back into a choice per
// service. The group is the builder's while building it again from those
// choices gives the very same text.
func ReadServices(doc acl.Document) ServicesState {
	st := ServicesState{Choices: map[string]string{}}
	idx := serviceIndex()
	var changes []string
	note := func(s string) {
		if !slices.Contains(changes, s) {
			changes = append(changes, s)
		}
	}
	first, last, n := -1, -1, 0
	var got []acl.Rule // the group's rules of the catalog, in order
	for i, r := range doc.Rules {
		if r.Group != ServicesGroup {
			continue
		}
		if first < 0 {
			first = i
			own := afterHeader(r.Before)
			st.Version = markVersion(own)
			if len(own) > 1 || len(own) == 1 && st.Version == 0 {
				note("в группе есть свои комментарии или пустые строки")
			}
		} else if len(r.Before) > 0 {
			note("в группе есть свои комментарии или пустые строки")
		}
		last, n = i, n+1
		if r.Bad() {
			note(fmt.Sprintf("строка «%s» — не правило", strings.TrimSpace(r.Text)))
			continue
		}
		c, ok := idx[addrKey(r.Address)]
		if !ok {
			note(fmt.Sprintf("правило «%s» — не из каталога", ruleText(r)))
			continue
		}
		if r.Off {
			note(fmt.Sprintf("правило «%s» выключено", ruleText(r)))
		}
		if was, ok := st.Choices[c.ID]; ok && !strings.EqualFold(was, r.Outbound) {
			note(fmt.Sprintf("у «%s» правила с разными выходами", c.Name))
			continue
		}
		st.Choices[c.ID] = r.Outbound
		got = append(got, r)
	}
	if first < 0 {
		return st
	}
	st.Found = true
	if placeServices(doc, serviceRules(st.Choices)).Text() == doc.Text() {
		return st
	}
	st.Edited = true
	if n != last-first+1 {
		note("правила группы стоят не подряд")
	}
	switch st.Version {
	case 0:
		note("нет отметки конструктора: группу собрали не на этой вкладке")
	case ServicesVersion:
	default:
		note(fmt.Sprintf("группу собрала другая версия каталога (%d, сейчас %d)", st.Version, ServicesVersion))
	}
	want := serviceRules(st.Choices)
	for _, w := range want {
		i := slices.IndexFunc(got, func(r acl.Rule) bool { return addrKey(r.Address) == addrKey(w.Address) })
		switch {
		case i < 0:
			note(fmt.Sprintf("у «%s» нет правила %s", w.Comment, w.Address))
		case got[i].Address != w.Address || got[i].Proto != w.Proto || got[i].Port != w.Port || got[i].Hijack != w.Hijack || got[i].Comment != w.Comment:
			note(fmt.Sprintf("правило «%s» изменено", ruleText(got[i])))
		}
	}
	if len(changes) == 0 {
		note("правила группы переставлены или изменены")
	}
	if len(changes) > maxChanges {
		changes = append(changes[:maxChanges], fmt.Sprintf("и ещё %d", len(changes)-maxChanges))
	}
	st.Changes = changes
	return st
}

func ruleText(r acl.Rule) string {
	if t := strings.TrimSpace(r.Text); t != "" {
		return t
	}
	return r.Outbound + "(" + r.Address + ")"
}

// afterHeader are the lines of before below its last group header (all of
// them without one): the lines inside the group the rule starts.
func afterHeader(before []string) []string {
	for i := len(before) - 1; i >= 0; i-- {
		if _, ok := acl.HeaderOf(before[i]); ok {
			return before[i+1:]
		}
	}
	return before
}

// aboveHeader are the lines of before above its last group header: they
// belong to what comes before the group.
func aboveHeader(before []string) []string {
	for i := len(before) - 1; i >= 0; i-- {
		if _, ok := acl.HeaderOf(before[i]); ok {
			return slices.Clone(before[:i])
		}
	}
	return nil
}

// markVersion is the catalog version of the builder's mark among lines
// (0: none).
func markVersion(lines []string) int {
	for _, l := range lines {
		rest, ok := strings.CutPrefix(strings.TrimSpace(l), servicesMark)
		if !ok {
			continue
		}
		digits, _, _ := strings.Cut(rest, " ")
		if v, err := strconv.Atoi(digits); err == nil && v > 0 {
			return v
		}
	}
	return 0
}

// placeServices is doc with rules as the builder's group: where the group
// is (its first rule), else after the block of local networks at the top.
// The rules outside the group stay as they are, in their order; comment
// lines above the group's header stay above it. No rules: no group.
func placeServices(doc acl.Document, rules []acl.Rule) acl.Document {
	out := acl.Document{Tail: doc.Tail}
	at := -1
	var keep []string
	for _, r := range doc.Rules {
		if r.Group == ServicesGroup {
			if at < 0 {
				at, keep = len(out.Rules), aboveHeader(r.Before)
			}
			continue
		}
		out.Rules = append(out.Rules, r)
	}
	if at < 0 {
		at = localEnd(out.Rules)
	}
	switch {
	case len(rules) > 0:
		rules = slices.Clone(rules)
		rules[0].Before = slices.Concat(keep, []string{acl.GroupHeader(ServicesGroup), servicesMarkLine()})
		out.Rules = slices.Insert(out.Rules, at, rules...)
	case len(keep) == 0:
	case at < len(out.Rules):
		out.Rules[at].Before = slices.Concat(keep, out.Rules[at].Before)
	default:
		out.Tail = slices.Concat(keep, out.Tail)
	}
	return out
}

// localEnd is where a new group goes: after the block of local networks
// at the top (the rules of the "local networks" template's group, reject
// of the networks it rejects or of geoip:private), else first.
func localEnd(rules []acl.Rule) int {
	local := map[string]bool{"geoip:private": true}
	for _, n := range localNets {
		local[n] = true
	}
	for i, r := range rules {
		if r.Group != localGroup && (r.Bad() || !strings.EqualFold(r.Outbound, "reject") || !local[addrKey(r.Address)]) {
			return i
		}
	}
	return len(rules)
}

// ServicesEditedError: the group was changed by hand (or built from
// another catalog version), and the builder was not told to overwrite it.
type ServicesEditedError struct{ Changes []string }

func (e *ServicesEditedError) Error() string {
	return "Группа «" + ServicesGroup + "» не такая, какой её собирает конструктор: " + strings.Join(e.Changes, "; ") + ". Сборка заменит её целиком."
}

// servicesEnv is what the builder knows of the server.
type servicesEnv struct {
	// entry: the server is the entry of a deployed cascade.
	entry bool
	// outbounds are the draft's outbounds.
	outbounds []string
	// visible are the services whose categories the controller's geo
	// databases have.
	visible map[string]bool
}

// buildServices is doc with the builder's group made of choices (service
// ID → outbound; "" or left out: no rules). An outbound is direct,
// reject, cascade (on the entry of a cascade only) or an outbound of the
// draft. A group changed by hand is replaced only with overwrite.
func buildServices(doc acl.Document, choices map[string]string, env servicesEnv, overwrite bool) (acl.Document, error) {
	byID := map[string]CatalogService{}
	for _, c := range catalogServices() {
		byID[c.ID] = c
	}
	ids := make([]string, 0, len(choices))
	for id := range choices {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	clean := map[string]string{}
	for _, id := range ids {
		o := strings.TrimSpace(choices[id])
		if o == "" {
			continue
		}
		c, ok := byID[id]
		switch {
		case !ok:
			return doc, &model.FieldError{Field: "choices", Msg: fmt.Sprintf("Сервиса «%s» нет в каталоге.", id)}
		case !env.visible[id]:
			return doc, &model.FieldError{Field: "choices", Msg: fmt.Sprintf("В базах geo controller нет категорий сервиса «%s»: его правила не собрать.", c.Name)}
		}
		name, err := serviceOutbound(o, env)
		if err != nil {
			return doc, err
		}
		clean[id] = name
	}
	if !overwrite {
		if st := ReadServices(doc); st.Edited {
			return doc, &ServicesEditedError{Changes: st.Changes}
		}
	}
	return placeServices(doc, serviceRules(clean)), nil
}

// serviceOutbound is the outbound a choice names, as the rules will name
// it.
func serviceOutbound(o string, env servicesEnv) (string, error) {
	switch l := strings.ToLower(o); l {
	case "direct", "reject":
		return l, nil
	case cascade.OutboundName:
		if !env.entry {
			return "", &model.FieldError{Field: "choices", Msg: "«Через выход» — только на входе развёрнутого каскада: у этого сервера выхода каскада нет."}
		}
		return l, nil
	}
	for _, n := range env.outbounds {
		if strings.EqualFold(n, o) {
			return n, nil
		}
	}
	return "", &model.FieldError{Field: "choices", Msg: fmt.Sprintf("Нет outbound «%s»: выберите «напрямую», «блок» или outbound сервера.", o)}
}

// visibleServices are the services whose geosite categories and geoip
// codes geo has (none without databases).
func visibleServices(geo hacl.GeoLoader) (map[string]bool, error) {
	out := map[string]bool{}
	if geo == nil {
		return out, nil
	}
	sites, err := geo.LoadGeoSite()
	if err != nil {
		return nil, err
	}
	ips, err := geo.LoadGeoIP()
	if err != nil {
		return nil, err
	}
	for _, c := range catalogServices() {
		ok := true
		for _, n := range c.Sites {
			ok = ok && sites[strings.ToLower(n)] != nil
		}
		for _, n := range c.IPs {
			ok = ok && ips[strings.ToLower(n)] != nil
		}
		out[c.ID] = ok
	}
	return out, nil
}

// serviceSamples are requests for the dry run: the sample domain of each
// catalog service a rule of the documents names a geosite category of.
// Rules by geo names have no samples of their own.
func serviceSamples(docs ...acl.Document) []acl.Request {
	bySite := map[string]CatalogService{}
	for _, c := range catalogServices() {
		for _, n := range c.Sites {
			bySite[n] = c
		}
	}
	var out []acl.Request
	seen := map[string]bool{}
	for _, d := range docs {
		for _, r := range d.Rules {
			name, ok := strings.CutPrefix(addrKey(r.Address), "geosite:")
			if !ok || r.Bad() {
				continue
			}
			name, _, _ = strings.Cut(name, "@")
			if c, ok := bySite[strings.TrimSpace(name)]; ok && !seen[c.ID] {
				seen[c.ID] = true
				out = append(out, acl.Request{Host: c.Sample, Proto: "tcp", Port: 443})
			}
		}
	}
	return out
}

// ServicesView is the «По сервисам» tab of a server's draft.
type ServicesView struct {
	Version int `json:"version"`
	// Sections are those with services the controller's geo databases
	// have the categories of, with those services only.
	Sections []ServiceSection `json:"sections"`
	// Hidden are the services whose categories the databases lack.
	Hidden []CatalogService `json:"hidden"`
	// NoGeo: the controller has no geo databases, so no service is shown.
	NoGeo bool `json:"noGeo,omitempty"`
	// OwnGeo: the server reads geo databases of its own, which may lack
	// categories the controller's have.
	OwnGeo bool `json:"ownGeo,omitempty"`
	// Cascade is the deployed cascade the server is the entry of: "through
	// the exit" (the cascade outbound) is offered.
	Cascade *ChainRef     `json:"cascade,omitempty"`
	State   ServicesState `json:"state"`
}

// ServicesInput is a choice per service for the draft's rules.
type ServicesInput struct {
	ACL acl.Document `json:"acl"`
	// Outbounds are the names of the draft's outbounds.
	Outbounds []string `json:"outbounds"`
	// Choices: service ID → direct, reject, cascade (the entry of a
	// cascade only) or an outbound of the draft; "" or left out: no
	// rules for the service.
	Choices map[string]string `json:"choices"`
	// Overwrite replaces a group changed by hand.
	Overwrite bool `json:"overwrite,omitempty"`
}

// ServicesResult is the draft with the builder's group.
type ServicesResult struct {
	ACL   acl.Document  `json:"acl"`
	State ServicesState `json:"state"`
}

// builderEnv is what the builder knows of the server, the deployed
// cascade it is the entry of and whether it reads geo databases of its
// own.
func (s *Service) builderEnv(ctx context.Context, serverID int64) (servicesEnv, *ChainRef, bool, error) {
	var env servicesEnv
	ref, err := s.entryOf(ctx, serverID)
	if err != nil {
		return env, nil, false, err
	}
	own := false
	_, b, err := s.Editor.Current(ctx, serverID)
	if err != nil && !errors.Is(err, apply.ErrNoConfig) {
		return env, nil, false, err
	} else if err == nil {
		if c, err := hyconfig.ParseServer(b); err == nil {
			own = s.Geo != nil && s.geoOf(c) == nil
		}
	}
	vis, err := visibleServices(s.Geo)
	if err != nil {
		return env, nil, false, &model.FieldError{Field: "geo", Msg: "Базы geo controller не читаются: " + err.Error()}
	}
	return servicesEnv{entry: ref != nil, visible: vis}, ref, own, nil
}

// Services is the tab for the draft doc of the server: the services the
// controller's geo databases have the categories of, and the builder's
// group of the draft read back.
func (s *Service) Services(ctx context.Context, serverID int64, doc acl.Document) (ServicesView, error) {
	env, ref, own, err := s.builderEnv(ctx, serverID)
	if err != nil {
		return ServicesView{}, err
	}
	v := ServicesView{Version: ServicesVersion, Sections: []ServiceSection{}, Hidden: []CatalogService{}, NoGeo: s.Geo == nil, OwnGeo: own, Cascade: ref, State: ReadServices(doc)}
	for _, sec := range Catalog() {
		shown := sec
		shown.Services = nil
		for _, c := range sec.Services {
			if env.visible[c.ID] {
				shown.Services = append(shown.Services, c)
			} else {
				v.Hidden = append(v.Hidden, c)
			}
		}
		if len(shown.Services) > 0 {
			v.Sections = append(v.Sections, shown)
		}
	}
	return v, nil
}

// BuildServices puts the group built of in.Choices into the draft
// in.ACL; nothing is stored. "Through the exit" on a server that is not
// the entry of a cascade, an unknown service or outbound is a
// *model.FieldError; a group changed by hand without in.Overwrite a
// *ServicesEditedError.
func (s *Service) BuildServices(ctx context.Context, serverID int64, in ServicesInput) (ServicesResult, error) {
	env, _, _, err := s.builderEnv(ctx, serverID)
	if err != nil {
		return ServicesResult{}, err
	}
	env.outbounds = in.Outbounds
	doc, err := buildServices(in.ACL, in.Choices, env, in.Overwrite)
	if err != nil {
		return ServicesResult{}, err
	}
	return ServicesResult{ACL: doc, State: ReadServices(doc)}, nil
}
