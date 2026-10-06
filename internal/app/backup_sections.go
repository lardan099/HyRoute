package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// The sections of a backup (the table below): what each one holds, how it is
// collected for an export, decoded (strictly) from a file and described.

type sectionDef struct {
	key, title string
	modes      []string // first = default
	defaultOn  bool
	secret     bool     // exists only in a backup with a password
	files      []string // data files the section may write (broken checks, undo titles)
}

// backupSections is the section table in the order of the export dialog,
// the preview and the restore.
var backupSections = []sectionDef{
	{"servers", "Серверы", []string{"replace", "add"}, true, false, []string{"profiles.json"}},
	{"subscriptions", "Подписки", []string{"replace", "add"}, true, true, []string{"subscriptions.json", "profiles.json"}},
	{"groups", "Группы серверов", []string{"replace", "add"}, true, false, []string{"groups.json"}}, // groups
	{"rules", "Правила", []string{"replace", "add"}, true, false, []string{"settings.json", "rulesets.json"}},
	{"proxies", "Прокси", []string{"replace", "add"}, true, false, []string{"proxies.json"}},
	{"networks", "Сети", []string{"replace", "add"}, true, false, []string{"networks.json"}}, // netmodes
	{"dns", "DNS", []string{"replace"}, true, false, []string{"dns.json"}},                   // dns
	{"settings", "Настройки", []string{"replace"}, true, false, []string{"settings.json", "prefs.json"}},
	{"geo", "Базы правил", []string{"replace"}, true, false, []string{"prefs.json"}},
	{"appearance", "Оформление", []string{"replace"}, true, false, nil},
	// stats: an independent section (B1b, stats' own files and lock), only
	// with a password (it shows which sites and programs were opened).
	{"stats", "Статистика", []string{"replace"}, false, true, nil},
}

func sectionByKey(key string) *sectionDef {
	for i := range backupSections {
		if backupSections[i].key == key {
			return &backupSections[i]
		}
	}
	return nil
}

// importLimits are the counts a restore accepts from an (untrusted) file.
// ExportBackup checks the same numbers on what it collected (checkLimits),
// so every copy HyRoute writes can be restored. The save paths have no such
// caps.
var importLimits = struct{ serversTotal, subs, rules, proxies, nameRunes int }{
	serversTotal: 10000, // manual + every subscription's servers
	subs:         100,
	rules:        10000, // per rules config (each rule profile separately)
	proxies:      64,
	nameRunes:    200, // longer names are shortened on import, never an error
}

var (
	ruleKeys = []string{"defaultAction", "defaultProfile", "defaultFallback", "rules"}
	geoKeys  = []string{"geoSource", "geoSiteURL", "geoIPURL", "geoAutoOff", "geoIntervalHours"}
	// prefsNever: prefs that stay this computer's: the skipped version, and
	// hyroutectl's access (a copy never widens it).
	prefsNever = []string{"skipVersion", "cli"}
	// settingsSecretKeys, prefsSecretKeys: keys of settings.json and
	// prefs.json that hold credentials, dropped from a copy without a
	// password (backup B4). None today.
	settingsSecretKeys, prefsSecretKeys []string
	themes                              = []string{"system", "light", "dark", "midnight"}                 // keep in sync with state.svelte.ts Theme
	accents                             = []string{"blue", "violet", "teal", "orange", "pink", "rainbow"} // … Accent
)

var themeNames = map[string]string{"system": "Как в Windows", "light": "Светлая", "dark": "Тёмная", "midnight": "Полночь"}
var accentNames = map[string]string{"blue": "Синий", "violet": "Фиолетовый", "teal": "Бирюзовый", "orange": "Оранжевый", "pink": "Розовый", "rainbow": "Радуга"}

// settingLabels are the «Настройки» page's labels of the engine and prefs
// keys (plan lines «было → станет»); weakening marks a change that lowers
// protection (a warning too). A key without a label shows as is. The cli
// key never travels (prefsNever).
var settingLabels = map[string]string{
	"killSwitch":      "Kill switch",
	"blockQUIC":       "Блокировать QUIC с неизвестным сайтом",
	"blockIPv6Tunnel": "Не пускать IPv6 в VPN",
	"preferRemoteDNS": "Узнавать адрес сайта на сервере",
	"exactWebDomains": "Точное определение сайта",
	"sniffTimeoutMs":  "Ожидание имени сайта, мс",
	"logsToDisk":      "Хранить логи на диске",
	"logMaxMB":        "Размер лога, МБ",
	"logKeep":         "Хранить файлов лога",
	"updateCheck":     "Проверка обновлений",
	"updateChannel":   "Канал обновлений",
	"autoConnect":     "Подключаться сразу после запуска",
	"closeToTray":     "Кнопка × сворачивает в трей",
}

// ---- wire types (decoded strictly) ----

type bkServers struct {
	Main string             `json:"main"`
	List []hysteria.Profile `json:"list"`
}

type bkSub struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	URL      string             `json:"url"`
	Enabled  bool               `json:"enabled"`
	Interval string             `json:"interval"`
	UserInfo string             `json:"userInfo,omitempty"`
	InfoAt   time.Time          `json:"infoAt,omitzero"` // subinfo
	Servers  []hysteria.Profile `json:"servers"`
}

type bkRules struct {
	Config   rules.Config    `json:"config"`
	Rulesets json.RawMessage `json:"rulesets,omitempty"` // store.Rulesets (rulesets); Pending never exported
}

type bkProxy struct {
	store.LocalProxy
	Password string `json:"password"`
}

type bkSettings struct {
	Engine map[string]json.RawMessage `json:"engine"` // nil (null) = not in the copy; {} = every option at its default
	Prefs  map[string]json.RawMessage `json:"prefs"`
}

type bkGeo struct {
	GeoSource        string `json:"geoSource,omitempty"`
	GeoSiteURL       string `json:"geoSiteURL,omitempty"`
	GeoIPURL         string `json:"geoIPURL,omitempty"`
	GeoAutoOff       *bool  `json:"geoAutoOff,omitempty"`
	GeoIntervalHours int    `json:"geoIntervalHours,omitempty"`
}

// decoded is a payload's sections decoded; errs holds why a section cannot
// be imported (its key then has no value here).
type decoded struct {
	servers    *bkServers
	subs       []bkSub
	groups     *groups.File
	rules      *bkRules
	rulesets   *store.Rulesets
	proxies    []bkProxy
	settings   *bkSettings
	geo        *bkGeo
	appearance *BackupAppearance
	net        *netmode.Config   // netmodes
	dns        *dnspolicy.Config // dns
	stats      json.RawMessage   // stats: checked by the stats store (CheckStatsImport)
	errs       map[string]string
	unknown    []string // section keys this version does not know
}

func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("лишние данные после раздела")
	}
	return nil
}

// errNewerSection: a section's own format version is newer than this
// HyRoute reads.
var errNewerSection = errors.New("формат новее, чем читает эта версия")

// sectionErr is the text of a section that cannot be imported.
func sectionErr(err error) string {
	if s := err.Error(); strings.Contains(s, "unknown field") || errors.Is(err, errNewerSection) {
		return "Раздел сделан более новой версией HyRoute и не читается этой: " + s
	}
	return "Раздел повреждён: " + err.Error()
}

// parseImportGroups reads a «Группы» section strictly with groups.Parse's
// rules, except that a malformed group ID («grp-XYZ», «../x») is not an
// error: planGroups renumbers it, so the file keeps it as is.
func parseImportGroups(raw json.RawMessage) (*groups.File, error) {
	var f groups.File
	if err := strictDecode(raw, &f); err != nil {
		return nil, err
	}
	cp := f.Clone()
	used := map[string]bool{}
	for _, g := range cp.Groups {
		used[g.ID] = true
	}
	n := 0
	for i := range cp.Groups {
		g := &cp.Groups[i]
		if groups.ValidID(g.ID) {
			continue
		}
		id := ""
		for id == "" || used[id] {
			n++
			id = groups.NewID(fmt.Sprintf("%012x", n))
		}
		used[id] = true
		if cp.Main == g.ID {
			cp.Main = id
		}
		g.ID = id
	}
	b, _ := json.Marshal(cp)
	if _, err := groups.Parse(b); err != nil {
		return nil, err
	}
	return f.Clone(), nil
}

// parseImportNetworks reads a «Сети» section strictly with netmode.Parse's
// rules, except that a malformed or repeated rule ID and a malformed rule
// profile reference are not errors: the plan gives such a rule a new ID
// and drops the reference with a warning, so the result keeps them as
// they are (normalized).
func parseImportNetworks(raw json.RawMessage) (*netmode.Config, error) {
	var cfg netmode.Config
	if err := strictDecode(raw, &cfg); err != nil {
		return nil, err
	}
	switch {
	case cfg.Version > netmode.Version:
		return nil, fmt.Errorf("правила сетей: %w (%d)", errNewerSection, cfg.Version)
	case cfg.Version < 0:
		return nil, fmt.Errorf("неверная версия формата %d", cfg.Version)
	}
	cfg.Version = netmode.Version
	netmode.Normalize(&cfg)
	check := cfg.Clone()
	seen := map[string]bool{}
	for i := range check.Rules {
		r := &check.Rules[i]
		if !netmode.ValidID(r.ID) || seen[r.ID] {
			r.ID = ""
		}
		seen[r.ID] = true
		if !netmode.ValidID(r.Ruleset) {
			r.Ruleset = ""
		}
	}
	if !netmode.ValidID(check.Unknown.Ruleset) {
		check.Unknown.Ruleset = ""
	}
	if err := netmode.Validate(check); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// parseImportDNS reads a «DNS» section: strict, normalized and validated
// as SaveDNS does. A custom server's host never reaches the error text
// (as dnsLoadError).
func parseImportDNS(raw json.RawMessage) (*dnspolicy.Config, error) {
	var cfg dnspolicy.Config
	if err := strictDecode(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		var he dnspolicy.HostError
		if errors.As(err, &he) {
			return nil, errors.New("неверное имя или IP своего DNS-сервера")
		}
		return nil, err
	}
	return &cfg, nil
}

// decodeSections decodes every known section of p strictly.
func decodeSections(p *backup.Payload) *decoded {
	d := &decoded{errs: map[string]string{}}
	for key, raw := range p.Sections {
		if e := p.Errors[key]; e != "" {
			d.errs[key] = e // a legacy section that did not map
			continue
		}
		var err error
		switch key {
		case "servers":
			var v bkServers
			if err = strictDecode(raw, &v); err == nil {
				d.servers = &v
			}
		case "subscriptions":
			if !p.Secrets {
				err = errors.New("подписки в копии без пароля не хранятся")
			} else if err = strictDecode(raw, &d.subs); err == nil && len(d.subs) > importLimits.subs {
				err = fmt.Errorf("подписок больше %d", importLimits.subs)
			}
		case "groups":
			var f *groups.File
			if f, err = parseImportGroups(raw); err == nil {
				d.groups = f
			}
		case "rules":
			var v bkRules
			if err = strictDecode(raw, &v); err == nil && len(v.Config.Rules) > importLimits.rules {
				err = fmt.Errorf("правил больше %d", importLimits.rules)
			}
			if err == nil && len(v.Rulesets) > 0 && string(v.Rulesets) != "null" {
				var rs *store.Rulesets
				if rs, err = store.ParseRulesets(v.Rulesets); err == nil {
					for _, e := range rs.List {
						if e.Newer() {
							err = fmt.Errorf("unknown field в профиле правил «%s»", e.Name)
							break
						}
						if len(e.Config.Rules) > importLimits.rules {
							err = fmt.Errorf("правил больше %d", importLimits.rules)
							break
						}
					}
					rs.Pending = nil
					d.rulesets = rs
				}
			}
			if err == nil {
				d.rules = &v
			}
		case "proxies":
			if err = strictDecode(raw, &d.proxies); err == nil && len(d.proxies) > importLimits.proxies {
				err = fmt.Errorf("прокси больше %d", importLimits.proxies)
			}
		case "settings":
			var v bkSettings
			if err = strictDecode(raw, &v); err == nil {
				if v.Prefs != nil {
					err = checkPrefsPart(v.Prefs)
				}
				if err == nil && v.Engine != nil {
					err = checkEnginePart(v.Engine)
				}
				d.settings = &v
			}
		case "geo":
			var v bkGeo
			if err = strictDecode(raw, &v); err == nil {
				err = validateGeoPrefs(v.GeoSource, v.GeoSiteURL, v.GeoIPURL, v.GeoIntervalHours)
			}
			if err == nil {
				d.geo = &v
			}
		case "appearance":
			var v BackupAppearance
			if err = strictDecode(raw, &v); err == nil {
				d.appearance = &v
			}
		case "networks":
			d.net, err = parseImportNetworks(raw)
		case "dns":
			d.dns, err = parseImportDNS(raw)
		case "stats":
			if !p.Secrets {
				err = errors.New("статистика в копии без пароля не хранится")
			} else {
				d.stats = raw
			}
		default:
			d.unknown = append(d.unknown, key)
			continue
		}
		if err != nil {
			d.errs[key] = sectionErr(err)
			switch key {
			case "servers":
				d.servers = nil
			case "subscriptions":
				d.subs = nil
			case "rules":
				d.rules, d.rulesets = nil, nil
			case "proxies":
				d.proxies = nil
			case "settings":
				d.settings = nil
			}
		}
	}
	if d.servers != nil {
		if n := len(d.servers.List) + subServers(d.subs); n > importLimits.serversTotal {
			d.errs["servers"] = sectionErr(fmt.Errorf("серверов больше %d", importLimits.serversTotal))
			d.servers = nil
		}
	}
	if n := subServers(d.subs); n > importLimits.serversTotal {
		d.errs["subscriptions"] = sectionErr(fmt.Errorf("серверов больше %d", importLimits.serversTotal))
		d.subs = nil
	}
	slices.Sort(d.unknown)
	return d
}

func subServers(subs []bkSub) int {
	n := 0
	for _, s := range subs {
		n += len(s.Servers)
	}
	return n
}

// checkEnginePart: the engine keys decode strictly into settings.Settings
// (an unknown key = a newer HyRoute). Rule keys never travel here.
func checkEnginePart(m map[string]json.RawMessage) error {
	m = maps.Clone(m)
	for _, k := range ruleKeys {
		delete(m, k)
	}
	b, _ := json.Marshal(m)
	return strictDecode(b, &settings.Settings{})
}

// checkPrefsPart: the prefs keys decode strictly into store.Prefs and take
// only the values the «Настройки» page allows.
func checkPrefsPart(m map[string]json.RawMessage) error {
	b, _ := json.Marshal(m)
	var p store.Prefs
	if err := strictDecode(b, &p); err != nil {
		return err
	}
	return checkPrefs(p)
}

func checkPrefs(p store.Prefs) error {
	switch {
	case p.UpdateCheck != "" && p.UpdateCheck != "auto" && p.UpdateCheck != "manual":
		return fmt.Errorf("неизвестный режим проверки обновлений %q", p.UpdateCheck)
	case p.UpdateChannel != "" && p.UpdateChannel != "stable" && p.UpdateChannel != "beta":
		return fmt.Errorf("неизвестный канал обновлений %q", p.UpdateChannel)
	case p.LogMaxMB < 0 || p.LogMaxMB > 200:
		return fmt.Errorf("размер лога %d МБ вне 0–200", p.LogMaxMB)
	case p.LogKeep < 0 || p.LogKeep > 20:
		return fmt.Errorf("число файлов лога %d вне 0–20", p.LogKeep)
	}
	return nil
}

// ---- the configuration a backup is made from and a restore produces ----

// cfgState holds deep copies: plans never touch the controller's values.
type cfgState struct {
	Profiles store.Profiles
	Subs     []store.Subscription
	Settings settings.Settings
	Proxies  []store.LocalProxy
	Prefs    store.Prefs
	Groups   *groups.File     // groups: never nil
	Rulesets *store.Rulesets  // rulesets: nil = not saved (or broken)
	Net      netmode.Config   // netmodes
	DNS      dnspolicy.Config // dns
	// Broken: file name → load error.
	Broken map[string]error
}

// snapshotLocked copies the configuration (c.mu held).
func (c *Controller) snapshotLocked() cfgState {
	s := cfgState{
		Profiles: store.Profiles{Active: c.profiles.Active, List: slices.Clone(c.profiles.List)},
		Subs:     slices.Clone(c.subs),
		Proxies:  slices.Clone(c.proxies),
		Prefs:    c.prefs,
		Groups:   c.groupsFile.Clone(),
		Broken:   map[string]error{},
	}
	s.Settings = *c.settings
	s.Settings.Config = c.settings.Config.Clone()
	if c.rulesets != nil && c.rulesetsBroken == nil {
		s.Rulesets = c.rulesets.Clone()
		s.Rulesets.Pending = nil
		if a := s.Rulesets.Find(s.Rulesets.Active); a != nil {
			a.SetConfig(c.settings.Config)
		}
	}
	net, netErr := c.netExportLocked()
	s.Net, s.DNS = net, c.dns
	for name, err := range map[string]error{"profiles.json": c.profilesBroken, "subscriptions.json": c.subsBroken,
		"settings.json": c.settingsBroken, "proxies.json": c.proxiesBroken, "prefs.json": c.prefsBroken,
		"groups.json": c.groupsBroken, "rulesets.json": c.rulesetsBroken, "dns.json": c.dnsBroken, "networks.json": netErr} {
		if err != nil {
			s.Broken[name] = err
		}
	}
	return s
}

// mainTarget is the result's main target (groups' main, else the server).
func (s *cfgState) mainTarget() string {
	if s.Groups != nil && s.Groups.Main != "" {
		return s.Groups.Main
	}
	return s.Profiles.Active
}

// eachConfig visits the active rules and every inactive rule profile.
func (s *cfgState) eachConfig(fn func(label string, cfg *rules.Config)) {
	fn("", &s.Settings.Config)
	if s.Rulesets == nil {
		return
	}
	for i := range s.Rulesets.List {
		if e := &s.Rulesets.List[i]; e.ID != s.Rulesets.Active {
			fn(e.Name, &e.Config)
		}
	}
}

// ---- collect (export) ----

// collectSections builds the chosen sections of an export and their
// reference table.
func collectSections(st cfgState, keys []string, secrets bool, app *BackupAppearance) (map[string]json.RawMessage, map[string]backup.Target, error) {
	out := map[string]json.RawMessage{}
	var refs []string
	put := func(key string, v any) error {
		b, err := json.Marshal(v)
		if err == nil {
			out[key] = b
		}
		return err
	}
	for _, key := range keys {
		def := sectionByKey(key)
		if def == nil {
			return nil, nil, fmt.Errorf("неизвестный раздел %q", key)
		}
		if def.secret && !secrets {
			return nil, nil, backup.ErrSecrets
		}
		if key != "settings" && key != "appearance" {
			for _, f := range def.files {
				if err := st.Broken[f]; err != nil && !(key == "rules" && f == "rulesets.json") {
					return nil, nil, fmt.Errorf("%s не загружен — сохранять нечего", f)
				}
			}
		}
		var err error
		switch key {
		case "servers":
			v := bkServers{Main: st.Profiles.Active, List: []hysteria.Profile{}}
			for _, p := range st.Profiles.List {
				if p.Source == "" {
					if !secrets {
						p.Auth, p.Obfs.Password = "", ""
					}
					v.List = append(v.List, p)
				}
			}
			refs = append(refs, v.Main)
			err = put(key, v)
		case "subscriptions":
			list := []bkSub{}
			for _, s := range st.Subs {
				b := bkSub{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled, Interval: s.Interval, UserInfo: s.UserInfo, InfoAt: s.InfoAt, Servers: []hysteria.Profile{}}
				for _, p := range st.Profiles.List {
					if p.Source == "sub:"+s.ID {
						b.Servers = append(b.Servers, p)
					}
				}
				list = append(list, b)
			}
			err = put(key, list)
		case "groups":
			f := st.Groups.Clone()
			if !secrets && f.Probe != nil && f.Probe.URL != "" && f.Probe.URL != groups.DefaultProbeURL {
				f.Probe.URL = "" // may carry a key: the default is used
				if f.Probe.IntervalSec == 0 {
					f.Probe = nil
				}
			}
			refs = append(refs, f.Refs()...)
			refs = append(refs, f.Main)
			for _, g := range f.Groups {
				refs = append(refs, g.ID)
			}
			err = put(key, f)
		case "rules":
			v := bkRules{Config: st.Settings.Config.Clone()}
			if v.Config.Rules == nil {
				v.Config.Rules = []rules.Rule{}
			}
			cfgs := []rules.Config{v.Config}
			if st.Rulesets != nil {
				b, err := json.Marshal(st.Rulesets)
				if err != nil {
					return nil, nil, err
				}
				v.Rulesets = b
				for _, e := range st.Rulesets.List {
					cfgs = append(cfgs, e.Config)
				}
			}
			for _, cfg := range cfgs {
				refs = append(refs, configTargets(cfg)...)
			}
			err = put(key, v)
		case "proxies":
			list := []bkProxy{}
			for _, p := range st.Proxies {
				if !secrets && p.Password != "" {
					continue
				}
				list = append(list, bkProxy{LocalProxy: p, Password: p.Password})
				refs = append(refs, p.Profile)
			}
			err = put(key, list)
		case "settings":
			v := bkSettings{}
			if st.Broken["settings.json"] == nil {
				v.Engine = jsonMap(st.Settings)
				for _, k := range ruleKeys {
					delete(v.Engine, k)
				}
				if !secrets {
					for _, k := range settingsSecretKeys {
						delete(v.Engine, k)
					}
				}
			}
			if st.Broken["prefs.json"] == nil {
				v.Prefs = jsonMap(st.Prefs)
				for _, k := range append(slices.Clone(geoKeys), prefsNever...) {
					delete(v.Prefs, k)
				}
				if !secrets {
					for _, k := range prefsSecretKeys {
						delete(v.Prefs, k)
					}
				}
			}
			if v.Engine == nil && v.Prefs == nil {
				return nil, nil, errors.New("settings.json и prefs.json не загружены — сохранять нечего")
			}
			err = put(key, v)
		case "geo":
			if st.Broken["prefs.json"] != nil {
				return nil, nil, errors.New("prefs.json не загружен — сохранять нечего")
			}
			p := st.Prefs
			v := bkGeo{GeoSource: p.GeoSource, GeoSiteURL: p.GeoSiteURL, GeoIPURL: p.GeoIPURL, GeoAutoOff: p.GeoAutoOff, GeoIntervalHours: p.GeoIntervalHours}
			if !secrets {
				// A token may sit anywhere in the URL: custom links never go
				// into a file anyone can read.
				v.GeoSiteURL, v.GeoIPURL = "", ""
				if v.GeoSource == "custom" {
					v.GeoSource = ""
				}
			}
			err = put(key, v)
		case "appearance":
			if app == nil {
				continue
			}
			err = put(key, app)
		case "networks":
			err = put(key, st.Net)
		case "dns":
			v := st.DNS
			if !secrets {
				// A custom server's URL may carry an account ID: the
				// default is used.
				for _, u := range []*dnspolicy.Upstream{&v.Tunnel, &v.Direct} {
					if u.Preset == dnspolicy.Custom {
						u.Preset, u.URL = "", ""
					}
				}
			}
			err = put(key, v)
		case "stats":
			continue // ExportBackup adds the stats store's own export
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return out, targetsOf(st, refs), nil
}

func jsonMap(v any) map[string]json.RawMessage {
	b, _ := json.Marshal(v)
	m := map[string]json.RawMessage{}
	json.Unmarshal(b, &m)
	return m
}

// configTargets lists the targets a rules config names.
func configTargets(cfg rules.Config) []string {
	out := append([]string{cfg.DefaultProfile}, cfg.DefaultFallback...)
	for _, r := range cfg.Rules {
		out = append(out, r.Profile)
		out = append(out, r.Fallback...)
	}
	return out
}

// targetsOf describes the referenced servers and groups (secret-free).
func targetsOf(st cfgState, refs []string) map[string]backup.Target {
	subName := map[string]string{}
	for _, s := range st.Subs {
		subName["sub:"+s.ID] = s.Name
	}
	out := map[string]backup.Target{}
	for _, id := range refs {
		if id == "" || len(out) >= importLimits.serversTotal {
			continue
		}
		if _, ok := out[id]; ok {
			continue
		}
		if p := st.Profiles.Find(id); p != nil {
			out[id] = backup.Target{Name: clip(p.Name, 255), Host: clip(p.Host, 255), Ports: clip(p.Ports, 255), Sub: clip(subName[p.Source], 255)}
		} else if g := st.Groups.Find(id); g != nil {
			out[id] = backup.Target{Name: clip(g.Name, 255), Group: true} // 64 runes may be 256 bytes
		}
	}
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// checkLimits counts what planRestore step 1 counts and runs the section
// checks a restore would run, so an export never writes a copy its own
// restore refuses.
func checkLimits(sections map[string]json.RawMessage, secrets bool) error {
	d := decodeSections(&backup.Payload{Secrets: secrets, Sections: sections})
	servers := 0
	if b, ok := sections["servers"]; ok {
		var v struct {
			List []json.RawMessage `json:"list"`
		}
		json.Unmarshal(b, &v)
		servers += len(v.List)
	}
	if b, ok := sections["subscriptions"]; ok {
		var v []struct {
			Servers []json.RawMessage `json:"servers"`
		}
		json.Unmarshal(b, &v)
		for _, s := range v {
			servers += len(s.Servers)
		}
	}
	tail := func(sec string) string {
		return fmt.Sprintf("такую копию нельзя будет восстановить. Снимите «%s» или удалите лишние", sec)
	}
	if servers > importLimits.serversTotal {
		return sentencef("В копии будет %d серверов — больше %d: такую копию нельзя будет восстановить. Снимите «Подписки» или удалите лишние серверы", servers, importLimits.serversTotal)
	}
	if b, ok := sections["subscriptions"]; ok {
		var l []json.RawMessage
		json.Unmarshal(b, &l)
		if len(l) > importLimits.subs {
			return sentencef("Подписок больше %d: %s", importLimits.subs, tail("Подписки"))
		}
	}
	if b, ok := sections["rules"]; ok {
		var v struct {
			Config struct {
				Rules []json.RawMessage `json:"rules"`
			} `json:"config"`
			Rulesets *struct {
				List []struct {
					Config struct {
						Rules []json.RawMessage `json:"rules"`
					} `json:"config"`
				} `json:"list"`
			} `json:"rulesets"`
		}
		json.Unmarshal(b, &v)
		n := len(v.Config.Rules)
		if v.Rulesets != nil {
			for _, e := range v.Rulesets.List {
				n = max(n, len(e.Config.Rules))
			}
		}
		if n > importLimits.rules {
			return sentencef("Правил больше %d: %s", importLimits.rules, tail("Правила"))
		}
	}
	if b, ok := sections["proxies"]; ok {
		var l []json.RawMessage
		json.Unmarshal(b, &l)
		if len(l) > importLimits.proxies {
			return sentencef("Прокси больше %d: %s", importLimits.proxies, tail("Прокси"))
		}
	}
	for _, def := range backupSections {
		if e := d.errs[def.key]; e != "" {
			return sentencef("Раздел «%s» не получится восстановить: %s", def.title, e)
		}
	}
	if d.proxies != nil {
		ports := map[int]bool{}
		for _, p := range d.proxies {
			if ports[p.Port] {
				return sentencef("Раздел «Прокси»: порт %d у двух прокси — такую копию нельзя будет восстановить", p.Port)
			}
			ports[p.Port] = true
		}
	}
	return nil
}

// ---- dialog texts ----

// plural is api.ts plural: "5 серверов".
func plural(n int, one, few, many string) string {
	w := many
	if m := n % 100; m < 11 || m > 14 {
		switch n % 10 {
		case 1:
			w = one
		case 2, 3, 4:
			w = few
		}
	}
	return fmt.Sprintf("%d %s", n, w)
}

func nServers(n int) string { return plural(n, "сервер", "сервера", "серверов") }
func nSubs(n int) string {
	return plural(n, "подписка", "подписки", "подписок")
}
func nRules(n int) string { return plural(n, "правило", "правила", "правил") }
func nNetRules(n int) string {
	return plural(n, "правило сетей", "правила сетей", "правил сетей")
}
func nGroups(n int) string { return plural(n, "группа", "группы", "групп") }
func nProfiles(n int) string {
	return plural(n, "профиль правил", "профиля правил", "профилей правил")
}

// geoDetail describes the rule databases' settings.
func geoDetail(src string, custom bool, auto bool, hours int) string {
	var s string
	switch {
	case custom || src == "custom":
		s = "свои ссылки"
	case src == "":
		s = "источник по умолчанию"
	default:
		s = src
		if g, ok := geodata.FindSource(src); ok && g.Name != "" {
			s = g.Name
		}
	}
	if !auto {
		return s + ", обновление вручную"
	}
	if hours <= 0 {
		hours = 12
	}
	return fmt.Sprintf("%s, раз в %d ч", s, hours)
}

// dnsDetail describes the DNS settings (never a custom server's URL).
func dnsDetail(cfg dnspolicy.Config) string {
	var parts []string
	if cfg.ByRules {
		parts = append(parts, "DNS по правилам через «"+cfg.Tunnel.UpstreamName(true)+"»")
	}
	if cfg.Direct.Preset != "" {
		parts = append(parts, "прямые запросы через «"+cfg.Direct.UpstreamName(false)+"»")
	}
	if cfg.BlockBrowserDoH {
		parts = append(parts, "браузеры не обходят DNS")
	}
	if len(parts) == 0 {
		return "всё выключено"
	}
	return strings.Join(parts, ", ")
}

func dnsCustom(cfg dnspolicy.Config) bool {
	return cfg.Tunnel.Preset == dnspolicy.Custom || cfg.Direct.Preset == dnspolicy.Custom
}

// BackupContents lists the sections for the export dialog.
func (c *Controller) BackupContents(secrets bool) []BackupSectionInfo {
	// stats: read with no Controller lock held (its own disk lock).
	statsDetail, statsEmpty := c.StatsBackupInfo()
	c.mu.Lock()
	st := c.snapshotLocked()
	c.mu.Unlock()
	out := []BackupSectionInfo{}
	for _, def := range backupSections {
		in := BackupSectionInfo{Key: def.key, Title: def.title, Available: true}
		broken := ""
		for _, f := range def.files {
			if st.Broken[f] != nil && !(def.key == "rules" && f == "rulesets.json") && def.key != "settings" {
				broken = f
			}
		}
		switch def.key {
		case "servers":
			n := 0
			for _, p := range st.Profiles.List {
				if p.Source == "" {
					n++
				}
			}
			in.Detail, in.Empty = nServers(n), n == 0
		case "subscriptions":
			n := len(st.Profiles.List)
			for _, p := range st.Profiles.List {
				if p.Source == "" {
					n--
				}
			}
			in.Detail, in.Empty = nSubs(len(st.Subs))+", "+nServers(n), len(st.Subs) == 0
			if !secrets {
				in.Available, in.Reason = false, "нужен пароль: ссылка подписки — это ключ доступа"
			}
		case "groups":
			in.Detail, in.Empty = nGroups(len(st.Groups.Groups)), len(st.Groups.Groups) == 0 && st.Groups.Main == "" && st.Groups.Probe == nil
			if !secrets && st.Groups.Probe != nil && st.Groups.Probe.URL != "" && st.Groups.Probe.URL != groups.DefaultProbeURL {
				in.Detail += " (свой адрес проверки не сохранится)"
			}
		case "rules":
			in.Detail = nRules(len(st.Settings.Rules))
			if st.Rulesets != nil {
				in.Detail += " · " + nProfiles(len(st.Rulesets.List))
			} else if st.Broken["rulesets.json"] != nil {
				// Only the active rules go into the copy then.
				in.Detail += " · rulesets.json не загружен — другие профили правил не сохранятся"
			}
		case "proxies":
			withPass := 0
			for _, p := range st.Proxies {
				if p.Password != "" {
					withPass++
				}
			}
			in.Detail, in.Empty = plural(len(st.Proxies), "прокси", "прокси", "прокси"), len(st.Proxies) == 0
			if !secrets && withPass > 0 {
				in.Detail += fmt.Sprintf(" (%d с паролем не сохранится)", withPass)
				if withPass == len(st.Proxies) {
					// Nothing to save, but the proxies are there: say why.
					in.Detail = plural(len(st.Proxies), "прокси", "прокси", "прокси") + " (с паролем не сохраняются без пароля копии)"
					in.Available, in.Reason = false, in.Detail
				}
			}
		case "settings":
			in.Detail = "kill switch, запуск, журнал, обновления, параметры маршрутизации"
			switch {
			case st.Broken["settings.json"] != nil && st.Broken["prefs.json"] != nil:
				broken = "settings.json"
			case st.Broken["prefs.json"] != nil:
				in.Detail = "prefs.json не загружен — сохранятся только параметры маршрутизации"
			case st.Broken["settings.json"] != nil:
				in.Detail = "settings.json не загружен — сохранятся только журнал, обновления и запуск"
			}
		case "geo":
			p := st.Prefs
			in.Detail = geoDetail(p.GeoSource, false, p.GeoAutoUpdate(), p.GeoHours())
			if !secrets && (p.GeoSource == "custom" || p.GeoSiteURL != "" || p.GeoIPURL != "") {
				in.Detail = "свои ссылки не сохранятся: в них может быть ключ"
			}
		case "appearance":
			in.Detail = "тема и цвет акцента"
		case "networks":
			in.Detail, in.Empty = nNetRules(len(st.Net.Rules)), len(st.Net.Rules) == 0 && !st.Net.Enabled
			if !st.Net.Enabled {
				in.Detail += ", выключены"
			}
		case "dns":
			in.Detail = dnsDetail(st.DNS)
			if !secrets && dnsCustom(st.DNS) {
				in.Detail = "свой DNS-сервер не сохранится: в ссылке может быть ключ"
			}
		case "stats":
			in.Detail, in.Empty = statsDetail, statsEmpty
			if !secrets {
				in.Available, in.Reason = false, "нужен пароль: в статистике — какими программами вы пользовались"
			}
		}
		if broken != "" {
			in.Available, in.Reason = false, broken+" не загружен — сохранять нечего"
		}
		if in.Empty {
			in.Detail = "пусто"
		}
		in.Default = in.Available && !in.Empty && def.defaultOn
		out = append(out, in)
	}
	return out
}

// ---- HyRoute 1.2.0 files (.hyroute) ----

// legacyPayload is the payload of a HyRoute 1.2.0 backup (its
// internal/app/backup.go): settings.json whole, and for a full one the
// servers, subscriptions (with links), proxies (with passwords), prefs.
type legacyPayload struct {
	Settings      json.RawMessage `json:"settings"`
	Profiles      *store.Profiles `json:"profiles,omitempty"`
	Subscriptions []legacySub     `json:"subscriptions,omitempty"`
	Proxies       []bkProxy       `json:"proxies,omitempty"`
	Prefs         *store.Prefs    `json:"prefs,omitempty"`
}

type legacySub struct {
	store.Subscription
	URL string `json:"url"`
}

// legacySections maps a 1.2.0 payload into our sections. A «Только
// правила» file brings the rules only: its engine options (kill switch,
// leak protection) never replace the user's (their copies carried them,
// PITFALLS #3/#8).
func legacySections(p *backup.Payload) error {
	var lp legacyPayload
	if err := json.Unmarshal(p.LegacyData, &lp); err != nil || lp.Settings == nil {
		return backup.ErrDamaged
	}
	put := func(key string, v any) {
		b, _ := json.Marshal(v)
		p.Sections[key] = b
	}
	// settings.json that does not parse costs its rules and engine options
	// only: the servers, subscriptions, proxies and prefs still map.
	st, _, err := settings.Parse(lp.Settings)
	unreadable := func(key string) {
		p.Sections[key] = lp.Settings // listed, not importable
		if p.Errors == nil {
			p.Errors = map[string]string{}
		}
		p.Errors[key] = "Настройки из копии HyRoute 1.2.0 не читаются: " + err.Error()
	}
	var cfg rules.Config
	if err != nil {
		unreadable("rules")
	} else {
		cfg = st.Config
		put("rules", bkRules{Config: cfg})
	}
	if p.Legacy != "full" {
		return nil
	}
	var set bkSettings
	if err == nil {
		set.Engine = jsonMap(st)
		for _, k := range ruleKeys {
			delete(set.Engine, k)
		}
	}
	if lp.Prefs != nil {
		set.Prefs = jsonMap(lp.Prefs)
		for _, k := range append(slices.Clone(geoKeys), prefsNever...) {
			delete(set.Prefs, k)
		}
		put("geo", bkGeo{GeoSource: lp.Prefs.GeoSource, GeoSiteURL: lp.Prefs.GeoSiteURL, GeoIPURL: lp.Prefs.GeoIPURL,
			GeoAutoOff: lp.Prefs.GeoAutoOff, GeoIntervalHours: lp.Prefs.GeoIntervalHours})
	}
	if set.Engine != nil || set.Prefs != nil {
		put("settings", set)
	} else {
		unreadable("settings")
	}
	if lp.Profiles != nil {
		srv := bkServers{Main: lp.Profiles.Active, List: []hysteria.Profile{}}
		for _, pr := range lp.Profiles.List {
			if pr.Source == "" {
				srv.List = append(srv.List, pr)
			}
		}
		put("servers", srv)
		subs := []bkSub{}
		for _, s := range lp.Subscriptions {
			b := bkSub{ID: s.ID, Name: s.Name, URL: s.URL, Enabled: s.Enabled, Interval: s.Interval, UserInfo: s.UserInfo, InfoAt: s.InfoAt, Servers: []hysteria.Profile{}}
			for _, pr := range lp.Profiles.List {
				if pr.Source == "sub:"+s.ID {
					b.Servers = append(b.Servers, pr)
				}
			}
			subs = append(subs, b)
		}
		put("subscriptions", subs)
		// The rules may name subscription servers: describe them.
		cur := cfgState{Profiles: *lp.Profiles, Groups: &groups.File{}}
		for _, s := range lp.Subscriptions {
			cur.Subs = append(cur.Subs, s.Subscription)
		}
		p.Targets = targetsOf(cur, append(configTargets(cfg), lp.Profiles.Active))
	}
	if lp.Proxies != nil {
		// socks-udp: HyRoute 1.2.0 served UDP on every LAN proxy (and wrote
		// no "udp"): a restored one keeps it, as KeepV12ProxyUDP does.
		for i := range lp.Proxies {
			if lp.Proxies[i].LAN && lp.Proxies[i].UDP == "" {
				lp.Proxies[i].UDP = "on"
			}
		}
		put("proxies", lp.Proxies)
	}
	return nil
}

// maskedHost is a subscription URL's host for the preview (sensitive).
func maskedHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "ссылка"
	}
	return u.Hostname()
}
