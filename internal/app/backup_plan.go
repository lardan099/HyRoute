package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// planRestore turns a backup and the user's choice into the
// configuration a restore produces, the files it writes and the texts the
// user confirms. Pure and deterministic given env: it never opens, stats
// or resolves a path or a host from the backup, and never logs.

// planEnv is what the plan needs from the OS; tests fake it.
type planEnv struct {
	newID     func() string
	driveType func(root string) uint32 // GetDriveTypeW on Windows (no file on the path is opened)
	// stats: CheckStatsImport's result for the file's «Статистика», made
	// by the caller before any Controller lock (B1b).
	statsDetail string
	statsErr    error
}

const (
	driveRemovable = 2
	driveFixed     = 3
)

// restoreWrites is the write order of a restore: subscriptions first (see
// AddSubscription), targets before what references them, rule profiles
// before the network rules that name them.
var restoreWrites = []string{"subscriptions.json", "profiles.json", "groups.json", "proxies.json", "settings.json", "rulesets.json",
	"networks.json", "dns.json", "prefs.json"}

type restorePlan struct {
	next        cfgState
	writes      []string // in restoreWrites order
	keepBroken  []string // written files that are broken now: a copy is kept first
	sections    []string // keys applied, table order
	removedSubs []string // current subscription IDs absent from next.Subs
	refreshSubs []string // enabled subscriptions to update afterwards
	redact      map[string][]string
	appearance  *BackupAppearance
	ksChange    int // -1 off, 0 same, +1 on
	rules       rulesWrite
	counts      struct{ servers, rules int }
	lines       []BackupMsg
	warnings    []BackupMsg
	err         string
}

// rulesWrite is how the rules step writes (backup_commit.go).
type rulesWrite struct {
	// rulesets: the rule profiles to write (nil = keep what is there);
	// only: rulesets.json alone (an add of profiles), else a pair.
	rulesets *store.Rulesets
	only     bool
}

// ---- message builder ----

type msgB struct{ m BackupMsg }

func msg(key string) *msgB { return &msgB{BackupMsg{Key: key, Parts: []BackupPart{}}} }

// t appends plain text, s a part Privacy mode replaces with «***».
func (b *msgB) t(s string) *msgB { return b.add(s, false) }
func (b *msgB) s(s string) *msgB { return b.add(s, true) }

func (b *msgB) add(s string, sens bool) *msgB {
	if s != "" {
		b.m.Parts = append(b.m.Parts, BackupPart{T: s, S: sens})
		b.m.Text += s
	}
	return b
}

func (pl *restorePlan) line(b *msgB) { pl.lines = append(pl.lines, b.m) }
func (pl *restorePlan) warn(b *msgB) { pl.warnings = append(pl.warnings, b.m) }
func (pl *restorePlan) linef(key, f string, a ...any) {
	pl.line(msg(key).t(fmt.Sprintf(f, a...)))
}
func (pl *restorePlan) warnf(key, f string, a ...any) {
	pl.warn(msg(key).t(fmt.Sprintf(f, a...)))
}

// planDigest is BackupPlan.Digest: sha256 over the error, then every line
// and warning (key and text, NUL-separated). Texts never carry IDs.
func planDigest(pl *restorePlan) string {
	h := sha256.New()
	h.Write([]byte(pl.err))
	h.Write([]byte{0})
	for _, l := range [][]BackupMsg{pl.lines, pl.warnings} {
		for _, m := range l {
			h.Write([]byte(m.Key))
			h.Write([]byte{0})
			h.Write([]byte(m.Text))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- small checks ----

var (
	importIDRe = regexp.MustCompile(`^[0-9a-f]{8,32}$`)
	ruleIDRe   = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)
)

// shortName trims s and cuts it to importLimits.nameRunes runes.
func shortName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= importLimits.nameRunes {
		return s, false
	}
	r := []rune(s)[:importLimits.nameRunes]
	return strings.TrimRight(string(r), " "), true
}

// importedPathErr accepts only a local fixed or removable drive-letter path
// (backup B6); the reason otherwise. Nothing on the path is opened.
func importedPathErr(p string, env planEnv) string {
	switch {
	case len(p) > 260:
		return "путь длиннее 260 символов"
	case p != strings.TrimSpace(p):
		return "пробел в начале или в конце"
	case strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`):
		return "сетевой путь"
	case len(p) < 3 || !(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') || p[1] != ':' || p[2] != '\\':
		return "не полный путь на диске"
	case strings.Contains(p[2:], ":"):
		return "недопустимое имя"
	case filepath.Clean(p) != p || strings.Contains(p, `\..\`) || strings.Contains(p, "/"):
		return "путь не в обычном виде"
	}
	if env.driveType == nil {
		return "диск неизвестен"
	}
	if t := env.driveType(p[:3]); t != driveFixed && t != driveRemovable {
		return "не локальный диск"
	}
	return ""
}

// validServer is SaveProfile's check of an imported server: the host
// check and Validate (a placeholder obfs password stands for one a copy
// without secrets could not carry). It returns the server normalized.
func validServer(p hysteria.Profile, secrets bool) (hysteria.Profile, error) {
	host, ports, err := editorHost(p.Host, p.Ports)
	if err != nil {
		return p, err
	}
	p.Host, p.Ports = host, ports
	q := p
	if !secrets && q.Obfs.Password == "" {
		q.Obfs.Password = "x"
	}
	if err := q.Validate(); err != nil {
		return p, err
	}
	if p.Name == "" {
		p.Name = p.Host
	}
	return p, nil
}

// validSubURL is httpFetch's check: http(s) with a host.
func validSubURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("ссылка подписки должна начинаться с http:// или https://")
	}
	return nil
}

// ---- server matching ----

// srvIndex buckets servers by host and ports: SameConnection needs both
// equal, and a 10 000-server restore must not compare every pair.
type srvIndex map[string][]int

// hostKey takes the ports as a set, like connKey: a backup made by
// HyRoute up to v1.3.0-beta.3 may hold "443,443,20000-30000" for the
// server a subscription now gives as "443,20000-30000".
func hostKey(p *hysteria.Profile) string { return p.Host + "\x00" + hysteria.NormalizePorts(p.Ports) }

func indexOf(list []hysteria.Profile) srvIndex {
	ix := srvIndex{}
	for i := range list {
		k := hostKey(&list[i])
		ix[k] = append(ix[k], i)
	}
	return ix
}

// matchServer finds b among pool: connection equal (secrets ignored when b
// is secret-free); the one with b's ID, else the only one, else none
// (ambiguous when there were several). IDs and names never match alone.
func matchServer(b hysteria.Profile, pool []hysteria.Profile, ix srvIndex, secretFree bool, skip func(int) bool) (int, bool) {
	var cand []int
	b.Ports = hysteria.NormalizePorts(b.Ports)
	for _, i := range ix[hostKey(&b)] {
		if skip != nil && skip(i) {
			continue
		}
		x := pool[i]
		x.Ports = b.Ports // the same set: hostKey
		if secretFree && hysteria.SameConnectionNoSecrets(b, x) || !secretFree && hysteria.SameConnection(b, x) {
			cand = append(cand, i)
		}
	}
	for _, i := range cand {
		if pool[i].ID == b.ID {
			return i, false
		}
	}
	if len(cand) == 1 {
		return cand[0], false
	}
	return -1, len(cand) > 1
}

// ---- the plan ----

type planCtx struct {
	pl       *restorePlan
	cur      cfgState
	p        *backup.Payload
	d        *decoded
	ch       map[string]string
	env      planEnv
	tmap     map[string]string           // backup target ID → result ID (servers and groups)
	full     map[string]hysteria.Profile // the backup's servers by their ID in the file
	removed  []removedServer             // current servers the restore drops (kept if still referenced)
	cands    []removedServer             // add mode: subscription servers of the file not matched, kept only if referenced
	dangling []danglingRef
	shortN   int
	used     map[string]bool // IDs taken in the result
	// groupsReplaced: the current groups a «Группы: Заменить» replaced.
	groupsReplaced *groups.File
	// rsmap: rule profile ID in the file → its ID in the result.
	rsmap map[string]string
	// serversSum: the line «Серверы: будет …» (index in pl.lines, +1; 0 =
	// none) with its counts; the totals are filled in once the servers
	// still referenced are kept (finishServersLine).
	serversSum                int
	serversAdd, serversUpdate int
}

type removedServer struct {
	p   hysteria.Profile
	sub string // "sub:<id>" it belonged to ("" = manual)
}

type danglingRef struct{ where, id string }

// planRestore computes the restore of p's sections chosen in ch over cur.
func planRestore(cur cfgState, p *backup.Payload, ch BackupChoice, env planEnv) *restorePlan {
	d := decodeSections(p)
	pl := &restorePlan{redact: map[string][]string{}}
	x := &planCtx{pl: pl, cur: cur, p: p, d: d, ch: map[string]string{}, env: env, tmap: map[string]string{},
		full: map[string]hysteria.Profile{}, used: map[string]bool{}, rsmap: map[string]string{}}
	for k, m := range ch.Sections {
		x.ch[k] = m
	}
	if err := x.selection(); err != "" {
		pl.err = err
		return pl
	}
	pl.next = cur
	pl.next.Profiles = store.Profiles{Active: cur.Profiles.Active, List: slices.Clone(cur.Profiles.List)}
	pl.next.Subs = slices.Clone(cur.Subs)
	pl.next.Proxies = slices.Clone(cur.Proxies)
	pl.next.Groups = cur.Groups.Clone()
	pl.next.Settings.Config = cur.Settings.Config.Clone()
	if cur.Rulesets != nil {
		pl.next.Rulesets = cur.Rulesets.Clone()
	}
	pl.next.Broken = maps.Clone(cur.Broken)
	x.collectFull()

	x.planServers()
	x.planSubs()
	x.planMain()
	x.planGroups()
	x.planRules()
	x.planProxies()
	x.keepReferenced()
	x.keepReplacedGroups()
	x.keepGroupMembers()
	x.finishServersLine()
	x.finishGroups()
	x.reportDangling()
	x.planNetworks()
	x.planDNS()
	x.planSettings()
	x.planAppearance()
	x.planStats()
	if x.shortN > 0 {
		pl.linef("", "Имена длиннее %d символов сокращены: %d.", importLimits.nameRunes, x.shortN)
	}
	if pl.err == "" {
		x.finalCheck()
	}
	if pl.err == "" {
		x.decideWrites()
	}
	return pl
}

func (x *planCtx) chosen(key string) bool  { return x.ch[key] != "" }
func (x *planCtx) replace(key string) bool { return x.ch[key] == "replace" }

// selection is step 0: the choice, broken files, reference safety.
func (x *planCtx) selection() string {
	if len(x.ch) == 0 {
		return "Выберите хотя бы один раздел"
	}
	for key, mode := range x.ch {
		def := sectionByKey(key)
		if def == nil {
			return fmt.Sprintf("Раздел «%s» этой версией HyRoute не восстанавливается", key)
		}
		if _, ok := x.p.Sections[key]; !ok {
			return fmt.Sprintf("Раздела «%s» в копии нет", def.title)
		}
		if e := x.d.errs[key]; e != "" {
			return fmt.Sprintf("«%s»: %s", def.title, e)
		}
		if !slices.Contains(def.modes, mode) {
			return fmt.Sprintf("«%s»: такой режим не поддерживается", def.title)
		}
	}
	broken := func(f string) bool { return x.cur.Broken[f] != nil }
	covered := map[string]bool{
		"profiles.json":      x.replace("servers") && (!broken("subscriptions.json") || x.replace("subscriptions")),
		"subscriptions.json": x.replace("subscriptions"),
		"groups.json":        x.replace("groups"),
		"settings.json":      x.replace("rules"),
		"rulesets.json":      x.replace("rules") && x.d.rulesets != nil,
		"proxies.json":       x.replace("proxies"),
		"prefs.json":         x.replace("settings") && x.d.settings != nil && x.d.settings.Prefs != nil || x.replace("geo"),
		"networks.json":      x.replace("networks"),
		"dns.json":           x.replace("dns"),
	}
	coverBy := map[string]string{"profiles.json": "Серверы", "subscriptions.json": "Подписки", "groups.json": "Группы серверов",
		"settings.json": "Правила", "rulesets.json": "Правила", "proxies.json": "Прокси", "prefs.json": "Настройки",
		"networks.json": "Сети", "dns.json": "DNS"}
	for _, def := range backupSections {
		if !x.chosen(def.key) {
			continue
		}
		for _, f := range x.sectionWrites(def.key) {
			if broken(f) && !covered[f] {
				by := "«" + coverBy[f] + "»"
				if f == "profiles.json" && broken("subscriptions.json") {
					by = "«Серверы» и «Подписки»" // each holds part of the file
				}
				return fmt.Sprintf("%s не загружен: чтобы восстановить его, отметьте %s в режиме «Заменить»", f, by)
			}
		}
	}
	if x.replace("servers") || x.replace("subscriptions") {
		for _, f := range []string{"settings.json", "proxies.json", "rulesets.json", "groups.json"} {
			if broken(f) && !covered[f] {
				return fmt.Sprintf("%s не загружен: заменить серверы нельзя — неизвестно, какие из них нужны правилам, прокси и группам", f)
			}
		}
	}
	return ""
}

// sectionWrites are the files a chosen section writes.
func (x *planCtx) sectionWrites(key string) []string {
	switch key {
	case "servers":
		return []string{"profiles.json"}
	case "subscriptions":
		return []string{"subscriptions.json", "profiles.json"}
	case "groups":
		return []string{"groups.json"}
	case "rules":
		if x.d.rulesets != nil {
			return []string{"settings.json", "rulesets.json"}
		}
		return []string{"settings.json"}
	case "proxies":
		return []string{"proxies.json"}
	case "settings":
		var out []string
		if x.d.settings != nil && x.d.settings.Engine != nil {
			out = append(out, "settings.json")
		}
		if x.d.settings != nil && x.d.settings.Prefs != nil {
			out = append(out, "prefs.json")
		}
		return out
	case "geo":
		return []string{"prefs.json"}
	case "networks":
		return []string{"networks.json"}
	case "dns":
		return []string{"dns.json"}
	}
	return nil // stats: its own files (ReplaceStats)
}

// collectFull indexes the backup's own servers (chosen or not): resolver
// step 4 matches them by connection.
func (x *planCtx) collectFull() {
	if x.d.servers != nil {
		for _, s := range x.d.servers.List {
			x.full[s.ID] = s
		}
	}
	for _, sub := range x.d.subs {
		for _, s := range sub.Servers {
			x.full[s.ID] = s
		}
	}
}

// freeID keeps id when it is a valid import ID not taken in the result,
// else gives a new one.
func (x *planCtx) freeID(id string) string {
	if !importIDRe.MatchString(id) || x.used[id] {
		id = x.env.newID()
		for x.used[id] {
			id = x.env.newID()
		}
	}
	x.used[id] = true
	return id
}

func (x *planCtx) markUsed() {
	x.used = map[string]bool{}
	for _, p := range x.pl.next.Profiles.List {
		x.used[p.ID] = true
	}
	// A current server «Заменить» drops comes back in step 6 while
	// something refers to it: a server from the file never takes its ID
	// (a matched one gets it explicitly).
	for _, p := range x.cur.Profiles.List {
		x.used[p.ID] = true
	}
}

// importServer checks and cleans a server from the file: name, host,
// paths (backup B6). ok is false when it is skipped (with a warning).
func (x *planCtx) importServer(key string, s hysteria.Profile, cur *hysteria.Profile) (hysteria.Profile, bool) {
	var short bool
	if s.Name, short = shortName(s.Name); short {
		x.shortN++
	}
	// Before validServer: Validate refuses an ECH path that is not a local
	// drive path, and that must drop the setting, not the server.
	if s.TLS.ECH != "" && !hysteria.ECHInline(s.TLS.ECH) {
		if importedPathErr(s.TLS.ECH, x.env) != "" {
			s.TLS.ECH = ""
			x.pl.warn(msg(key).t("Сервер «" + s.Name + "»: настройка ECH не перенесена — укажите её в редакторе сервера"))
		} else if cur == nil || cur.TLS.ECH != s.TLS.ECH {
			x.pl.warn(msg(key).t("Сервер «" + s.Name + "» будет читать настройку ECH из файла ").s(s.TLS.ECH).t("."))
		}
	}
	s, err := validServer(s, x.p.Secrets)
	if err != nil {
		x.pl.warn(msg(key).t("Сервер «" + s.Name + "» не восстановлен: " + err.Error()))
		return s, false
	}
	if s.TLS.CA != "" {
		if why := importedPathErr(s.TLS.CA, x.env); why != "" {
			s.TLS.CA = ""
			x.pl.warn(msg(key).t("Сервер «" + s.Name + "»: путь к сертификату не перенесён (" + why + ") — укажите файл в редакторе сервера"))
		} else if cur == nil || cur.TLS.CA != s.TLS.CA {
			x.pl.warn(msg(key).t("Сервер «" + s.Name + "» будет проверять сертификат по файлу ").s(s.TLS.CA).t("."))
		}
	}
	return s, true
}

func (x *planCtx) secretFree(s hysteria.Profile) bool {
	return !x.p.Secrets || s.Auth == "" && s.Obfs.Password == ""
}

// planServers is step 2.
func (x *planCtx) planServers() {
	if !x.chosen("servers") || x.d.servers == nil {
		return
	}
	pl, next := x.pl, &x.pl.next
	var kept []hysteria.Profile
	var pool []hysteria.Profile
	if x.replace("servers") {
		for _, s := range next.Profiles.List {
			if s.Source == "" {
				pool = append(pool, s)
			} else {
				kept = append(kept, s)
			}
		}
	} else {
		kept = next.Profiles.List
		pool = next.Profiles.List
	}
	next.Profiles.List = kept
	x.markUsed()
	ix := indexOf(pool)
	matched := map[int]bool{}
	added, updated, have, noPass, inherited := 0, 0, 0, 0, 0
	for _, b := range x.d.servers.List {
		b.Source, b.Missing = "", false
		b, ok := x.importServer("servers", b, nil)
		if !ok {
			continue
		}
		free := x.secretFree(b)
		i, amb := matchServer(b, pool, ix, free, func(i int) bool { return x.replace("servers") && matched[i] })
		if amb {
			pl.warn(msg("servers").t("Сервер «" + b.Name + "»: несколько ваших серверов с такими же параметрами — пароль не подставлен"))
		}
		if !x.replace("servers") {
			if i >= 0 {
				x.tmap[b.ID] = pool[i].ID
				have++
				continue
			}
		} else if i >= 0 {
			cur := pool[i]
			matched[i] = true
			if free {
				b.Auth, b.Obfs.Password = cur.Auth, cur.Obfs.Password
				inherited++
			}
			x.tmap[b.ID] = cur.ID
			b.ID = cur.ID
			x.used[b.ID] = true
			next.Profiles.List = append(next.Profiles.List, b)
			updated++
			continue
		}
		id := x.freeID(b.ID)
		x.tmap[b.ID] = id
		b.ID = id
		if free {
			b.Auth, b.Obfs.Password = "", ""
			noPass++
		}
		next.Profiles.List = append(next.Profiles.List, b)
		added++
	}
	removedN := 0
	if x.replace("servers") {
		for i, s := range pool {
			if !matched[i] {
				x.removed = append(x.removed, removedServer{p: s})
				removedN++
			}
		}
		x.serversSum, x.serversAdd, x.serversUpdate = len(pl.lines)+1, added, updated
		pl.linef("servers", "Серверы: будет %d — добавится %d, обновится %d, удалится %d.", 0, added, updated, removedN)
	} else {
		pl.linef("servers", "Серверы: добавится %d, уже есть %d.", added, have)
	}
	if inherited > 0 {
		pl.linef("servers", "Пароли взяты у ваших серверов: %d.", inherited)
	}
	if noPass > 0 && !x.p.Secrets {
		pl.warnf("servers", "%s без пароля: впишите пароли в редакторе сервера, иначе они не подключатся.", nServers(noPass))
	}
}

// planSubs is step 3.
func (x *planCtx) planSubs() {
	if !x.chosen("subscriptions") || x.d.subs == nil {
		return
	}
	pl, next := x.pl, &x.pl.next
	curByID := map[string]store.Subscription{}
	curByURL := map[string]store.Subscription{}
	for _, s := range x.cur.Subs {
		curByID[s.ID] = s
		curByURL[s.URL] = s
	}
	usedSub := map[string]bool{}
	if x.replace("subscriptions") {
		oldServers := map[string][]hysteria.Profile{}
		var list []hysteria.Profile
		for _, s := range next.Profiles.List {
			if s.Source != "" {
				oldServers[s.Source] = append(oldServers[s.Source], s)
				x.removed = append(x.removed, removedServer{p: s, sub: s.Source})
			} else {
				list = append(list, s)
			}
		}
		next.Profiles.List = list
		next.Subs = nil
		x.markUsed()
		keptIDs := map[string]bool{}
		for _, b := range x.d.subs {
			ns, ok := x.importSub(b, usedSub)
			if !ok {
				continue
			}
			src := "sub:" + ns.ID
			if c, same := curByID[b.ID]; same && c.URL == b.URL && importIDRe.MatchString(b.ID) {
				name := ns.Name
				ns = c
				ns.Name, ns.Enabled, ns.Interval = name, b.Enabled, b.Interval
				keptIDs[ns.ID] = true
			}
			next.Subs = append(next.Subs, ns)
			old := oldServers[src]
			if !keptIDs[ns.ID] {
				old = nil
			}
			ix := indexOf(old)
			taken := map[int]bool{}
			for _, s := range b.Servers {
				s.Source = src
				s, ok := x.importServer("subscriptions", s, nil)
				if !ok {
					continue
				}
				i, _ := matchServer(s, old, ix, false, func(i int) bool { return taken[i] })
				var id string
				if i >= 0 {
					taken[i] = true
					id = old[i].ID
					x.used[id] = true
					x.dropRemoved(id)
				} else {
					id = x.freeID(s.ID)
				}
				x.tmap[s.ID] = id
				s.ID = id
				next.Profiles.List = append(next.Profiles.List, s)
			}
			if ns.Enabled {
				pl.refreshSubs = append(pl.refreshSubs, ns.ID)
			}
			pl.redact["sub:"+ns.ID] = urlSecrets(ns.URL)
		}
		gone := 0
		for _, s := range x.cur.Subs {
			if !slices.ContainsFunc(next.Subs, func(n store.Subscription) bool { return n.ID == s.ID }) {
				pl.removedSubs = append(pl.removedSubs, s.ID)
				gone++
			}
		}
		n := 0
		for _, s := range next.Profiles.List {
			if s.Source != "" {
				n++
			}
		}
		t := fmt.Sprintf("Подписки: будет %d (%s)", len(next.Subs), nServers(n))
		if gone > 0 {
			t += fmt.Sprintf(", ваших удалится: %d", gone)
		}
		pl.linef("subscriptions", "%s.", t)
		return
	}
	// Add.
	x.markUsed()
	for _, s := range next.Subs {
		usedSub[s.ID] = true
	}
	added := 0
	var have []string
	for _, b := range x.d.subs {
		if c, ok := curByURL[b.URL]; ok && b.URL != "" {
			have = append(have, c.Name)
			src := "sub:" + c.ID
			var pool []hysteria.Profile
			for _, s := range next.Profiles.List {
				if s.Source == src {
					pool = append(pool, s)
				}
			}
			ix := indexOf(pool)
			for _, s := range b.Servers {
				s.Source = src
				s, ok := x.importServer("subscriptions", s, nil)
				if !ok {
					continue
				}
				if i, _ := matchServer(s, pool, ix, false, nil); i >= 0 {
					x.tmap[s.ID] = pool[i].ID
					continue
				}
				bid := s.ID
				s.ID, s.Missing = x.freeID(s.ID), true
				x.tmap[bid] = s.ID
				x.cands = append(x.cands, removedServer{p: s, sub: src})
			}
			continue
		}
		ns, ok := x.importSub(b, usedSub)
		if !ok {
			continue
		}
		next.Subs = append(next.Subs, ns)
		src := "sub:" + ns.ID
		for _, s := range b.Servers {
			s.Source = src
			s, ok := x.importServer("subscriptions", s, nil)
			if !ok {
				continue
			}
			bid := s.ID
			s.ID = x.freeID(s.ID)
			x.tmap[bid] = s.ID
			next.Profiles.List = append(next.Profiles.List, s)
		}
		if ns.Enabled {
			x.pl.refreshSubs = append(x.pl.refreshSubs, ns.ID)
		}
		x.pl.redact["sub:"+ns.ID] = urlSecrets(ns.URL)
		added++
	}
	t := fmt.Sprintf("Подписки: добавится %d", added)
	for _, n := range have {
		t += "; «" + n + "» уже есть — её серверы останутся как есть"
	}
	x.pl.linef("subscriptions", "%s.", t)
}

// importSub checks a subscription of the file and makes its new entry.
func (x *planCtx) importSub(b bkSub, usedSub map[string]bool) (store.Subscription, bool) {
	name, short := shortName(b.Name)
	if short {
		x.shortN++
	}
	if err := validSubURL(b.URL); err != nil {
		x.pl.warn(msg("subscriptions").t("Подписка «" + name + "» не восстановлена: " + err.Error()))
		return store.Subscription{}, false
	}
	if !validInterval(b.Interval) {
		x.pl.warn(msg("subscriptions").t("Подписка «" + name + "» не восстановлена: неизвестный интервал обновления"))
		return store.Subscription{}, false
	}
	id := b.ID
	sameCur := false
	for _, c := range x.cur.Subs {
		if c.ID == id {
			sameCur = c.URL == b.URL
		}
	}
	if !importIDRe.MatchString(id) || usedSub[id] || x.replace("subscriptions") && !sameCur && slices.ContainsFunc(x.cur.Subs, func(c store.Subscription) bool { return c.ID == id }) {
		id = x.env.newID()
		for usedSub[id] {
			id = x.env.newID()
		}
	}
	usedSub[id] = true
	return store.Subscription{ID: id, Name: name, URL: b.URL, Enabled: b.Enabled, Interval: b.Interval,
		Count: len(b.Servers), UserInfo: b.UserInfo, InfoAt: b.InfoAt}, true
}

// dropRemoved: a server matched again is not removed.
func (x *planCtx) dropRemoved(id string) {
	x.removed = slices.DeleteFunc(x.removed, func(r removedServer) bool { return r.p.ID == id })
}

// planMain is step 4.
func (x *planCtx) planMain() {
	next := &x.pl.next
	if !x.chosen("servers") && !x.chosen("subscriptions") {
		return
	}
	var want string
	if x.d.servers != nil {
		want = x.tmap[x.d.servers.Main]
	}
	exists := func(id string) bool { return id != "" && next.Profiles.Find(id) != nil }
	if x.replace("servers") || x.replace("subscriptions") {
		switch {
		case exists(want):
			next.Profiles.Active = want
		case exists(next.Profiles.Active):
		case len(next.Profiles.List) > 0:
			next.Profiles.Active = next.Profiles.List[0].ID
		default:
			next.Profiles.Active = ""
		}
		return
	}
	if next.Profiles.Active == "" && exists(want) {
		next.Profiles.Active = want
	}
}

// resolve is step 5: a target named by imported data, in the result.
func (x *planCtx) resolve(id, where string) string {
	next := &x.pl.next
	if id == "" {
		return ""
	}
	if t, ok := x.tmap[id]; ok {
		if next.Profiles.Find(t) == nil && next.Groups.Find(t) == nil {
			x.dangling = append(x.dangling, danglingRef{where, t})
		}
		return t
	}
	if next.Profiles.Find(id) != nil || next.Groups.Find(id) != nil {
		return id
	}
	if f, ok := x.full[id]; ok {
		ix := indexOf(next.Profiles.List)
		if i, _ := matchServer(f, next.Profiles.List, ix, true, nil); i >= 0 {
			x.tmap[id] = next.Profiles.List[i].ID
			return next.Profiles.List[i].ID
		}
	}
	d, ok := x.p.Targets[id]
	if f, full := x.full[id]; full {
		d, ok = backup.Target{Name: f.Name, Host: f.Host, Ports: f.Ports}, true
	}
	if ok && d.Group {
		var found []string
		for _, g := range next.Groups.Groups {
			if strings.EqualFold(strings.TrimSpace(g.Name), strings.TrimSpace(d.Name)) {
				found = append(found, g.ID)
			}
		}
		if len(found) == 1 {
			x.tmap[id] = found[0]
			x.pl.line(msg("").t("Группа «" + d.Name + "» найдена среди ваших по имени."))
			return found[0]
		}
		x.tmap[id] = id
		x.dangling = append(x.dangling, danglingRef{where, id})
		return id
	}
	if ok {
		name := strings.TrimSpace(d.Name)
		pick := func(match func(p hysteria.Profile) bool, among func(p hysteria.Profile) bool) string {
			var got []string
			for _, p := range next.Profiles.List {
				if (among == nil || among(p)) && match(p) {
					got = append(got, p.ID)
				}
			}
			if len(got) == 1 {
				return got[0]
			}
			return ""
		}
		sameName := func(p hysteria.Profile) bool { return strings.EqualFold(strings.TrimSpace(p.Name), name) }
		ports := hysteria.NormalizePorts(d.Ports) // a set, as in hostKey
		sameAddr := func(p hysteria.Profile) bool {
			return strings.EqualFold(p.Host, d.Host) && hysteria.NormalizePorts(p.Ports) == ports
		}
		if r := pick(func(p hysteria.Profile) bool { return sameAddr(p) && sameName(p) }, nil); r != "" {
			x.tmap[id] = r
			x.pl.line(msg("").t("Сервер «" + d.Name + "» найден среди ваших по имени и адресу."))
			return r
		}
		r := ""
		if d.Sub != "" {
			subs := map[string]bool{}
			for _, s := range next.Subs {
				if strings.EqualFold(s.Name, d.Sub) {
					subs["sub:"+s.ID] = true
				}
			}
			r = pick(sameName, func(p hysteria.Profile) bool { return subs[p.Source] })
		}
		if r == "" {
			r = pick(sameName, nil)
		}
		if r != "" {
			x.tmap[id] = r
			x.pl.warn(msg("").t("Сервер «" + d.Name + "» найден среди ваших по имени."))
			return r
		}
		if r := pick(sameAddr, nil); r != "" {
			x.tmap[id] = r
			x.pl.warn(msg("").t("Сервер «" + d.Name + "» найден среди ваших по адресу (имя другое: «" + next.Profiles.Find(r).Name + "»)."))
			return r
		}
	}
	x.tmap[id] = id
	x.dangling = append(x.dangling, danglingRef{where, id})
	return id
}

func (x *planCtx) resolveConfig(cfg *rules.Config, label string) {
	suffix := ""
	if label != "" {
		suffix = rulesetRefSuffix(label)
	}
	cfg.DefaultProfile = x.resolve(cfg.DefaultProfile, "«Всё остальное»"+suffix)
	for j := range cfg.DefaultFallback {
		cfg.DefaultFallback[j] = x.resolve(cfg.DefaultFallback[j], "«Всё остальное»"+suffix)
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		where := "Правило «" + r.Name + "»" + suffix
		r.Profile = x.resolve(r.Profile, where)
		for j := range r.Fallback {
			r.Fallback[j] = x.resolve(r.Fallback[j], where)
		}
	}
}

// cleanRules: names shortened, rule IDs kept when valid and free.
func (x *planCtx) cleanRules(cfg *rules.Config, taken map[string]bool) {
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		var short bool
		if r.Name, short = shortName(r.Name); short {
			x.shortN++
		}
		switch {
		case r.ID == "":
		case !ruleIDRe.MatchString(r.ID):
			r.ID = ""
		case taken[r.ID]:
			r.ID = x.env.newID()
		}
		if r.ID != "" {
			taken[r.ID] = true
		}
	}
}

// planGroups: the file's groups (replace/add), remapped; used current
// groups stay in replace. Members are pruned later (finishGroups).
func (x *planCtx) planGroups() {
	if !x.chosen("groups") || x.d.groups == nil {
		return
	}
	next := &x.pl.next
	f := x.d.groups.Clone()
	gmap := map[string]string{}
	taken := map[string]bool{}
	names := map[string]bool{}
	if !x.replace("groups") {
		for _, g := range next.Groups.Groups {
			taken[g.ID] = true
			names[strings.ToLower(g.Name)] = true
		}
	}
	for i := range f.Groups {
		g := &f.Groups[i]
		id := g.ID
		if !groups.ValidID(id) || taken[id] || next.Profiles.Find(id) != nil {
			id = groups.NewID(x.env.newID())
		}
		taken[id] = true
		gmap[g.ID] = id
		x.tmap[g.ID] = id
		if !x.replace("groups") {
			name := g.Name
			for n := 2; names[strings.ToLower(name)]; n++ {
				name = fmt.Sprintf("%s (%d)", clipRunes(g.Name, groups.MaxNameRunes-5), n)
			}
			g.Name = name
			names[strings.ToLower(name)] = true
		}
	}
	f.Remap(func(m string) string { return x.resolveMember(m) }, func(id string) string { return gmap[id] })
	if x.replace("groups") {
		old := next.Groups
		next.Groups = f
		x.groupsReplaced = old
		x.pl.linef("groups", "Группы серверов: будет %d.", len(f.Groups))
		var was *groups.Probe
		if old != nil {
			was = old.Probe
		}
		x.planProbe(was, f.Probe)
		return
	}
	next.Groups.Groups = append(next.Groups.Groups, f.Groups...)
	x.pl.linef("groups", "Группы серверов: добавится %d.", len(f.Groups))
}

// planProbe shows the latency probe a «Группы серверов: Заменить» installs
// when it changes. The probe URL is fetched through every server of a used
// group on a schedule, so one other than the default is also a warning.
func (x *planCtx) planProbe(a, b *groups.Probe) {
	ua, ea := a.Effective()
	ub, eb := b.Effective()
	if ua == ub && ea == eb {
		return
	}
	x.pl.line(msg("groups").t("Проверка задержки: ").s(ua).t(fmt.Sprintf(", каждые %d с → ", int(ea.Seconds()))).
		s(ub).t(fmt.Sprintf(", каждые %d с.", int(eb.Seconds()))))
	if ub != ua && ub != groups.DefaultProbeURL {
		x.pl.warn(msg("groups").t("Группы будут проверять задержку через каждый свой сервер запросом на адрес из копии: ").s(ub).
			t(". Этот сайт увидит адреса ваших серверов и когда вы в сети."))
	}
}

// resolveMember maps a group member of the file (a server) into the result.
func (x *planCtx) resolveMember(m string) string {
	if t, ok := x.tmap[m]; ok {
		return t
	}
	return x.resolve(m, "")
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// planRules is step 5 for the rules (and rule profiles).
func (x *planCtx) planRules() {
	if !x.chosen("rules") || x.d.rules == nil {
		return
	}
	pl, next := x.pl, &x.pl.next
	before := len(next.Settings.Rules)
	fileCfg := x.d.rules.Config.Clone()
	if fileCfg.Rules == nil {
		fileCfg.Rules = []rules.Rule{}
	}
	if x.replace("rules") {
		if rs := x.d.rulesets; rs != nil {
			rs = rs.Clone()
			x.importRulesets(rs, map[string]bool{}, false)
			a := rs.Find(rs.Active)
			if a == nil && len(rs.List) > 0 {
				rs.Active, a = rs.List[0].ID, &rs.List[0]
			}
			next.Rulesets = rs
			next.Settings.Config = a.Config.Clone()
			pl.rules.rulesets = rs
			pl.counts.rules = len(a.Config.Rules)
			pl.line(msg("rules").t(fmt.Sprintf("Правила: %s из копии заменят ваши. Включится профиль правил «%s». ", nProfiles(len(rs.List)), a.Name)).t(defaultText(a.Config, x.fileTargetName)))
			return
		}
		x.cleanRules(&fileCfg, map[string]bool{})
		x.resolveConfig(&fileCfg, "")
		next.Settings.Config = fileCfg
		if next.Rulesets != nil {
			if a := next.Rulesets.Find(next.Rulesets.Active); a != nil {
				a.SetConfig(fileCfg)
			}
		}
		pl.counts.rules = len(fileCfg.Rules)
		pl.line(msg("rules").t(fmt.Sprintf("Правила: %s из копии заменят ваши %d. ", nRules(len(fileCfg.Rules)), before)).t(defaultText(fileCfg, x.fileTargetName)))
		return
	}
	if rs := x.d.rulesets; rs != nil {
		base := next.Rulesets
		if base == nil {
			// The profiles appear with this add: the current rules become
			// the first one, as with the second profile created.
			id := x.env.newID()
			base = &store.Rulesets{Version: store.RulesetsVersion, Active: id,
				List: []store.Ruleset{{ID: id, Name: defaultRulesetName, Config: next.Settings.Config.Clone()}}}
		}
		base = base.Clone()
		taken := map[string]bool{}
		for _, e := range base.List {
			taken[e.ID] = true
		}
		add := rs.Clone()
		x.importRulesets(add, taken, true)
		for _, e := range add.List {
			e.Name = store.UniqueRulesetName(base.List, e.Name)
			base.List = append(base.List, e)
		}
		if len(base.List) > store.MaxRulesets {
			pl.err = fmt.Sprintf("Профилей правил станет больше %d: выберите «Заменить»", store.MaxRulesets)
			return
		}
		next.Rulesets = base
		pl.rules.rulesets, pl.rules.only = base, true
		pl.counts.rules = len(next.Settings.Rules)
		pl.linef("rules", "Правила: добавится %s; включённый профиль не меняется.", nProfiles(len(add.List)))
		return
	}
	taken := map[string]bool{}
	for _, r := range next.Settings.Rules {
		if r.ID != "" {
			taken[r.ID] = true
		}
	}
	x.cleanRules(&fileCfg, taken)
	// «Всё остальное» stays yours in add mode: the copy's own default is
	// not resolved, so its server gives no lines about it.
	fileCfg.DefaultProfile, fileCfg.DefaultFallback = "", nil
	x.resolveConfig(&fileCfg, "")
	next.Settings.Rules = append(slices.Clone(next.Settings.Rules), fileCfg.Rules...)
	if next.Rulesets != nil {
		if a := next.Rulesets.Find(next.Rulesets.Active); a != nil {
			a.SetConfig(next.Settings.Config)
		}
	}
	pl.counts.rules = len(next.Settings.Rules)
	pl.linef("rules", "Правила: %s добавится после ваших %d. «Всё остальное» не меняется.", nRules(len(fileCfg.Rules)), before)
}

// importRulesets validates the profiles of the file: IDs (B2), names,
// rule IDs, targets.
func (x *planCtx) importRulesets(rs *store.Rulesets, taken map[string]bool, add bool) {
	names := map[string]bool{}
	for i := range rs.List {
		e := &rs.List[i]
		old := e.ID
		if !importIDRe.MatchString(e.ID) || taken[e.ID] {
			e.ID = x.env.newID()
			for taken[e.ID] {
				e.ID = x.env.newID()
			}
		}
		taken[e.ID] = true
		x.rsmap[old] = e.ID
		if rs.Active == old {
			rs.Active = e.ID
		}
		if n, err := store.CleanRulesetName(e.Name); err == nil {
			e.Name = n
		}
		if !add && names[strings.ToLower(e.Name)] {
			e.Name = store.UniqueRulesetName(rs.List[:i], e.Name)
		}
		names[strings.ToLower(e.Name)] = true
		cfg := e.Config.Clone()
		if cfg.Rules == nil {
			cfg.Rules = []rules.Rule{}
		}
		x.cleanRules(&cfg, map[string]bool{})
		x.resolveConfig(&cfg, e.Name)
		e.SetConfig(cfg)
	}
}

// defaultText describes «Всё остальное»; name names its target.
func defaultText(cfg rules.Config, name func(id string) string) string {
	switch cfg.DefaultAction {
	case rules.Direct:
		return "«Всё остальное» — напрямую."
	case rules.Block:
		return "«Всё остальное» блокируется."
	}
	if cfg.DefaultProfile == "" {
		return "«Всё остальное» — через VPN (основной сервер)."
	}
	return "«Всё остальное» — через VPN («" + name(cfg.DefaultProfile) + "»)."
}

// fileTargetName names a target the file's rules use (resolved): ours,
// else the name the file gives, else «сервер из копии» — a HyRoute 1.2.0
// «Только правила» file names none, and nothing was deleted here.
func (x *planCtx) fileTargetName(id string) string {
	next := &x.pl.next
	if next.Profiles.Find(id) != nil || next.Groups.Find(id) != nil {
		return next.targetName(id)
	}
	if t, ok := x.p.Targets[id]; ok && t.Name != "" {
		return t.Name
	}
	if f, ok := x.full[id]; ok && f.Name != "" {
		return f.Name
	}
	if groups.IsGroupID(id) {
		return "группа из копии"
	}
	return "сервер из копии"
}

func (s *cfgState) targetName(id string) string {
	if p := s.Profiles.Find(id); p != nil {
		return p.Name
	}
	if g := s.Groups.Find(id); g != nil {
		return g.Name
	}
	return "удалённый сервер"
}

// planProxies is step 5 for the proxies.
func (x *planCtx) planProxies() {
	if !x.chosen("proxies") || x.d.proxies == nil {
		return
	}
	pl, next := x.pl, &x.pl.next
	var list []store.LocalProxy
	if !x.replace("proxies") {
		list = slices.Clone(next.Proxies)
	}
	ids := map[string]bool{}
	for _, p := range list {
		ids[p.ID] = true
	}
	ports := map[int]string{}
	for _, p := range list {
		ports[p.Port] = p.Name
	}
	added := 0
	for _, b := range x.d.proxies {
		p := b.LocalProxy
		p.Password = b.Password
		var short bool
		if p.Name, short = shortName(p.Name); short {
			x.shortN++
		}
		if other, ok := ports[p.Port]; ok {
			if x.replace("proxies") {
				pl.err = fmt.Sprintf("«Прокси»: порт %d у двух прокси в копии", p.Port)
				return
			}
			pl.warn(msg("proxies").t(fmt.Sprintf("Прокси «%s»: порт %d уже занят прокси «%s» — пропущен", p.Name, p.Port, other)))
			continue
		}
		if !importIDRe.MatchString(p.ID) || ids[p.ID] {
			p.ID = x.env.newID()
			for ids[p.ID] {
				p.ID = x.env.newID()
			}
		}
		p.Profile = x.resolve(p.Profile, "Прокси «"+p.Name+"»")
		if p.LAN && p.Enabled {
			p.Enabled = false
			pl.line(msg("proxies").t("Прокси «" + p.Name + "» (доступ из локальной сети) будет выключен — включите его на странице «Прокси»."))
		}
		if err := validateProxy(p, list); err != nil {
			pl.warn(msg("proxies").t("Прокси «" + p.Name + "» не восстановлен: " + err.Error()))
			continue
		}
		// socks-udp: stored as SaveProxy stores it (a LAN proxy's value is
		// always written, so it never reads as v1.2.0's: KeepV12ProxyUDP).
		if !p.LAN {
			p.NormalizeUDP()
		} else if p.UDP == "" {
			p.UDP = "off"
		}
		ids[p.ID] = true
		ports[p.Port] = p.Name
		list = append(list, p)
		if p.Password != "" {
			pl.redact["proxy:"+p.ID] = []string{p.Password}
		}
		added++
	}
	if list == nil {
		list = []store.LocalProxy{}
	}
	next.Proxies = list
	if x.replace("proxies") {
		pl.linef("proxies", "Прокси: будет %d.", len(list))
	} else {
		pl.linef("proxies", "Прокси: добавится %d.", added)
	}
}

// resultRefs: the targets referenced in the result (every rule profile,
// disabled rules too; proxies; the main target), as targetRefsLocked.
func (x *planCtx) resultRefs() map[string][]string {
	next := &x.pl.next
	refs := map[string][]string{}
	add := func(id, where string) {
		if id != "" {
			refs[id] = append(refs[id], where)
		}
	}
	next.eachConfig(func(label string, cfg *rules.Config) {
		suffix := ""
		if label != "" {
			suffix = rulesetRefSuffix(label)
		}
		if cfg.DefaultAction == rules.Tunnel {
			add(cfg.DefaultProfile, "«Всё остальное»"+suffix)
			for _, f := range cfg.DefaultFallback {
				add(f, "«Всё остальное»"+suffix)
			}
		}
		for _, r := range cfg.Rules {
			if r.Action != rules.Tunnel {
				continue
			}
			add(r.Profile, "правило «"+r.Name+"»"+suffix)
			for _, f := range r.Fallback {
				add(f, "правило «"+r.Name+"»"+suffix)
			}
		}
	})
	for _, p := range next.Proxies {
		add(p.Profile, "прокси «"+p.Name+"»")
	}
	add(next.mainTarget(), "основной")
	return refs
}

// keep puts a removed server (or a candidate) back: manual when its
// subscription is gone, «нет в подписке» under one still there.
func (x *planCtx) keep(r removedServer) {
	next := &x.pl.next
	p := r.p
	if r.sub != "" && slices.ContainsFunc(next.Subs, func(s store.Subscription) bool { return "sub:"+s.ID == r.sub }) {
		p.Source, p.Missing = r.sub, true
	} else {
		p.Source, p.Missing = "", false
	}
	next.Profiles.List = append(next.Profiles.List, p)
}

// keepReferenced is step 6.
func (x *planCtx) keepReferenced() {
	refs := x.resultRefs()
	n := 0
	var rest []removedServer
	for _, r := range x.removed {
		if where := refs[r.p.ID]; len(where) > 0 {
			x.keep(r)
			if n++; n <= 10 {
				x.pl.line(msg("servers").t("Сервер «" + r.p.Name + "» останется: на него ссылается " + strings.Join(where, ", ") + "."))
			}
			continue
		}
		rest = append(rest, r)
	}
	var cands []removedServer
	for _, r := range x.cands {
		if len(refs[r.p.ID]) > 0 {
			x.keep(r)
			continue
		}
		cands = append(cands, r)
	}
	if n > 10 {
		x.pl.linef("servers", "И ещё %s останутся: на них ссылаются правила или прокси.", nServers(n-10))
	}
	x.removed, x.cands = rest, cands
	// Main: the server main may have been removed.
	next := &x.pl.next
	if next.Profiles.Find(next.Profiles.Active) == nil {
		next.Profiles.Active = ""
		if len(next.Profiles.List) > 0 {
			next.Profiles.Active = next.Profiles.List[0].ID
		}
	}
}

// finishServersLine counts «Серверы: будет …» on the result: the servers
// kept because something refers to them (a subscription's that became
// manual too) are there, not removed.
func (x *planCtx) finishServersLine() {
	if x.serversSum == 0 {
		return
	}
	manual, removed := 0, 0
	for _, s := range x.pl.next.Profiles.List {
		if s.Source == "" {
			manual++
		}
	}
	for _, r := range x.removed {
		if r.sub == "" {
			removed++
		}
	}
	x.pl.lines[x.serversSum-1] = msg("servers").t(fmt.Sprintf("Серверы: будет %d — добавится %d, обновится %d, удалится %d.", manual, x.serversAdd, x.serversUpdate, removed)).m
}

// keepGroupMembers is step 6b: a used group never loses its last member
// by a restore.
func (x *planCtx) keepGroupMembers() {
	next := &x.pl.next
	refs := x.resultRefs()
	exists := func(id string) bool { return next.Profiles.Find(id) != nil }
	for _, g := range next.Groups.Groups {
		if len(refs[g.ID]) == 0 || slices.ContainsFunc(g.Members, exists) {
			continue
		}
		kept := 0
		for _, m := range g.Members {
			if kept >= groups.MaxMembers {
				break
			}
			for _, list := range []*[]removedServer{&x.removed, &x.cands} {
				if i := slices.IndexFunc(*list, func(r removedServer) bool { return r.p.ID == m }); i >= 0 {
					r := (*list)[i]
					*list = slices.Delete(*list, i, i+1)
					x.keep(r)
					kept++
					x.pl.line(msg("servers").t("Сервер «" + r.p.Name + "» останется: иначе группа «" + g.Name + "», которую используют правила, останется без серверов."))
				}
			}
		}
	}
}

// keepReplacedGroups keeps the current groups a group replace would drop
// while still referenced. Before keepGroupMembers, so that the last members
// of such a group stay too; one whose name a group of the copy took gets
// " (2)", as in add mode (two groups of one name do not validate).
func (x *planCtx) keepReplacedGroups() {
	if x.groupsReplaced == nil {
		return
	}
	next := &x.pl.next
	refs := x.resultRefs()
	names := map[string]bool{}
	for _, g := range next.Groups.Groups {
		names[strings.ToLower(g.Name)] = true
	}
	for _, g := range x.groupsReplaced.Groups {
		if next.Groups.Find(g.ID) != nil || len(refs[g.ID]) == 0 {
			continue
		}
		name := g.Name
		for n := 2; names[strings.ToLower(name)]; n++ {
			name = fmt.Sprintf("%s (%d)", clipRunes(g.Name, groups.MaxNameRunes-5), n)
		}
		names[strings.ToLower(name)] = true
		line := "Группа «" + g.Name + "» останется: на неё ссылается " + strings.Join(refs[g.ID], ", ") + "."
		if name != g.Name {
			line = "Группа «" + g.Name + "» останется под именем «" + name + "» (это имя есть в копии): на неё ссылается " + strings.Join(refs[g.ID], ", ") + "."
			g.Name = name
		}
		next.Groups.Groups = append(next.Groups.Groups, g)
		x.pl.line(msg("groups").t(line))
	}
}

// finishGroups prunes members that are not servers of the result (in
// memory only when «Группы» is not restored) and reports empty groups.
func (x *planCtx) finishGroups() {
	next := &x.pl.next
	refs := x.resultRefs()
	if x.groupsReplaced != nil {
		if m := x.d.groups.Main; m != "" && next.Groups.Main == "" {
			fallback := "основным станет сервер «" + next.targetName(next.Profiles.Active) + "»"
			x.pl.warn(msg("groups").t("Основной группы «" + x.d.groups.Main + "» нет — " + fallback))
		}
	}
	exists := func(id string) bool { return next.Profiles.Find(id) != nil }
	f := next.Groups
	if !x.chosen("groups") {
		f = f.Clone() // the file is pruned by groups' own next save
	}
	before := map[string]int{}
	for _, g := range f.Groups {
		before[g.ID] = len(g.Members)
	}
	f.Prune(exists)
	if x.chosen("groups") || x.replace("servers") || x.replace("subscriptions") {
		for _, g := range f.Groups {
			if len(g.Members) > 0 || before[g.ID] == 0 && !x.chosen("groups") {
				continue
			}
			if len(refs[g.ID]) > 0 {
				x.pl.warn(msg("groups").t("Группа «" + g.Name + "» останется без серверов — соединения через неё будут отклоняться"))
			} else {
				x.pl.line(msg("groups").t("Группа «" + g.Name + "» останется без серверов."))
			}
		}
	}
}

// reportDangling: references that resolve to nothing (fail closed).
func (x *planCtx) reportDangling() {
	next := &x.pl.next
	n := 0
	seen := map[danglingRef]bool{}
	// A 1.2.0 «Только правила» file carries no servers: one warning that
	// says what it means (1.2.0 sent such rules through the main server).
	legacy := x.p.Legacy == "rules"
	def, ruleWhere := false, map[string]bool{}
	for _, r := range x.dangling {
		if r.where == "" || seen[r] || next.Profiles.Find(r.id) != nil || next.Groups.Find(r.id) != nil {
			continue
		}
		seen[r] = true
		if legacy {
			if strings.HasPrefix(r.where, "«Всё остальное»") {
				def = true
			} else {
				ruleWhere[r.where] = true
			}
			continue
		}
		if n++; n > 20 {
			continue
		}
		name, what := "", "сервера"
		if t, ok := x.p.Targets[r.id]; ok {
			name = t.Name
			if t.Group {
				what = "группы"
			}
		} else if f, ok := x.full[r.id]; ok {
			name = f.Name
		} else if groups.IsGroupID(r.id) {
			what = "группы"
		}
		ref := what + " «" + name + "»"
		if name == "" {
			ref = what + " из копии" // the file does not name it
		}
		x.pl.warn(msg("").t(r.where + ": " + ref + " нет — соединения по нему будут отклоняться, пока вы не выберете сервер"))
	}
	if n > 20 {
		x.pl.warnf("", "И ещё %d ссылок на серверы, которых нет.", n-20)
	}
	if nr := len(ruleWhere); def || nr > 0 {
		who, verb := "«Всё остальное»", "будет"
		switch {
		case def && nr > 0:
			who, verb = "«Всё остальное» и "+nRules(nr), "будут"
		case nr > 0:
			who = nRules(nr)
			if nr%10 != 1 || nr%100 == 11 {
				verb = "будут"
			}
		}
		x.pl.warn(msg("").t("В копии HyRoute 1.2 «Только правила» нет серверов: " + who + " " + verb +
			" отклонять соединения, пока вы не выберете для них сервер на странице «Правила» (HyRoute 1.2 вёл их через основной сервер)."))
	}
}

// ---- settings (step 7) ----

// overlay replaces in dst (marshalled) every key except keepKeys by
// src's, then decodes it back strictly.
func overlay(dst any, keep []string, src map[string]json.RawMessage, skip []string, out any) error {
	m := jsonMap(dst)
	for k := range m {
		if !slices.Contains(keep, k) {
			delete(m, k)
		}
	}
	for k, v := range src {
		if !slices.Contains(skip, k) {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return strictDecode(b, out)
}

func (x *planCtx) planSettings() {
	pl, next := x.pl, &x.pl.next
	oldSt, oldPrefs := x.cur.Settings, x.cur.Prefs
	if x.chosen("settings") && x.d.settings != nil {
		if e := x.d.settings.Engine; e != nil {
			var st settings.Settings
			if err := overlay(next.Settings, ruleKeys, e, ruleKeys, &st); err != nil {
				pl.err = "Настройки не читаются этой версией HyRoute: " + err.Error()
				return
			}
			st.Config = next.Settings.Config
			next.Settings = st
		}
		if p := x.d.settings.Prefs; p != nil {
			var np store.Prefs
			keep := append(slices.Clone(geoKeys), prefsNever...)
			if err := overlay(next.Prefs, keep, p, keep, &np); err != nil {
				pl.err = "Настройки не читаются этой версией HyRoute: " + err.Error()
				return
			}
			next.Prefs = np
		}
	}
	if x.chosen("geo") && x.d.geo != nil {
		gp := *x.d.geo
		if gp.GeoSource == "custom" && (oldPrefs.GeoSiteURL != gp.GeoSiteURL || oldPrefs.GeoIPURL != gp.GeoIPURL) {
			// As the DNS server above: your own links are left out of a
			// copy without a password, and a base from someone else's
			// address may send sites past the tunnel.
			if !x.p.Secrets {
				gp.GeoSource, gp.GeoSiteURL, gp.GeoIPURL = oldPrefs.GeoSource, oldPrefs.GeoSiteURL, oldPrefs.GeoIPURL
				pl.warn(msg("geo").t("Свои ссылки на базы правил из копии без пароля не переносятся: источник баз остаётся ваш."))
			} else {
				pl.warn(msg("geo").t("Базы правил будут скачиваться по ссылкам из копии: ").s(strings.Join(nonEmpty(urlHost(gp.GeoSiteURL), urlHost(gp.GeoIPURL)), ", ")).
					t(". База решает, какие сайты идут через VPN: восстанавливайте так только свою копию."))
			}
		}
		g := jsonMap(&gp)
		var np store.Prefs
		all := jsonMap(next.Prefs)
		for _, k := range geoKeys {
			delete(all, k)
		}
		maps.Copy(all, g)
		b, _ := json.Marshal(all)
		if err := strictDecode(b, &np); err != nil {
			pl.err = "Базы правил не читаются этой версией HyRoute: " + err.Error()
			return
		}
		next.Prefs = np
		pl.line(msg("geo").t("Базы правил: " + geoDetail(np.GeoSource, np.GeoSource == "custom", np.GeoAutoUpdate(), np.GeoHours()) + "."))
	}
	if x.cur.Broken["prefs.json"] != nil {
		// cli: the access chosen in the unreadable file is unknown and
		// reads as off (CLIMode); a restore never widens it.
		next.Prefs.CLI = "off"
	}
	switch {
	case !oldSt.KillSwitchOn() && next.Settings.KillSwitchOn():
		pl.ksChange = 1
	case oldSt.KillSwitchOn() && !next.Settings.KillSwitchOn():
		pl.ksChange = -1
	}
	if !x.chosen("settings") {
		return
	}
	changes := settingChanges(oldSt, next.Settings, oldPrefs, next.Prefs)
	for _, c := range changes {
		pl.line(msg("settings").t(c.label + ": " + c.from + " → " + c.to + "."))
		if c.warn != "" {
			pl.warn(msg("settings").t(c.warn))
		}
	}
	if len(changes) == 0 {
		pl.line(msg("settings").t("Настройки не изменятся."))
	}
}

type settingChange struct{ key, label, from, to, warn string }

func yesNo(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

func onOff(b bool) string {
	if b {
		return "включён"
	}
	return "выключен"
}

// settingChanges is the key-by-key diff of the effective values.
func settingChanges(a, b settings.Settings, pa, pb store.Prefs) []settingChange {
	var out []settingChange
	add := func(key, from, to, warn string) {
		if from != to {
			label := settingLabels[key]
			if label == "" {
				label = key
			}
			out = append(out, settingChange{key, label, from, to, warn})
		}
	}
	weak := func(was, now bool, text string) string {
		if was && !now {
			return text
		}
		return ""
	}
	add("killSwitch", onOff(a.KillSwitchOn()), onOff(b.KillSwitchOn()), weak(a.KillSwitchOn(), b.KillSwitchOn(), "Kill switch выключится: если HyRoute упадёт, трафик пойдёт напрямую"))
	add("blockQUIC", yesNo(a.QUICBlocked()), yesNo(b.QUICBlocked()), weak(a.QUICBlocked(), b.QUICBlocked(), "Блокировать QUIC с неизвестным сайтом выключится: такие соединения пойдут по «Всё остальное»"))
	add("blockIPv6Tunnel", yesNo(a.IPv6TunnelBlocked()), yesNo(b.IPv6TunnelBlocked()), weak(a.IPv6TunnelBlocked(), b.IPv6TunnelBlocked(), "Не пускать IPv6 в VPN выключится: IPv6-соединения программ пойдут в VPN"))
	add("preferRemoteDNS", yesNo(a.RemoteDNS()), yesNo(b.RemoteDNS()), weak(a.RemoteDNS(), b.RemoteDNS(), "Узнавать адрес сайта на сервере выключится: адреса сайтов будет узнавать ваш провайдер"))
	add("exactWebDomains", yesNo(a.ExactWeb()), yesNo(b.ExactWeb()), "")
	add("sniffTimeoutMs", fmt.Sprint(a.SniffTimeout().Milliseconds()), fmt.Sprint(b.SniffTimeout().Milliseconds()), "")
	add("logsToDisk", yesNo(pa.ToDisk()), yesNo(pb.ToDisk()), "")
	add("logMaxMB", fmt.Sprint(pa.MaxBytes()>>20), fmt.Sprint(pb.MaxBytes()>>20), "")
	add("logKeep", fmt.Sprint(pa.Keep()), fmt.Sprint(pb.Keep()), "")
	check := func(s string) string {
		if s == "manual" {
			return "только вручную"
		}
		return "автоматически"
	}
	add("updateCheck", check(pa.UpdateCheck), check(pb.UpdateCheck), "")
	channel := func(s string) string {
		if s == "beta" {
			return "beta"
		}
		return "стабильный"
	}
	w := ""
	if pb.UpdateChannel == "beta" && pa.UpdateChannel != "beta" {
		w = "Канал обновлений: beta — HyRoute будет предлагать предварительные версии"
	}
	add("updateChannel", channel(pa.UpdateChannel), channel(pb.UpdateChannel), w)
	add("autoConnect", yesNo(pa.AutoConnect), yesNo(pb.AutoConnect), "")
	add("closeToTray", yesNo(pa.CloseToTrayOn()), yesNo(pb.CloseToTrayOn()), "")
	// The cli key never changes (prefsNever). Keys of later features
	// without a label: shown as they are.
	known := map[string]bool{}
	for k := range settingLabels {
		known[k] = true
	}
	for _, k := range append(append(slices.Clone(ruleKeys), geoKeys...), prefsNever...) {
		known[k] = true
	}
	for _, pair := range [][2]map[string]json.RawMessage{{jsonMap(a), jsonMap(b)}, {jsonMap(pa), jsonMap(pb)}} {
		all := maps.Clone(pair[0])
		maps.Copy(all, pair[1])
		for _, k := range slices.Sorted(maps.Keys(all)) {
			if known[k] {
				continue
			}
			from, to := string(pair[0][k]), string(pair[1][k])
			if from == "" {
				from = "—"
			}
			if to == "" {
				to = "—"
			}
			add(k, from, to, "")
		}
	}
	return out
}

func (x *planCtx) planAppearance() {
	if !x.chosen("appearance") || x.d.appearance == nil {
		return
	}
	a := *x.d.appearance
	if !slices.Contains(themes, a.Theme) {
		if a.Theme != "" {
			x.pl.warn(msg("appearance").t("Тема из копии не поддерживается этой версией HyRoute — оставлена ваша"))
		}
		a.Theme = ""
	}
	if !slices.Contains(accents, a.Accent) {
		if a.Accent != "" {
			x.pl.warn(msg("appearance").t("Цвет акцента из копии не поддерживается этой версией HyRoute — оставлен ваш"))
		}
		a.Accent = ""
	}
	x.pl.appearance = &a
	parts := []string{}
	if a.Theme != "" {
		parts = append(parts, "тема «"+themeNames[a.Theme]+"»")
	}
	if a.Accent != "" {
		parts = append(parts, "акцент «"+accentNames[a.Accent]+"»")
	}
	if len(parts) > 0 {
		x.pl.line(msg("appearance").t("Оформление: " + strings.Join(parts, ", ") + "."))
	}
}

// finalCheck is step 8: counts of the result and what the files must
// parse to.
func (x *planCtx) finalCheck() {
	pl, next := x.pl, &x.pl.next
	if len(next.Profiles.List) > importLimits.serversTotal {
		pl.err = fmt.Sprintf("Серверов станет больше %d: выберите «Заменить» или меньше разделов", importLimits.serversTotal)
		return
	}
	ids := map[string]bool{}
	for _, s := range next.Profiles.List {
		if ids[s.ID] {
			pl.err = "Внутренняя ошибка восстановления: два сервера с одним ID (" + s.ID + "). Ничего не изменено."
			return
		}
		ids[s.ID] = true
	}
	if len(next.Subs) > importLimits.subs {
		pl.err = fmt.Sprintf("Подписок станет больше %d: выберите «Заменить» или меньше разделов", importLimits.subs)
		return
	}
	if len(next.Settings.Rules) > importLimits.rules {
		pl.err = fmt.Sprintf("Правил станет больше %d: выберите «Заменить»", importLimits.rules)
		return
	}
	if len(next.Proxies) > importLimits.proxies {
		pl.err = fmt.Sprintf("Прокси станет больше %d: выберите «Заменить»", importLimits.proxies)
		return
	}
	if next.Settings.Rules == nil {
		next.Settings.Rules = []rules.Rule{}
	}
	if x.chosen("rules") || x.chosen("settings") {
		if _, _, _, err := store.ValidateSettings(&next.Settings); err != nil {
			sec := "Правила"
			if x.chosen("settings") && !x.chosen("rules") {
				sec = "Настройки"
			}
			pl.err = sec + " не читаются этой версией HyRoute: " + err.Error()
			return
		}
	}
	if rs := pl.rules.rulesets; rs != nil {
		if err := rs.Validate(); err != nil {
			pl.err = "Профили правил не читаются этой версией HyRoute: " + err.Error()
			return
		}
		for _, e := range rs.List {
			if e.ID == rs.Active {
				continue
			}
			if err := rules.Check(e.Config); err != nil {
				pl.err = fmt.Sprintf("Профиль правил «%s» не читается этой версией HyRoute: %v", e.Name, err)
				return
			}
		}
	}
	if x.chosen("settings") || x.chosen("geo") {
		if err := checkPrefs(next.Prefs); err != nil {
			pl.err = "Раздел повреждён: " + err.Error()
			return
		}
	}
	if x.chosen("groups") {
		if err := next.Groups.Validate(); err != nil {
			pl.err = "Группы серверов не сохранятся: " + err.Error()
			return
		}
	}
	if x.chosen("networks") {
		if err := netmode.Validate(next.Net); err != nil {
			pl.err = "Правила сетей не сохранятся: " + err.Error()
			return
		}
	}
	for _, def := range backupSections {
		if x.chosen(def.key) {
			pl.sections = append(pl.sections, def.key)
		}
	}
	pl.counts.servers = len(next.Profiles.List)
}

// decideWrites is step 9: the files that change, in write order.
func (x *planCtx) decideWrites() {
	pl, next, cur := x.pl, &x.pl.next, &x.cur
	differ := func(a, b any) bool {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		return string(ja) != string(jb)
	}
	subsJSON := func(l []store.Subscription) any {
		type withURL struct {
			store.Subscription
			URL string
		}
		out := []withURL{}
		for _, s := range l {
			out = append(out, withURL{s, s.URL})
		}
		return out
	}
	proxiesJSON := func(l []store.LocalProxy) any {
		out := []bkProxy{}
		for _, p := range l {
			out = append(out, bkProxy{p, p.Password})
		}
		return out
	}
	want := map[string]bool{
		"subscriptions.json": x.chosen("subscriptions") && differ(subsJSON(cur.Subs), subsJSON(next.Subs)),
		"profiles.json":      (x.chosen("servers") || x.chosen("subscriptions")) && !reflect.DeepEqual(cur.Profiles, next.Profiles),
		"groups.json":        x.chosen("groups") && differ(cur.Groups, next.Groups),
		"proxies.json":       x.chosen("proxies") && differ(proxiesJSON(cur.Proxies), proxiesJSON(next.Proxies)),
		"settings.json":      (x.chosen("rules") || x.chosen("settings")) && differ(cur.Settings, next.Settings),
		"rulesets.json":      pl.rules.rulesets != nil && differ(cur.Rulesets, pl.rules.rulesets),
		"prefs.json":         (x.chosen("settings") || x.chosen("geo")) && differ(cur.Prefs, next.Prefs),
		"networks.json":      x.chosen("networks") && differ(cur.Net, next.Net),
		"dns.json":           x.chosen("dns") && differ(cur.DNS, next.DNS),
	}
	for f := range want {
		if cur.Broken[f] != nil && slices.Contains(x.allWrites(), f) {
			want[f] = true // a covered broken file is always replaced
		}
	}
	if want["rulesets.json"] && !pl.rules.only {
		want["settings.json"] = true // a pair
	}
	for _, f := range restoreWrites {
		if want[f] {
			pl.writes = append(pl.writes, f)
			if cur.Broken[f] != nil {
				pl.keepBroken = append(pl.keepBroken, f)
			}
		}
	}
	if !want["rulesets.json"] {
		pl.rules.rulesets = nil
	}
	if cur.Broken["profiles.json"] != nil && x.replace("servers") && !x.chosen("subscriptions") {
		for _, s := range next.Subs {
			if s.Enabled && !slices.Contains(pl.refreshSubs, s.ID) {
				pl.refreshSubs = append(pl.refreshSubs, s.ID)
			}
		}
	}
}

func (x *planCtx) allWrites() []string {
	var out []string
	for key := range x.ch {
		out = append(out, x.sectionWrites(key)...)
	}
	return out
}

// ---- networks (netmodes), DNS, statistics ----

// resolveRuleset maps a rule profile named by the file's network rules into
// the result: through the restored profiles, by ID among the result's, else
// by a unique name of the file's profile. "" = none (name: the file's name
// for it, "" when unknown).
func (x *planCtx) resolveRuleset(id string) (string, string) {
	if t, ok := x.rsmap[id]; ok {
		return t, ""
	}
	rs := x.pl.next.Rulesets
	if rs != nil && netmode.ValidID(id) && rs.Find(id) != nil {
		return id, ""
	}
	name := ""
	if x.d.rulesets != nil {
		if e := x.d.rulesets.Find(id); e != nil {
			name = e.Name
		}
	}
	if name != "" && rs != nil {
		var found []string
		for _, e := range rs.List {
			if strings.EqualFold(strings.TrimSpace(e.Name), strings.TrimSpace(name)) {
				found = append(found, e.ID)
			}
		}
		if len(found) == 1 {
			x.pl.line(msg("networks").t("Профиль правил «" + name + "» найден среди ваших по имени."))
			return found[0], ""
		}
	}
	return "", name
}

// netRulesetName names a rule profile of the result.
func (x *planCtx) netRulesetName(id string) string {
	if rs := x.pl.next.Rulesets; rs != nil {
		if e := rs.Find(id); e != nil {
			return e.Name
		}
	}
	return "удалённый профиль правил"
}

// netConds describes a network rule's conditions: the first two, then «…».
// Wi-Fi and network names are sensitive (Privacy mode).
func netConds(b *msgB, m netmode.Match) {
	type cond struct {
		pre, v, post string
	}
	var cs []cond
	for _, k := range m.Networks {
		cs = append(cs, cond{"сеть «", k.Name, "»"})
	}
	for _, v := range m.SSIDs {
		cs = append(cs, cond{"Wi-Fi «", v, "»"})
	}
	for _, v := range m.Names {
		cs = append(cs, cond{"сеть «", v, "»"})
	}
	cats := map[string]string{netmode.Public: "общедоступная сеть", netmode.Private: "частная сеть", netmode.Domain: "доменная сеть"}
	for _, v := range m.Categories {
		cs = append(cs, cond{cats[v], "", ""})
	}
	ads := map[string]string{netmode.WiFi: "по Wi-Fi", netmode.Ethernet: "по кабелю", netmode.Mobile: "мобильная связь", netmode.Other: "другое подключение"}
	for _, v := range m.Adapters {
		cs = append(cs, cond{ads[v], "", ""})
	}
	for i, c := range cs {
		if i == 2 {
			b.t(", …")
			break
		}
		if i > 0 {
			b.t(", ")
		}
		b.t(c.pre)
		if c.v != "" {
			b.s(c.v)
		}
		b.t(c.post)
	}
}

// netActionText is a network rule's action in the words of the «Сети» page.
func (x *planCtx) netActionText(a netmode.Action) string {
	rs := ""
	if a.Ruleset != "" {
		rs = "профиль правил «" + x.netRulesetName(a.Ruleset) + "»"
	}
	switch {
	case a.Connect == netmode.Disconnect:
		return "отключиться (всё напрямую)"
	case a.Connect == netmode.Connect && rs != "":
		return "подключиться, " + rs
	case a.Connect == netmode.Connect:
		return "подключиться"
	case rs != "":
		return rs
	}
	return "ничего"
}

// planNetworks is the «Сети» section (netmodes): rule profile references
// through rsmap, rule IDs (B2), one line per restored rule, and a warning
// for each rule that would disconnect and lift the kill switch's block.
func (x *planCtx) planNetworks() {
	pl, next := x.pl, &x.pl.next
	if !x.chosen("networks") || x.d.net == nil {
		x.danglingNetRulesets()
		return
	}
	f := x.d.net.Clone()
	remap := func(where *msgB, a *netmode.Action) {
		if a.Ruleset == "" {
			return
		}
		id, name := x.resolveRuleset(a.Ruleset)
		if id == "" {
			if name == "" {
				name = "удалённый профиль правил"
			}
			pl.warn(where.t(": профиля правил «" + name + "» нет — профиль правил не переключается"))
		}
		a.Ruleset = id
	}
	for i := range f.Rules {
		r := &f.Rules[i] // names checked by parseImportNetworks
		remap(msg("networks").t("Сеть «").s(r.Name).t("»"), &r.Action)
	}
	remap(msg("networks").t(netmode.UnknownName), &f.Unknown)
	cur := x.cur.Net
	var res netmode.Config
	taken := map[string]bool{}
	if x.replace("networks") {
		res = f
	} else {
		res = cur.Clone()
		for _, r := range res.Rules {
			taken[r.ID] = true
		}
		res.Rules = append(res.Rules, f.Rules...)
		if len(res.Rules) > netmode.MaxRules {
			pl.err = fmt.Sprintf("Правил сетей станет больше %d: выберите «Заменить»", netmode.MaxRules)
			return
		}
	}
	first := len(res.Rules) - len(f.Rules) // the file's rules in res
	for i := first; i < len(res.Rules); i++ {
		r := &res.Rules[i]
		if !netmode.ValidID(r.ID) || taken[r.ID] {
			r.ID = x.env.newID()
			for taken[r.ID] {
				r.ID = x.env.newID()
			}
		}
		taken[r.ID] = true
	}
	res.Version = netmode.Version
	netmode.Normalize(&res)
	next.Net = res

	restored := res.Rules[first:]
	if x.replace("networks") {
		pl.linef("networks", "Правила сетей: будет %d.", len(res.Rules))
	} else {
		pl.linef("networks", "Правила сетей: добавится %d.", len(restored))
	}
	for i, r := range restored {
		if i == 20 {
			pl.linef("networks", "И ещё %s.", nNetRules(len(restored)-20))
			break
		}
		b := msg("networks").t("Сеть «").s(r.Name).t("» (")
		netConds(b, r.Match)
		b.t("): " + x.netActionText(r.Action))
		if !r.On() {
			b.t(" (правило выключено)")
		}
		pl.line(b.t("."))
	}
	if cur.Enabled != res.Enabled {
		pl.linef("networks", "Правила сетей: %s → %s.", onOffPl(cur.Enabled), onOffPl(res.Enabled))
	}
	if x.replace("networks") {
		pl.linef("networks", "%s: %s.", netmode.UnknownName, x.netActionText(res.Unknown))
	}
	if !res.Enabled {
		return
	}
	turnsOn := !cur.Enabled
	for _, r := range restored {
		if !r.On() || r.Connect != netmode.Disconnect {
			continue
		}
		same := !turnsOn && slices.ContainsFunc(cur.Rules, func(c netmode.Rule) bool {
			return c.ID == r.ID && c.On() && reflect.DeepEqual(c.Match, r.Match) && c.Action == r.Action
		})
		if same {
			continue
		}
		b := msg("networks").t("Сеть «").s(r.Name).t("» (")
		netConds(b, r.Match)
		pl.warn(b.t("): при подключении к ней HyRoute отключится и kill switch снимет блокировку — трафик пойдёт напрямую"))
	}
	if res.Unknown.Connect == netmode.Disconnect && (turnsOn || cur.Unknown.Connect != netmode.Disconnect) {
		pl.warn(msg("networks").t("В неизвестной сети HyRoute отключится и kill switch снимет блокировку — трафик пойдёт напрямую"))
	}
}

func onOffPl(b bool) string {
	if b {
		return "включены"
	}
	return "выключены"
}

// danglingNetRulesets: the network rules that stay (their section is not
// restored) and switch to a rule profile the restored rules drop.
func (x *planCtx) danglingNetRulesets() {
	if !x.chosen("rules") || x.cur.Broken["networks.json"] != nil {
		return
	}
	rs := x.pl.next.Rulesets
	gone := func(id string) bool { return id != "" && (rs == nil || rs.Find(id) == nil) }
	name := func(id string) string {
		if x.cur.Rulesets != nil {
			if e := x.cur.Rulesets.Find(id); e != nil {
				return e.Name
			}
		}
		return "удалённый профиль правил"
	}
	for _, r := range x.cur.Net.Rules {
		if gone(r.Ruleset) {
			x.pl.warn(msg("networks").t("Сеть «").s(r.Name).t("»: профиля правил «" + name(r.Ruleset) + "» не будет — профиль правил не переключится"))
		}
	}
	if gone(x.cur.Net.Unknown.Ruleset) {
		x.pl.warn(msg("networks").t(netmode.UnknownName + ": профиля правил «" + name(x.cur.Net.Unknown.Ruleset) + "» не будет — профиль правил не переключится"))
	}
}

// planDNS is the «DNS» section (replace only): each changed option as
// «было → станет»; turning a protection off is also a warning.
func (x *planCtx) planDNS() {
	if !x.chosen("dns") || x.d.dns == nil {
		return
	}
	pl := x.pl
	a, b := x.cur.DNS, *x.d.dns
	// A server of your own is an address the export of a copy without a
	// password leaves out: such a copy carrying one was made elsewhere, and
	// it would send the names to whoever wrote it. Yours stays. With a
	// password the address is shown and warned about.
	for _, u := range []struct {
		cur, in *dnspolicy.Upstream
		what    string
	}{{&a.Tunnel, &b.Tunnel, "DNS-сервер для VPN"}, {&a.Direct, &b.Direct, "Сервер для прямых DNS-запросов"}} {
		if u.in.Preset != dnspolicy.Custom || u.cur.Preset == dnspolicy.Custom && u.cur.URL == u.in.URL {
			continue
		}
		if !x.p.Secrets {
			*u.in = *u.cur
			pl.warn(msg("dns").t(u.what + " из копии без пароля не переносится (такая копия своего сервера не хранит): остаётся ваш."))
			continue
		}
		pl.warn(msg("dns").t(u.what + " станет сервером из копии: ").s(urlHost(u.in.URL)).
			t(". Он будет видеть имена сайтов и сможет подменять ответы: восстанавливайте так только свою копию."))
	}
	pl.next.DNS = b
	// Both: until the install, the current servers may still be logged.
	pl.redact["dns"] = append(dnsSecrets(a), dnsSecrets(b)...)
	n := 0
	add := func(label, from, to, warn string) {
		if from == to {
			return
		}
		n++
		pl.line(msg("dns").t(label + ": " + from + " → " + to + "."))
		if warn != "" {
			pl.warn(msg("dns").t(warn))
		}
	}
	upstream := func(u dnspolicy.Upstream, tunnel bool) string {
		if !tunnel && u.Preset == "" {
			return "нет"
		}
		return u.UpstreamName(tunnel)
	}
	sameCustom := func(p, q dnspolicy.Upstream) bool { return p.Preset != dnspolicy.Custom || p.URL == q.URL }
	weak := func(was, now bool, text string) string {
		if was && !now {
			return text
		}
		return ""
	}
	add("DNS по правилам", yesNo(a.ByRules), yesNo(b.ByRules),
		weak(a.ByRules, b.ByRules, "DNS по правилам выключится: имена сайтов, которые правила ведут через VPN, снова будет видеть и сможет подменить провайдер"))
	from, to := upstream(a.Tunnel, true), upstream(b.Tunnel, true)
	if from == to && !sameCustom(b.Tunnel, a.Tunnel) {
		to += " (другой адрес)"
	}
	add("DNS-сервер для VPN", from, to, "")
	add("Сверяться с правилами по IP и geoip", yesNo(!a.IgnoreAddrRules), yesNo(!b.IgnoreAddrRules), "")
	from, to = upstream(a.Direct, false), upstream(b.Direct, false)
	if from == to && !sameCustom(b.Direct, a.Direct) {
		to += " (другой адрес)"
	}
	add("Шифровать прямые DNS-запросы", from, to, "")
	add("Не давать браузерам обходить DNS", yesNo(a.BlockBrowserDoH), yesNo(b.BlockBrowserDoH),
		weak(a.BlockBrowserDoH, b.BlockBrowserDoH, "Не давать браузерам обходить DNS выключится: браузеры со своим DoH будут открывать сайты мимо правил для сайтов"))
	add("Отключать ECH", yesNo(a.StripECH), yesNo(b.StripECH), "")
	if n == 0 {
		pl.line(msg("dns").t("Настройки DNS не изменятся."))
	}
}

// planStats is the «Статистика» section: checked by the stats store before
// the plan (env), replaced after the restore.
func (x *planCtx) planStats() {
	if !x.chosen("stats") || x.d.stats == nil {
		return
	}
	if x.env.statsErr != nil {
		x.pl.err = "«Статистика»: " + x.env.statsErr.Error()
		return
	}
	t := "Статистика: ваша будет заменена статистикой из копии"
	if x.env.statsDetail != "" {
		t += " (" + x.env.statsDetail + ")"
	}
	x.pl.line(msg("stats").t(t + "."))
}

// urlHost is the host of a link for a plan line ("" for none): its path
// may hold a key.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
