package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// Pure planRestore tests over hand-made states.

func srv(id, name, host string) hysteria.Profile {
	return hysteria.Profile{ID: id, Name: name, Host: host, Ports: "443", Auth: "pass-" + id}
}

func baseState(list ...hysteria.Profile) cfgState {
	st := cfgState{Profiles: store.Profiles{List: list}, Groups: &groups.File{Version: 1, Groups: []groups.Group{}}, Broken: map[string]error{}}
	if len(list) > 0 {
		st.Profiles.Active = list[0].ID
	}
	st.Settings = *store.DefaultSettings()
	return st
}

type pbuild struct {
	p *backup.Payload
}

func payload(secrets bool) *pbuild {
	return &pbuild{&backup.Payload{App: "1.3.0", Secrets: secrets, Sections: map[string]json.RawMessage{}, Targets: map[string]backup.Target{}}}
}

func (b *pbuild) put(key string, v any) *pbuild {
	raw, _ := json.Marshal(v)
	b.p.Sections[key] = raw
	return b
}

func testEnv() planEnv {
	n := 0
	return planEnv{
		newID: func() string { n++; return fmt.Sprintf("e%011x", n) },
		driveType: func(root string) uint32 {
			return map[bool]uint32{true: driveFixed, false: 4}[strings.EqualFold(root, `C:\`) || strings.EqualFold(root, `D:\`)]
		},
	}
}

func plan(cur cfgState, p *backup.Payload, ch map[string]string) *restorePlan {
	return planRestore(cur, p, BackupChoice{Sections: ch}, testEnv())
}

func texts(pl *restorePlan) string {
	var b strings.Builder
	for _, m := range pl.lines {
		b.WriteString("L " + m.Text + "\n")
	}
	for _, m := range pl.warnings {
		b.WriteString("W " + m.Text + "\n")
	}
	return b.String()
}

// TestPlanGroupsProbe: «Группы серверов: Заменить» shows a changed
// latency probe; a URL other than the default is also a warning.
func TestPlanGroupsProbe(t *testing.T) {
	cur := baseState(srv("aaaaaaaa0001", "NL", "nl.example"))
	f := groups.File{Version: 1, Groups: []groups.Group{}}
	pl := plan(cur, payload(false).put("groups", f).p, map[string]string{"groups": "replace"})
	if strings.Contains(texts(pl), "Проверка задержки") {
		t.Fatal(texts(pl))
	}
	f.Probe = &groups.Probe{URL: "https://track.example/p", IntervalSec: 120}
	pl = plan(cur, payload(false).put("groups", f).p, map[string]string{"groups": "replace"})
	want := "L Проверка задержки: " + groups.DefaultProbeURL + ", каждые 60 с → https://track.example/p, каждые 120 с.\n"
	if pl.err != "" || !strings.Contains(texts(pl), want) || !strings.Contains(texts(pl), "W Группы будут проверять задержку") {
		t.Fatalf("%s\nwant %s", texts(pl), want)
	}
	for _, m := range pl.lines {
		if strings.HasPrefix(m.Text, "Проверка задержки") && !slices.ContainsFunc(m.Parts, func(p BackupPart) bool { return p.S && p.T == "https://track.example/p" }) {
			t.Fatalf("URL not sensitive: %+v", m.Parts)
		}
	}
	// Back to the default: a line, no warning.
	cur.Groups.Probe = f.Probe
	pl = plan(cur, payload(false).put("groups", groups.File{Version: 1, Groups: []groups.Group{}}).p, map[string]string{"groups": "replace"})
	if !strings.Contains(texts(pl), "L Проверка задержки: https://track.example/p") || strings.Contains(texts(pl), "W Группы будут") {
		t.Fatal(texts(pl))
	}
	// «Добавить к текущим» keeps the current probe.
	pl = plan(baseState(), payload(false).put("groups", f).p, map[string]string{"groups": "add"})
	if strings.Contains(texts(pl), "Проверка задержки") || pl.next.Groups.Probe != nil {
		t.Fatal(texts(pl))
	}
}

// TestPlanLegacyRulesOnlyTargets: a 1.2.0 «Только правила» file names no
// servers: its targets are «сервер из копии», not deleted ones, and one
// warning says what the dangling references mean.
func TestPlanLegacyRulesOnlyTargets(t *testing.T) {
	cur := baseState(srv("aaaaaaaa0001", "NL", "nl.example"))
	cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: "ffffffff0009", Rules: []rules.Rule{
		{Name: "a", Domains: []string{"a.example"}, Action: rules.Tunnel, Profile: "ffffffff0009"},
		{Name: "b", Domains: []string{"b.example"}, Action: rules.Tunnel, Profile: "ffffffff0008"},
		{Name: "c", Domains: []string{"c.example"}, Action: rules.Direct},
	}}
	b := payload(false).put("rules", bkRules{Config: cfg})
	b.p.Legacy = "rules"
	tx := texts(plan(cur, b.p, map[string]string{"rules": "replace"}))
	for _, want := range []string{"«Всё остальное» — через VPN («сервер из копии»).",
		"В копии HyRoute 1.2 «Только правила» нет серверов: «Всё остальное» и 2 правила будут отклонять соединения"} {
		if !strings.Contains(tx, want) {
			t.Fatalf("%s\nwant %s", tx, want)
		}
	}
	if strings.Contains(tx, "удалён") || strings.Contains(tx, "Правило «a»") {
		t.Fatal(tx)
	}
	// Ours: a target the file does not name is «из копии» too.
	b.p.Legacy = ""
	tx = texts(plan(cur, b.p, map[string]string{"rules": "replace"}))
	if !strings.Contains(tx, "Правило «b»: сервера из копии нет") || strings.Contains(tx, "удалён") {
		t.Fatal(tx)
	}
}

// A backup made by HyRoute up to v1.3.0-beta.3 may hold a server's ports
// in the old spelling (merge_test.go: oldPortLinks): it is still the
// server the subscription now gives with the new one.
func TestPlanOldPortSpecs(t *testing.T) {
	for _, c := range oldPortLinks {
		p, _, err := hysteria.ParseURI(c.link)
		if err != nil {
			t.Fatal(err)
		}
		p.ID = "aaaaaaaa0001"
		s := p
		s.ID, s.Name, s.Ports, s.Auth = "0000000000ff", "copy", c.saved, ""
		for _, mode := range []string{"replace", "add"} {
			pl := plan(baseState(p), payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": mode})
			if pl.err != "" {
				t.Fatal(pl.err)
			}
			if l := pl.next.Profiles.List; len(l) != 1 || l[0].ID != p.ID || l[0].Auth != p.Auth {
				t.Errorf("%s, %s: %+v", c.saved, mode, l)
			}
		}
	}
}

func TestPlanSecretsNeedSameConnection(t *testing.T) {
	cur := baseState(srv("aaaaaaaa0001", "NL", "nl.example"))
	for _, mode := range []string{"replace", "add"} {
		// The same ID, another host: no password moves.
		evil := srv("aaaaaaaa0001", "NL", "evil.example")
		evil.Auth = ""
		pl := plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{evil}}).p, map[string]string{"servers": mode})
		if pl.err != "" {
			t.Fatal(pl.err)
		}
		for _, p := range pl.next.Profiles.List {
			if p.Host == "evil.example" && p.Auth != "" {
				t.Fatalf("%s: secret moved to another host", mode)
			}
		}
		for _, change := range []func(p *hysteria.Profile){
			func(p *hysteria.Profile) { p.TLS.SNI = "x" },
			func(p *hysteria.Profile) { p.TLS.PinSHA256 = strings.Repeat("a", 64) },
			func(p *hysteria.Profile) { p.TLS.Insecure = true },
			func(p *hysteria.Profile) { p.Obfs.Type = "salamander" },
			func(p *hysteria.Profile) { p.Ports = "8443" },
		} {
			s := srv("aaaaaaaa0001", "NL", "nl.example")
			s.Auth = ""
			change(&s)
			pl := plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": mode})
			for _, p := range pl.next.Profiles.List {
				if p.Auth == "pass-aaaaaaaa0001" && !hysteria.SameConnectionNoSecrets(p, cur.Profiles.List[0]) {
					t.Fatalf("%s: secret moved to a different server %+v", mode, p)
				}
			}
		}
	}
	// Equal in every field: secrets copied, current ID kept.
	s := srv("0000000000ff", "NL copy", "nl.example")
	s.Auth = ""
	pl := plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": "replace"})
	if len(pl.next.Profiles.List) != 1 || pl.next.Profiles.List[0].ID != "aaaaaaaa0001" || pl.next.Profiles.List[0].Auth != "pass-aaaaaaaa0001" {
		t.Fatalf("%+v", pl.next.Profiles.List)
	}
	// Two equal current servers (two accounts): none copied.
	two := baseState(srv("aaaaaaaa0001", "A", "nl.example"), srv("aaaaaaaa0002", "B", "nl.example"))
	pl = plan(two, payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": "replace"})
	if !strings.Contains(texts(pl), "несколько ваших серверов") {
		t.Fatal(texts(pl))
	}
	for _, p := range pl.next.Profiles.List {
		if p.Name == "NL copy" && p.Auth != "" {
			t.Fatal("ambiguous: copied")
		}
	}
	s.ID = "aaaaaaaa0002"
	pl = plan(two, payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": "replace"})
	if p := pl.next.Profiles.Find("aaaaaaaa0002"); p == nil || p.Auth != "pass-aaaaaaaa0002" {
		t.Fatalf("%+v", pl.next.Profiles.List)
	}
}

func TestPlanAddSecretFreeNoDuplicates(t *testing.T) {
	a, b := srv("aaaaaaaa0001", "A", "a.example"), srv("aaaaaaaa0002", "B", "b.example")
	cur := baseState(a, b)
	fa, fb := a, b
	fa.Auth, fb.Auth = "", ""
	fa.ID, fb.ID = "bbbbbbbb0001", "bbbbbbbb0002"
	rule := rules.Rule{Name: "r", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: fb.ID}
	p := payload(false).put("servers", bkServers{List: []hysteria.Profile{fa, fb}}).put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rule}}}).p
	pl := plan(cur, p, map[string]string{"servers": "add", "rules": "replace"})
	if pl.err != "" || len(pl.next.Profiles.List) != 2 || !strings.Contains(texts(pl), "уже есть 2") {
		t.Fatalf("%s %s %+v", pl.err, texts(pl), pl.next.Profiles.List)
	}
	if pl.next.Profiles.List[1].Auth != "pass-aaaaaaaa0002" || pl.next.Settings.Rules[0].Profile != "aaaaaaaa0002" {
		t.Fatalf("%+v", pl.next.Settings.Rules)
	}
}

func TestPlanTargetsResolveSubServers(t *testing.T) {
	s1 := srv("aaaaaaaa0001", "NL-1", "nl.example")
	s1.Source = "sub:cccccccc0001"
	s2 := srv("aaaaaaaa0002", "DE", "de.example")
	s2.Source = "sub:cccccccc0001"
	s3 := srv("aaaaaaaa0003", "Other", "fi.example")
	cur := baseState(s1, s2, s3)
	cur.Subs = []store.Subscription{{ID: "cccccccc0001", Name: "Provider"}}
	rule := func(name, target string) rules.Rule {
		return rules.Rule{Name: name, Apps: []rules.AppMatch{{Pattern: name + ".exe"}}, Action: rules.Tunnel, Profile: target}
	}
	b := payload(false).put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		rule("both", "111111111111"), rule("name", "222222222222"), rule("addr", "333333333333"), rule("none", "444444444444"),
	}}})
	b.p.Targets = map[string]backup.Target{
		"111111111111": {Name: "NL-1", Host: "nl.example", Ports: "443", Sub: "Provider"},
		"222222222222": {Name: "DE", Host: "changed.example", Ports: "443", Sub: "Provider"},
		"333333333333": {Name: "Renamed", Host: "fi.example", Ports: "443"},
		"444444444444": {Name: "Gone", Host: "gone.example", Ports: "443"},
	}
	pl := plan(cur, b.p, map[string]string{"rules": "replace"})
	got := []string{}
	for _, r := range pl.next.Settings.Rules {
		got = append(got, r.Profile)
	}
	if !slices.Equal(got, []string{"aaaaaaaa0001", "aaaaaaaa0002", "aaaaaaaa0003", "444444444444"}) {
		t.Fatalf("%v\n%s", got, texts(pl))
	}
	tx := texts(pl)
	for _, want := range []string{"по имени и адресу", "найден среди ваших по имени.", "по адресу (имя другое: «Other»)", "Правило «none»: сервера «Gone» нет"} {
		if !strings.Contains(tx, want) {
			t.Fatalf("%q not in\n%s", want, tx)
		}
	}
	// Ambiguous by name: dangling.
	dup := baseState(srv("aaaaaaaa0001", "DE", "x.example"), srv("aaaaaaaa0002", "DE", "y.example"))
	pl = plan(dup, b.p, map[string]string{"rules": "replace"})
	if pl.next.Settings.Rules[1].Profile != "222222222222" {
		t.Fatal(pl.next.Settings.Rules[1].Profile)
	}
}

func echB64() string {
	list := []byte{0, 8, 0xfe, 0x0d, 0, 4, 1, 2, 3, 4}
	return base64.StdEncoding.EncodeToString(list)
}

func TestPlanImportedPaths(t *testing.T) {
	cur := baseState()
	cases := []struct {
		ca, ech        string
		keepCA, keepEC bool
		want           string
	}{
		{ca: `C:\ca.pem`, keepCA: true, want: "будет проверять сертификат по файлу"},
		{ca: `\\host\share\x.pem`, want: "путь к сертификату не перенесён"},
		{ca: `\\?\C:\x`, want: "путь к сертификату не перенесён"},
		{ca: `C:\x.pem:ads`, want: "путь к сертификату не перенесён"},
		{ca: `C:\a\..\b.pem`, want: "путь к сертификату не перенесён"},
		{ca: `ca.pem`, want: "путь к сертификату не перенесён"},
		{ca: `Z:\ca.pem`, want: "путь к сертификату не перенесён"}, // a network drive
		{ech: echB64(), keepEC: true},
		{ech: "  " + strings.TrimRight(base64.URLEncoding.EncodeToString([]byte{0, 8, 0xfe, 0x0d, 0, 4, 1, 2, 3, 4}), "=") + " ", keepEC: true},
		{ech: `\\attacker\share\x`, want: "настройка ECH не перенесена"},
		{ech: `\\?\UNC\h\s\x`, want: "настройка ECH не перенесена"},
		{ech: `ech.pem`, want: "настройка ECH не перенесена"},
		{ech: `C:\ech.pem`, keepEC: true, want: "будет читать настройку ECH из файла"},
	}
	for _, sec := range []string{"servers", "subscriptions"} {
		for i, tc := range cases {
			s := srv("aaaaaaaa0001", "X", "x.example")
			s.TLS.CA, s.TLS.ECH = tc.ca, tc.ech
			b := payload(true)
			ch := map[string]string{sec: "replace"}
			if sec == "servers" {
				b.put("servers", bkServers{List: []hysteria.Profile{s}})
			} else {
				b.put("subscriptions", []bkSub{{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Interval: "manual", Servers: []hysteria.Profile{s}}})
			}
			pl := plan(cur, b.p, ch)
			if pl.err != "" || len(pl.next.Profiles.List) != 1 {
				t.Fatalf("%s %d: %s", sec, i, pl.err)
			}
			got := pl.next.Profiles.List[0]
			if (got.TLS.CA != "") != tc.keepCA || (got.TLS.ECH != "") != tc.keepEC {
				t.Fatalf("%s %d: %+v", sec, i, got.TLS)
			}
			if tx := texts(pl); tc.want != "" && !strings.Contains(tx, tc.want) || tc.want == "" && strings.Contains(tx, "ECH") {
				t.Fatalf("%s %d: %s", sec, i, tx)
			}
			// A path is a sensitive part.
			for _, w := range pl.warnings {
				if strings.Contains(w.Text, "по файлу") || strings.Contains(w.Text, "из файла") {
					if !slices.ContainsFunc(w.Parts, func(p BackupPart) bool { return p.S && strings.Contains(p.T, `:\`) }) {
						t.Fatalf("%+v", w)
					}
				}
			}
		}
	}
	// A dropped ECH makes a secret-free server differ: no password moves.
	c := srv("aaaaaaaa0001", "X", "x.example")
	c.TLS.ECH = `C:\keep.pem`
	cur = baseState(c)
	s := c
	s.Auth, s.TLS.ECH = "", `\\attacker\share\x`
	pl := plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": "replace"})
	for _, p := range pl.next.Profiles.List {
		if p.TLS.ECH == "" && p.Auth != "" {
			t.Fatal("secret inherited by a server whose ECH was dropped")
		}
	}
}

func TestPlanKeepsLastMembersOfUsedGroup(t *testing.T) {
	a, b, c := srv("aaaaaaaa0001", "A", "a.example"), srv("aaaaaaaa0002", "B", "b.example"), srv("aaaaaaaa0003", "C", "c.example")
	a.Source, b.Source = "sub:cccccccc0001", "sub:cccccccc0001"
	cur := baseState(a, b, c)
	cur.Subs = []store.Subscription{{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Interval: "manual"}}
	cur.Groups.Groups = []groups.Group{{ID: "grp-000000000001", Name: "Авто", Strategy: groups.Failover, Members: []string{a.ID, b.ID}}}
	// Named by a rule of an inactive rule profile.
	inactive := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{Name: "g", Apps: []rules.AppMatch{{Pattern: "g.exe"}}, Action: rules.Tunnel, Profile: "grp-000000000001"}}}
	cur.Rulesets = &store.Rulesets{Version: 1, Active: "dddddddd0001", List: []store.Ruleset{{ID: "dddddddd0001", Name: "Main", Config: cur.Settings.Config}, {ID: "dddddddd0002", Name: "Games", Config: inactive}}}
	other := bkSub{ID: "cccccccc0002", Name: "Q", URL: "https://q.example/s", Interval: "manual", Servers: []hysteria.Profile{srv("eeeeeeee0001", "Q1", "q.example")}}
	pl := plan(cur, payload(true).put("subscriptions", []bkSub{other}).p, map[string]string{"subscriptions": "replace"})
	tx := texts(pl)
	if strings.Count(tx, "иначе группа «Авто»") != 2 || strings.Contains(tx, "Группа «Авто» останется без серверов") {
		t.Fatal(tx)
	}
	for _, id := range []string{a.ID, b.ID} {
		if p := pl.next.Profiles.Find(id); p == nil || p.Source != "" {
			t.Fatalf("%s: %+v", id, p)
		}
	}
	// The subscription still there (same ID and URL) without A and B:
	// they stay «нет в подписке» under it.
	same := bkSub{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Interval: "manual", Servers: []hysteria.Profile{srv("eeeeeeee0002", "N", "n.example")}}
	pl = plan(cur, payload(true).put("subscriptions", []bkSub{same}).p, map[string]string{"subscriptions": "replace"})
	if p := pl.next.Profiles.Find(a.ID); p == nil || p.Source != a.Source || !p.Missing {
		t.Fatalf("%+v", p)
	}
	// A group keeping another existing member shrinks, no line.
	cur.Groups.Groups[0].Members = []string{a.ID, c.ID}
	pl = plan(cur, payload(true).put("subscriptions", []bkSub{other}).p, map[string]string{"subscriptions": "replace"})
	if pl.next.Profiles.Find(a.ID) != nil || strings.Contains(texts(pl), "иначе группа") {
		t.Fatal(texts(pl))
	}
	// An unused group: removed, a line only.
	cur.Groups.Groups[0].Members = []string{a.ID}
	cur.Rulesets = nil
	pl = plan(cur, payload(true).put("subscriptions", []bkSub{other}).p, map[string]string{"subscriptions": "replace"})
	if pl.next.Profiles.Find(a.ID) != nil || !strings.Contains(texts(pl), "L Группа «Авто» останется без серверов") {
		t.Fatal(texts(pl))
	}
	// A used group from the file whose members exist nowhere: a warning.
	cur2 := baseState(c)
	cur2.Settings.Rules = []rules.Rule{{Name: "g", Apps: []rules.AppMatch{{Pattern: "g.exe"}}, Action: rules.Tunnel, Profile: "grp-000000000009"}}
	f := groups.File{Version: 1, Groups: []groups.Group{{ID: "grp-000000000009", Name: "Пустая", Strategy: groups.Failover, Members: []string{"999999999999"}}}}
	pl = plan(cur2, payload(false).put("groups", f).p, map[string]string{"groups": "replace"})
	if !strings.Contains(texts(pl), "W Группа «Пустая» останется без серверов — соединения через неё будут отклоняться") {
		t.Fatal(texts(pl))
	}
	// groups.json broken + «Серверы: Заменить» without «Группы»: refused.
	cur3 := baseState(c)
	cur3.Broken["groups.json"] = fmt.Errorf("x")
	pl = plan(cur3, payload(false).put("servers", bkServers{List: []hysteria.Profile{}}).p, map[string]string{"servers": "replace"})
	if !strings.Contains(pl.err, "groups.json не загружен") {
		t.Fatal(pl.err)
	}
}

func TestPlanNamesShortened(t *testing.T) {
	long := strings.Repeat("ж", 300)
	s := srv("aaaaaaaa0001", long, "a.example")
	b := payload(true).put("subscriptions", []bkSub{{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Interval: "manual", Servers: []hysteria.Profile{s}}}).
		put("proxies", []bkProxy{{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0001", Name: strings.Repeat("п", 250), Port: 20000}}})
	pl := plan(baseState(), b.p, map[string]string{"subscriptions": "replace", "proxies": "replace"})
	if pl.err != "" || !strings.Contains(texts(pl), "Имена длиннее 200 символов сокращены: 2") {
		t.Fatal(pl.err, texts(pl))
	}
	if n := len([]rune(pl.next.Profiles.List[0].Name)); n != 200 {
		t.Fatal(n)
	}
}

func TestPlanBadItemSkipped(t *testing.T) {
	good, bad := srv("aaaaaaaa0001", "Good", "a.example"), srv("aaaaaaaa0002", "Bad", "b.example")
	bad.Ports = "0"
	rule := rules.Rule{Name: "r", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: bad.ID}
	b := payload(true).put("servers", bkServers{List: []hysteria.Profile{good, bad}}).
		put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rule}}}).
		put("subscriptions", []bkSub{{ID: "cccccccc0001", Name: "FTP", URL: "ftp://x/y", Interval: "manual", Servers: []hysteria.Profile{srv("aaaaaaaa0003", "S", "s.example")}}})
	pl := plan(baseState(), b.p, map[string]string{"servers": "replace", "rules": "replace", "subscriptions": "replace"})
	tx := texts(pl)
	if pl.err != "" || len(pl.next.Profiles.List) != 1 || !strings.Contains(tx, "Сервер «Bad» не восстановлен") || !strings.Contains(tx, "Подписка «FTP» не восстановлена") {
		t.Fatal(pl.err, tx)
	}
	if pl.next.Settings.Rules[0].Profile != bad.ID || !strings.Contains(tx, "Правило «r»: сервера «Bad» нет") {
		t.Fatal(tx)
	}
}

func TestPlanDigest(t *testing.T) {
	cur := baseState(srv("aaaaaaaa0001", "NL-1", "nl.example"))
	s := srv("bbbbbbbb0001", "New", "new.example")
	rule := rules.Rule{Name: "r", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: "111111111111"}
	b := payload(true).put("servers", bkServers{List: []hysteria.Profile{s}}).put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rule}}}).
		put("settings", bkSettings{Engine: map[string]json.RawMessage{"killSwitch": json.RawMessage("true")}})
	b.p.Targets = map[string]backup.Target{"111111111111": {Name: "NL-1", Host: "other.example", Ports: "443"}}
	ch := BackupChoice{Sections: map[string]string{"servers": "add", "rules": "replace", "settings": "replace"}}
	display := planRestore(cur, b.p, ch, testEnv())
	real := planRestore(cur, b.p, ch, planEnv{newID: newID, driveType: testEnv().driveType})
	if planDigest(display) != planDigest(real) {
		t.Fatal("display and apply plans differ")
	}
	// A rename that changes the name match changes the digest.
	renamed := cur
	renamed.Profiles.List = []hysteria.Profile{srv("aaaaaaaa0001", "NL-2", "nl.example")}
	if planDigest(planRestore(renamed, b.p, ch, testEnv())) == planDigest(display) {
		t.Fatal("rename not seen")
	}
	on := true
	ks := cur
	ks.Settings.KillSwitch = &on
	if planDigest(planRestore(ks, b.p, ch, testEnv())) == planDigest(display) {
		t.Fatal("kill switch not seen")
	}
	// A change nothing shows keeps it.
	other := cur
	other.Prefs.SkipVersion = "9.9.9"
	if planDigest(planRestore(other, b.p, ch, testEnv())) != planDigest(display) {
		t.Fatal("invisible change")
	}
}

func TestPlanMsgParts(t *testing.T) {
	s := srv("aaaaaaaa0001", "NL", "nl.example")
	s.TLS.CA = `C:\certs\ca.pem`
	pl := plan(baseState(), payload(true).put("servers", bkServers{List: []hysteria.Profile{s}}).p, map[string]string{"servers": "replace"})
	for _, m := range append(slices.Clone(pl.lines), pl.warnings...) {
		joined := ""
		for _, p := range m.Parts {
			joined += p.T
			if p.S && strings.Contains(p.T, "NL") {
				t.Fatal("a server name marked sensitive")
			}
		}
		if joined != m.Text {
			t.Fatalf("%q != %q", joined, m.Text)
		}
	}
}

func TestPlanRulesAndSettings(t *testing.T) {
	cur := baseState()
	cur.Settings.Rules = []rules.Rule{{ID: "r1", Name: "mine", Apps: []rules.AppMatch{{Pattern: "a.exe"}}, Action: rules.Block}}
	file := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{ID: "", Name: "no id", Apps: []rules.AppMatch{{Pattern: "b.exe"}}, Action: rules.Block},
		{ID: "r1", Name: "collides", Apps: []rules.AppMatch{{Pattern: "c.exe"}}, Action: rules.Block},
		{ID: "../bad", Name: "invalid", Apps: []rules.AppMatch{{Pattern: "d.exe"}}, Action: rules.Block},
	}}
	pl := plan(cur, payload(false).put("rules", bkRules{Config: file}).p, map[string]string{"rules": "add"})
	r := pl.next.Settings.Rules
	if len(r) != 4 || r[0].ID != "r1" || r[1].ID != "" || r[2].ID == "r1" || r[2].ID == "" || r[3].ID != "" || pl.next.Settings.DefaultAction != cur.Settings.DefaultAction {
		t.Fatalf("%+v", r)
	}
	// Settings: every change a line, weakening ones a warning too.
	on, off := true, false
	cur.Settings.KillSwitch = &on
	eng := map[string]json.RawMessage{"killSwitch": json.RawMessage("false"), "blockIPv6Tunnel": json.RawMessage("false")}
	prefs := map[string]json.RawMessage{"updateChannel": json.RawMessage(`"beta"`)}
	pl = plan(cur, payload(false).put("settings", bkSettings{Engine: eng, Prefs: prefs}).p, map[string]string{"settings": "replace"})
	tx := texts(pl)
	for _, want := range []string{"L Kill switch: включён → выключен.", "W Kill switch выключится", "W Не пускать IPv6 в VPN выключится", "W Канал обновлений: beta"} {
		if !strings.Contains(tx, want) {
			t.Fatalf("%q not in\n%s", want, tx)
		}
	}
	if pl.ksChange != -1 || !sameRules(pl.next.Settings.Config, cur.Settings.Config) {
		t.Fatal("rules kept, kill switch off")
	}
	_ = off
	// A value the page does not allow: the section is refused.
	pl = plan(cur, payload(false).put("settings", bkSettings{Prefs: map[string]json.RawMessage{"updateChannel": json.RawMessage(`"nightly"`)}}).p, map[string]string{"settings": "replace"})
	if !strings.Contains(pl.err, "Раздел повреждён") {
		t.Fatal(pl.err)
	}
	// An unknown engine key: made by a newer HyRoute.
	pl = plan(cur, payload(false).put("settings", bkSettings{Engine: map[string]json.RawMessage{"future": json.RawMessage("1")}}).p, map[string]string{"settings": "replace"})
	if !strings.Contains(pl.err, "более новой версией") {
		t.Fatal(pl.err)
	}
}

func TestPlanSubsKeptAndRenumbered(t *testing.T) {
	cur := baseState(srv("aaaaaaaa0001", "S1", "s1.example"))
	cur.Profiles.List[0].Source = "sub:cccccccc0001"
	cur.Subs = []store.Subscription{{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Interval: "manual", Count: 1, HasPrevious: true, Warnings: []string{"w"}}}
	fs := srv("ffffffff0001", "S1", "s1.example")
	fs.Auth = "pass-aaaaaaaa0001"
	same := bkSub{ID: "cccccccc0001", Name: "P renamed", URL: "https://p.example/s", Interval: "12h", Servers: []hysteria.Profile{fs}}
	pl := plan(cur, payload(true).put("subscriptions", []bkSub{same}).p, map[string]string{"subscriptions": "replace"})
	s := pl.next.Subs[0]
	if s.ID != "cccccccc0001" || !s.HasPrevious || s.Name != "P renamed" || s.Interval != "12h" || len(pl.removedSubs) != 0 {
		t.Fatalf("%+v %v", s, pl.removedSubs)
	}
	if pl.next.Profiles.List[0].ID != "aaaaaaaa0001" {
		t.Fatal("server ID not kept")
	}
	// The same ID with another URL: a new ID, the old one removed.
	other := same
	other.URL = "https://other.example/s"
	pl = plan(cur, payload(true).put("subscriptions", []bkSub{other}).p, map[string]string{"subscriptions": "replace"})
	if pl.next.Subs[0].ID == "cccccccc0001" || !slices.Equal(pl.removedSubs, []string{"cccccccc0001"}) {
		t.Fatalf("%+v %v", pl.next.Subs, pl.removedSubs)
	}
	// Invalid IDs never reach file names.
	evil := same
	evil.ID = `..\..\x`
	evil.URL = "https://e.example/s"
	pl = plan(baseState(), payload(true).put("subscriptions", []bkSub{evil}).p, map[string]string{"subscriptions": "replace"})
	if !importIDRe.MatchString(pl.next.Subs[0].ID) {
		t.Fatal(pl.next.Subs[0].ID)
	}
}

func TestPlanProxies(t *testing.T) {
	cur := baseState()
	cur.Proxies = []store.LocalProxy{{ID: "aaaaaaaa0001", Name: "Mine", Port: 20000}}
	lan := bkProxy{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0001", Name: "LAN", Port: 20001, LAN: true, Enabled: true, Username: "u"}, Password: "p"}
	clash := bkProxy{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0002", Name: "Clash", Port: 20000}}
	pl := plan(cur, payload(true).put("proxies", []bkProxy{lan, clash}).p, map[string]string{"proxies": "add"})
	if len(pl.next.Proxies) != 2 || pl.next.Proxies[1].Enabled || !strings.Contains(texts(pl), "порт 20000 уже занят прокси «Mine»") || pl.redact["proxy:bbbbbbbb0001"] == nil {
		t.Fatalf("%+v\n%s", pl.next.Proxies, texts(pl))
	}
	dup := clash
	dup.ID = "bbbbbbbb0003"
	pl = plan(cur, payload(true).put("proxies", []bkProxy{clash, dup}).p, map[string]string{"proxies": "replace"})
	if !strings.Contains(pl.err, "порт 20000 у двух прокси") {
		t.Fatal(pl.err)
	}
}

func TestPlanBrokenCoverage(t *testing.T) {
	cur := baseState()
	cur.Broken["profiles.json"] = fmt.Errorf("x")
	cur.Subs = []store.Subscription{{ID: "cccccccc0001", Name: "P", URL: "https://p.example/s", Enabled: true, Interval: "manual"}}
	pl := plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{}}).p, map[string]string{"servers": "replace"})
	if pl.err != "" || !slices.Equal(pl.refreshSubs, []string{"cccccccc0001"}) || !slices.Contains(pl.keepBroken, "profiles.json") {
		t.Fatalf("%s %v %v", pl.err, pl.refreshSubs, pl.keepBroken)
	}
	pl = plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{}}).p, map[string]string{"servers": "add"})
	if !strings.Contains(pl.err, "profiles.json не загружен") {
		t.Fatal(pl.err)
	}
	cur = baseState()
	cur.Broken["prefs.json"] = fmt.Errorf("x")
	pl = plan(cur, payload(false).put("geo", bkGeo{GeoSource: "v2fly"}).p, map[string]string{"geo": "replace"})
	if pl.err != "" || !slices.Contains(pl.writes, "prefs.json") {
		t.Fatal(pl.err, pl.writes)
	}
	cur = baseState()
	cur.Broken["settings.json"] = fmt.Errorf("x")
	pl = plan(cur, payload(false).put("settings", bkSettings{Engine: map[string]json.RawMessage{}}).p, map[string]string{"settings": "replace"})
	if !strings.Contains(pl.err, "отметьте «Правила»") {
		t.Fatal(pl.err)
	}
	cur = baseState()
	cur.Broken["proxies.json"] = fmt.Errorf("x")
	pl = plan(cur, payload(false).put("servers", bkServers{List: []hysteria.Profile{}}).p, map[string]string{"servers": "replace"})
	if !strings.Contains(pl.err, "заменить серверы нельзя") {
		t.Fatal(pl.err)
	}
	_ = settings.Settings{}
}

// TestPlanGroupsImport: add renumbers a colliding grp- ID and dedupes the
// name; malformed IDs are renumbered (and rules naming them follow); a
// rules-only file finds a group of the file's by its unique name.
func TestPlanGroupsImport(t *testing.T) {
	a := srv("aaaaaaaa0001", "A", "a.example")
	cur := baseState(a)
	cur.Groups.Groups = []groups.Group{{ID: "grp-000000000001", Name: "Авто", Strategy: groups.Failover, Members: []string{a.ID}}}
	f := groups.File{Version: 1, Groups: []groups.Group{
		{ID: "grp-000000000001", Name: "авто", Strategy: groups.Failover, Members: []string{a.ID}},
		{ID: "grp-XYZ", Name: "X", Strategy: groups.Failover, Members: []string{a.ID}},
		{ID: "../x", Name: "Y", Strategy: groups.Failover, Members: []string{a.ID}},
	}}
	rule := rules.Rule{Name: "x", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Tunnel, Profile: "grp-XYZ"}
	b := payload(false).put("groups", f).put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rule}}})
	pl := plan(cur, b.p, map[string]string{"groups": "add", "rules": "replace"})
	if pl.err != "" {
		t.Fatal(pl.err)
	}
	gs := pl.next.Groups.Groups
	if len(gs) != 4 {
		t.Fatalf("%+v", gs)
	}
	ids := map[string]bool{}
	for _, g := range gs {
		if !groups.ValidID(g.ID) || ids[g.ID] {
			t.Fatalf("bad or repeated ID %q: %+v", g.ID, gs)
		}
		ids[g.ID] = true
	}
	if gs[0].ID != "grp-000000000001" || gs[0].Name != "Авто" || gs[1].Name != "авто (2)" || gs[2].Name != "X" || gs[3].Name != "Y" {
		t.Fatalf("%+v", gs)
	}
	if got := pl.next.Settings.Rules[0].Profile; got != gs[2].ID {
		t.Fatalf("rule target %q, group X is %q", got, gs[2].ID)
	}
	// Replace: the malformed IDs are renumbered too.
	pl = plan(cur, b.p, map[string]string{"groups": "replace"})
	for _, g := range pl.next.Groups.Groups {
		if !groups.ValidID(g.ID) {
			t.Fatalf("%+v", pl.next.Groups.Groups)
		}
	}
	// Rules only: the file's group is found here by its unique name.
	r := rules.Rule{Name: "g", Apps: []rules.AppMatch{{Pattern: "g.exe"}}, Action: rules.Tunnel, Profile: "grp-00000000000a"}
	ro := payload(false).put("rules", bkRules{Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{r}}})
	ro.p.Targets = map[string]backup.Target{"grp-00000000000a": {Name: "авто", Group: true}}
	pl = plan(cur, ro.p, map[string]string{"rules": "replace"})
	if got := pl.next.Settings.Rules[0].Profile; got != "grp-000000000001" || !strings.Contains(texts(pl), "Группа «авто» найдена среди ваших по имени.") {
		t.Fatalf("%q\n%s", got, texts(pl))
	}
}

func rsFile(active string, list ...store.Ruleset) json.RawMessage {
	b, _ := json.Marshal(&store.Rulesets{Version: store.RulesetsVersion, Active: active, List: list})
	return b
}

// TestPlanNetworks (netmodes): rule profile references follow the restored
// profiles (rsmap), then an ID or a name of this computer's; an unknown one
// drops only the profile part, with a warning. A rule that disconnects is a
// warning; IDs are renumbered on a collision in «Добавить».
func TestPlanNetworks(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{}}
	file := payload(false).put("rules", bkRules{Config: cfg, Rulesets: rsFile("0000000000a1",
		store.Ruleset{ID: "0000000000a1", Name: "Дом", Config: cfg}, store.Ruleset{ID: "0000000000a2", Name: "Игры", Config: cfg})})
	home := netmode.Rule{ID: "0000000000b1", Name: "Дом", Match: netmode.Match{SSIDs: []string{"HomeWiFi"}}, Action: netmode.Action{Connect: netmode.Disconnect, Ruleset: "0000000000a1"}}
	games := netmode.Rule{ID: "0000000000b2", Name: "Клуб", Match: netmode.Match{Categories: []string{netmode.Public}}, Action: netmode.Action{Ruleset: "0000000000a2"}}
	gone := netmode.Rule{ID: "0000000000b3", Name: "Офис", Match: netmode.Match{Names: []string{"corp"}}, Action: netmode.Action{Connect: netmode.Connect, Ruleset: "ffffffffffff"}}
	file.put("networks", netmode.Config{Version: 1, Enabled: true, Rules: []netmode.Rule{home, games, gone}, Unknown: netmode.Action{Connect: netmode.Connect}})

	cur := baseState()
	cur.Rulesets = &store.Rulesets{Version: store.RulesetsVersion, Active: "0000000000a1", List: []store.Ruleset{{ID: "0000000000a1", Name: "Мой", Config: cfg}}}
	cur.Net = netmode.Default()
	pl := plan(cur, file.p, map[string]string{"rules": "replace", "networks": "replace"})
	if pl.err != "" {
		t.Fatal(pl.err)
	}
	rs, net := pl.next.Rulesets, pl.next.Net
	byName := map[string]string{}
	for _, e := range rs.List {
		byName[e.Name] = e.ID
	}
	if len(net.Rules) != 3 || net.Rules[0].Ruleset != byName["Дом"] || net.Rules[1].Ruleset != byName["Игры"] || net.Rules[2].Ruleset != "" ||
		net.Rules[2].Connect != netmode.Connect || !net.Enabled || !slices.Contains(pl.writes, "networks.json") {
		t.Fatalf("%+v\n%+v", net, rs)
	}
	tx := texts(pl)
	for _, want := range []string{
		"L Правила сетей: будет 3.",
		"L Сеть «Дом» (Wi-Fi «HomeWiFi»): отключиться (всё напрямую).",
		"L Сеть «Клуб» (общедоступная сеть): профиль правил «Игры».",
		"L Правила сетей: выключены → включены.",
		"L Неизвестная сеть: подключиться.",
		"W Сеть «Офис»: профиля правил «удалённый профиль правил» нет — профиль правил не переключается",
		"W Сеть «Дом» (Wi-Fi «HomeWiFi»): при подключении к ней HyRoute отключится и kill switch снимет блокировку",
	} {
		if !strings.Contains(tx, want) {
			t.Fatalf("%q not in\n%s", want, tx)
		}
	}
	// SSIDs and rule names are masked in Privacy mode.
	for _, m := range pl.warnings {
		for _, p := range m.Parts {
			if strings.Contains(p.T, "HomeWiFi") && !p.S {
				t.Fatalf("SSID not sensitive: %+v", m.Parts)
			}
		}
	}

	// Rules not restored: a profile of this computer's by ID, then by the
	// file's name for it.
	cur.Rulesets.List = append(cur.Rulesets.List, store.Ruleset{ID: "0000000000c9", Name: "игры", Config: cfg})
	pl = plan(cur, file.p, map[string]string{"networks": "replace"})
	if r := pl.next.Net.Rules; r[0].Ruleset != "0000000000a1" || r[1].Ruleset != "0000000000c9" || !strings.Contains(texts(pl), "Профиль правил «Игры» найден среди ваших по имени.") {
		t.Fatalf("%+v\n%s", r, texts(pl))
	}

	// Add: current rules, «enabled» and «Неизвестная сеть» stay; a taken ID
	// is renumbered.
	cur.Net = netmode.Config{Version: 1, Enabled: true, Rules: []netmode.Rule{home}, Unknown: netmode.Action{}}
	pl = plan(cur, file.p, map[string]string{"networks": "add"})
	r := pl.next.Net.Rules
	if len(r) != 4 || r[0].ID != home.ID || r[1].ID == home.ID || !netmode.ValidID(r[1].ID) || pl.next.Net.Unknown.Connect != "" {
		t.Fatalf("%+v", pl.next.Net)
	}
	if strings.Contains(texts(pl), "Неизвестная сеть:") {
		t.Fatal(texts(pl))
	}
	// Over 100 rules: «Заменить».
	many := netmode.Config{Version: 1}
	for i := range netmode.MaxRules {
		many.Rules = append(many.Rules, netmode.Rule{Name: fmt.Sprintf("n%d", i), Match: netmode.Match{Names: []string{"x"}}})
	}
	pl = plan(cur, payload(false).put("networks", many).p, map[string]string{"networks": "add"})
	if !strings.Contains(pl.err, "Правил сетей станет больше 100") {
		t.Fatal(pl.err)
	}
	// A newer format is refused; a malformed ID is renumbered.
	pl = plan(cur, payload(false).put("networks", map[string]any{"version": 2}).p, map[string]string{"networks": "replace"})
	if !strings.Contains(pl.err, "более новой версией") {
		t.Fatal(pl.err)
	}
	bad := netmode.Config{Version: 1, Rules: []netmode.Rule{{ID: "../x", Name: "n", Match: netmode.Match{Names: []string{"x"}}}}}
	pl = plan(cur, payload(false).put("networks", bad).p, map[string]string{"networks": "replace"})
	if pl.err != "" || !netmode.ValidID(pl.next.Net.Rules[0].ID) {
		t.Fatal(pl.err, pl.next.Net.Rules)
	}

	// Rules restored without «Сети»: the network rules that switch to a
	// profile the restore drops are named.
	cur.Net = netmode.Config{Version: 1, Rules: []netmode.Rule{{ID: "0000000000d1", Name: "Кафе", Match: netmode.Match{Names: []string{"cafe"}}, Action: netmode.Action{Ruleset: "0000000000c9"}}}}
	pl = plan(cur, file.p, map[string]string{"rules": "replace"})
	if !strings.Contains(texts(pl), "W Сеть «Кафе»: профиля правил «игры» не будет") {
		t.Fatal(texts(pl))
	}
}

// TestPlanNetworksWeakening: the same disconnecting rule already there is
// no warning; turning the feature on warns about every such rule.
func TestPlanNetworksWeakening(t *testing.T) {
	home := netmode.Rule{ID: "0000000000b1", Name: "Дом", Match: netmode.Match{Names: []string{"home"}}, Action: netmode.Action{Connect: netmode.Disconnect}}
	cur := baseState()
	cur.Net = netmode.Config{Version: 1, Enabled: true, Rules: []netmode.Rule{home}, Unknown: netmode.Action{Connect: netmode.Connect}}
	file := payload(false).put("networks", netmode.Config{Version: 1, Enabled: true, Rules: []netmode.Rule{home}, Unknown: netmode.Action{Connect: netmode.Connect}}).p
	if pl := plan(cur, file, map[string]string{"networks": "replace"}); len(pl.warnings) != 0 {
		t.Fatal(texts(pl))
	}
	cur.Net.Enabled = false
	if pl := plan(cur, file, map[string]string{"networks": "replace"}); !strings.Contains(texts(pl), "W Сеть «Дом» (сеть «home»): при подключении к ней HyRoute отключится") {
		t.Fatal(texts(pl))
	}
	cur.Net.Enabled = true
	file = payload(false).put("networks", netmode.Config{Version: 1, Enabled: true, Rules: []netmode.Rule{home}, Unknown: netmode.Action{Connect: netmode.Disconnect}}).p
	if pl := plan(cur, file, map[string]string{"networks": "replace"}); !strings.Contains(texts(pl), "W В неизвестной сети HyRoute отключится") {
		t.Fatal(texts(pl))
	}
}

// TestPlanDNS: each changed option is a line (a custom server never by its
// URL); turning a protection off is a warning; the server's secrets reach
// the redactor before any write.
func TestPlanDNS(t *testing.T) {
	cur := baseState()
	cur.DNS = dnspolicy.Config{BlockBrowserDoH: true}
	const url = "https://dns.example/DNSSECRET42/dns-query"
	file := dnspolicy.Config{ByRules: true, Tunnel: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: url}}
	pl := plan(cur, payload(true).put("dns", file).p, map[string]string{"dns": "replace"})
	tx := texts(pl)
	for _, want := range []string{"L DNS по правилам: нет → да.", "L DNS-сервер для VPN: Cloudflare → свой сервер.", "W Не давать браузерам обходить DNS выключится"} {
		if !strings.Contains(tx, want) {
			t.Fatalf("%q not in\n%s", want, tx)
		}
	}
	if strings.Contains(tx, "DNSSECRET42") || !slices.Contains(pl.writes, "dns.json") || pl.next.DNS != file ||
		!slices.ContainsFunc(pl.redact["dns"], func(s string) bool { return strings.Contains(s, "DNSSECRET42") }) {
		t.Fatalf("%s %v %+v", tx, pl.writes, pl.redact)
	}
	// Unchanged: no write.
	cur.DNS = file
	if pl = plan(cur, payload(true).put("dns", file).p, map[string]string{"dns": "replace"}); len(pl.writes) != 0 || !strings.Contains(texts(pl), "Настройки DNS не изменятся.") {
		t.Fatal(pl.writes, texts(pl))
	}
	// A bad server: the section is refused.
	pl = plan(cur, payload(true).put("dns", dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: dnspolicy.Custom, URL: "tcp://9.9.9.9"}}).p, map[string]string{"dns": "replace"})
	if !strings.Contains(pl.err, "Раздел повреждён") {
		t.Fatal(pl.err)
	}
	// dns.json broken: «Заменить» of «DNS» replaces it, keeping a copy.
	cur.Broken["dns.json"] = fmt.Errorf("x")
	if pl = plan(cur, payload(true).put("dns", file).p, map[string]string{"dns": "replace"}); pl.err != "" || !slices.Contains(pl.keepBroken, "dns.json") {
		t.Fatal(pl.err, pl.keepBroken)
	}
}

// TestPlanStats: the stats store's check (made before the plan) decides;
// the section writes no data file.
func TestPlanStats(t *testing.T) {
	p := payload(true).put("stats", map[string]any{"v": 1}).p
	env := testEnv()
	env.statsDetail = "с 12.07.2026 · 3 дня"
	pl := planRestore(baseState(), p, BackupChoice{Sections: map[string]string{"stats": "replace"}}, env)
	if pl.err != "" || len(pl.writes) != 0 || !slices.Equal(pl.sections, []string{"stats"}) ||
		!strings.Contains(texts(pl), "Статистика: ваша будет заменена статистикой из копии (с 12.07.2026 · 3 дня).") {
		t.Fatalf("%s %v %v %s", pl.err, pl.writes, pl.sections, texts(pl))
	}
	env.statsErr = fmt.Errorf("файл повреждён")
	if pl = planRestore(baseState(), p, BackupChoice{Sections: map[string]string{"stats": "replace"}}, env); !strings.Contains(pl.err, "«Статистика»: файл повреждён") {
		t.Fatal(pl.err)
	}
	// Never in a copy without a password.
	if pl = plan(baseState(), payload(false).put("stats", map[string]any{"v": 1}).p, map[string]string{"stats": "replace"}); !strings.Contains(pl.err, "статистика в копии без пароля не хранится") {
		t.Fatal(pl.err)
	}
}

// TestPlanProxyUDP (socks-udp): the udp value is stored as SaveProxy stores
// it; a LAN proxy's is always written (never read as v1.2.0's).
func TestPlanProxyUDP(t *testing.T) {
	lan := bkProxy{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0001", Name: "LAN", Port: 20001, LAN: true, Username: "u"}, Password: "p"}
	on := bkProxy{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0002", Name: "Local", Port: 20002, UDP: "on"}}
	off := bkProxy{LocalProxy: store.LocalProxy{ID: "bbbbbbbb0003", Name: "NoUDP", Port: 20003, UDP: "off"}}
	pl := plan(baseState(), payload(true).put("proxies", []bkProxy{lan, on, off}).p, map[string]string{"proxies": "replace"})
	px := pl.next.Proxies
	if len(px) != 3 || px[0].UDP != "off" || px[1].UDP != "" || px[2].UDP != "off" {
		t.Fatalf("%+v", px)
	}
}

// TestPlanPrefsKeepCLI (cli): hyroutectl's access never comes from a copy;
// with prefs.json broken it is off.
func TestPlanPrefsKeepCLI(t *testing.T) {
	cur := baseState()
	cur.Prefs.CLI = "off"
	prefs := map[string]json.RawMessage{"cli": json.RawMessage(`"full"`), "autoConnect": json.RawMessage("true")}
	pl := plan(cur, payload(false).put("settings", bkSettings{Prefs: prefs}).p, map[string]string{"settings": "replace"})
	if pl.err != "" || pl.next.Prefs.CLI != "off" || !pl.next.Prefs.AutoConnect || strings.Contains(texts(pl), "cli") {
		t.Fatalf("%s %+v\n%s", pl.err, pl.next.Prefs, texts(pl))
	}
	cur = baseState()
	cur.Broken["prefs.json"] = fmt.Errorf("x")
	pl = plan(cur, payload(false).put("settings", bkSettings{Prefs: prefs}).p, map[string]string{"settings": "replace"})
	if pl.err != "" || pl.next.Prefs.CLI != "off" {
		t.Fatalf("%s %+v", pl.err, pl.next.Prefs)
	}
}
