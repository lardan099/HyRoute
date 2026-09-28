package netmode

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	gHome = "{5E1B9C0A-3C7D-4F0E-9A51-0D2B6B1C7E11}"
	gCafe = "{11111111-2222-3333-4444-555555555555}"
)

func off() *bool { v := false; return &v }

func TestParseDefaultsAndVersion(t *testing.T) {
	cfg, err := Parse([]byte(`{"enabled":true,"rules":[]}`))
	if err != nil || cfg.Version != 1 || !cfg.Enabled || cfg.Rules == nil {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := Parse([]byte(`{"version":2,"rules":[]}`)); err == nil || !strings.Contains(err.Error(), "более новой версией HyRoute (формат 2)") {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`{"version":1,"rules":[],"future":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Parse([]byte("\xef\xbb\xbf" + `{"version":1,"rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`{"version":1,"rules":[]} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	big := make([]byte, MaxFileSize+1)
	if _, err := Parse(big); err == nil || err.Error() != "networks.json больше 1 МБ" {
		t.Fatal(err)
	}
}

func rule(name string, m Match, a Action) Rule {
	return Rule{ID: "a1b2c3d4e5f6", Name: name, Match: m, Action: a}
}

func TestValidate(t *testing.T) {
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("x", i+1)
		}
		return out
	}
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{Rules: []Rule{rule("Дом", Match{}, Action{})}}, "Правило сети «Дом»: укажите хотя бы одно условие"},
		{Config{Rules: []Rule{rule("Дом", Match{Categories: []string{"home"}}, Action{})}}, `неизвестный тип сети "home"`},
		{Config{Rules: []Rule{rule("Дом", Match{Adapters: []string{"lan"}}, Action{})}}, `неизвестный вид подключения "lan"`},
		{Config{Rules: []Rule{rule("Дом", Match{SSIDs: []string{strings.Repeat("s", 33)}}, Action{})}}, "имя Wi-Fi пустое или длиннее 32 байт"},
		{Config{Rules: []Rule{rule("Дом", Match{SSIDs: []string{"hex:zz"}}, Action{})}}, "имя Wi-Fi пустое"},
		{Config{Rules: []Rule{rule("Дом", Match{Networks: []Known{{ID: "not-a-guid"}}}, Action{})}}, `неверный идентификатор сети "not-a-guid"`},
		{Config{Rules: []Rule{rule("Дом", Match{Names: many(33)}, Action{})}}, "больше 32 значений в одном условии"},
		{Config{Rules: []Rule{rule("Дом", Match{Names: []string{strings.Repeat("я", 257)}}, Action{})}}, "слишком длинное имя сети"},
		{Config{Rules: []Rule{rule("Дом", Match{Adapters: []string{WiFi}}, Action{Ruleset: "X"})}}, `неверный профиль правил "X"`},
		{Config{Rules: []Rule{rule("Дом", Match{Adapters: []string{WiFi}}, Action{Connect: "maybe"})}}, `неизвестное действие "maybe"`},
		{Config{Rules: []Rule{rule("А", Match{Adapters: []string{WiFi}}, Action{}), rule("Б", Match{Adapters: []string{WiFi}}, Action{})}}, `Два правила сетей с одним id "a1b2c3d4e5f6"`},
		{Config{Rules: []Rule{{ID: "XYZ", Name: "Дом", Match: Match{Adapters: []string{WiFi}}}}}, `неверный id "XYZ"`},
		{Config{Unknown: Action{Connect: "x"}}, `Неизвестная сеть: неизвестное действие "x"`},
		{Config{Rules: []Rule{rule("Дом\nсети: выключены", Match{Adapters: []string{WiFi}}, Action{})}}, "Правило сети №1: в названии не может быть управляющих символов"},
		{Config{Rules: []Rule{rule("Дом\u2028", Match{Adapters: []string{WiFi}}, Action{})}}, "Правило сети №1: в названии"},
		{Config{Rules: []Rule{rule("Дом", Match{Names: []string{"a\u2029b"}}, Action{})}}, "Правило сети «Дом»: в имени сети не может быть"},
		{Config{Rules: []Rule{rule("Дом", Match{Networks: []Known{{ID: gHome, Name: "a\x07"}}}, Action{})}}, "в имени сети не может быть"},
	}
	for i, c := range cases {
		err := Validate(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d: %v, want %q", i, err, c.want)
		}
	}
	var lots []Rule
	for i := 0; i < 101; i++ {
		lots = append(lots, Rule{Name: "r", Match: Match{Adapters: []string{WiFi}}})
	}
	if err := Validate(Config{Rules: lots}); err == nil || err.Error() != "Правил сетей больше 100" {
		t.Fatal(err)
	}
	okCfg := Config{Rules: []Rule{rule("Дом", Match{SSIDs: []string{"hex:00ff", "Кафе"}, Networks: []Known{{ID: gHome, Name: "HomeWiFi"}}}, Action{Connect: Disconnect, Ruleset: "0c0ffee12345"})}}
	if err := Validate(okCfg); err != nil {
		t.Fatal(err)
	}
}

func TestNormalize(t *testing.T) {
	on := true
	in := Config{Rules: []Rule{{
		Name:    "  ",
		Enabled: &on,
		Match: Match{
			Networks:   []Known{{ID: strings.ToLower(strings.Trim(gHome, "{}")), Name: " Home "}, {ID: gHome}},
			SSIDs:      []string{" a ", " a ", ""},
			Names:      []string{"Net", " net ", ""},
			Categories: []string{Private, Private},
			Adapters:   []string{" wifi"},
		},
	}}}
	orig := in.Rules[0].Match.SSIDs[0]
	Normalize(&in)
	r := in.Rules[0]
	if r.Name != "Сеть 1" || r.Enabled != nil {
		t.Fatalf("%+v", r)
	}
	if len(r.Match.Networks) != 1 || r.Match.Networks[0].ID != gHome || r.Match.Networks[0].Name != "Home" {
		t.Fatalf("%+v", r.Match.Networks)
	}
	if strings.Join(r.Match.SSIDs, "|") != " a " || strings.Join(r.Match.Names, "|") != "Net" || len(r.Match.Categories) != 1 || r.Match.Adapters[0] != WiFi {
		t.Fatalf("%+v", r.Match)
	}
	if orig != " a " {
		t.Fatal("caller's slice changed")
	}
	var nilRules Config
	Normalize(&nilRules)
	if nilRules.Rules == nil {
		t.Fatal("nil rules")
	}
}

func wifi(id string, ident bool) Network {
	return Network{ID: id, Identified: ident, Name: "HomeWiFi", Category: Private, Adapter: WiFi, AdapterID: "{A}", GatewayIP: "192.168.1.1"}
}

func TestDecideOrderAndUnknown(t *testing.T) {
	cfg := Config{
		Rules: []Rule{
			{ID: "00000001", Name: "Выкл", Enabled: off(), Match: Match{Adapters: []string{WiFi}}, Action: Action{Connect: Connect}},
			{ID: "00000002", Name: "Дом", Match: Match{Networks: []Known{{ID: gHome}}}, Action: Action{Connect: Disconnect}},
			{ID: "00000003", Name: "Wi-Fi", Match: Match{Adapters: []string{WiFi}}, Action: Action{Connect: Connect}},
		},
		Unknown: Action{Connect: Connect, Ruleset: "abcdef12"},
	}
	if d := Decide(cfg, wifi(gHome, true)); d.Name != "Дом" || d.Connect != Disconnect || d.Unknown {
		t.Fatalf("%+v", d)
	}
	if d := Decide(cfg, wifi(gCafe, true)); d.Name != "Wi-Fi" || d.RuleID != "00000003" {
		t.Fatalf("%+v", d)
	}
	eth := wifi(gCafe, true)
	eth.Adapter = Ethernet
	if d := Decide(cfg, eth); !d.Unknown || d.Name != UnknownName || d.Action != cfg.Unknown {
		t.Fatalf("%+v", d)
	}
}

func TestMatchSemantics(t *testing.T) {
	n := wifi(gHome, true)
	n.SSID = "HomeSSID"
	both := Match{Networks: []Known{{ID: gHome}}, Categories: []string{Public, Private}}
	if !both.Matches(n) {
		t.Fatal("AND/OR")
	}
	both.Categories = []string{Public}
	if both.Matches(n) {
		t.Fatal("AND across groups")
	}
	noID := n
	noID.ID = ""
	if (Match{Networks: []Known{{ID: gHome}}}).Matches(noID) {
		t.Fatal("empty ID matched")
	}
	if !(Match{Names: []string{"homewifi"}}).Matches(n) {
		t.Fatal("names are case-insensitive")
	}
	if (Match{SSIDs: []string{"homessid"}}).Matches(n) || !(Match{SSIDs: []string{"HomeSSID"}}).Matches(n) {
		t.Fatal("SSIDs exact")
	}
	eth := n
	eth.Adapter = Ethernet
	if (Match{SSIDs: []string{"HomeSSID"}}).Matches(eth) {
		t.Fatal("SSID condition needs Wi-Fi")
	}
	denied := n
	denied.SSID, denied.SSIDDenied = "", true
	if !(Match{SSIDs: []string{"HomeWiFi"}}).Matches(denied) || (Match{SSIDs: []string{"HomeSSID"}}).Matches(denied) {
		t.Fatal("SSID falls back to the NLM name")
	}
	noCat := n
	noCat.Category = ""
	if (Match{Categories: []string{""}}).Matches(noCat) || (Match{Categories: []string{Private}}).Matches(noCat) {
		t.Fatal("empty category matched")
	}
	if (Match{}).Matches(n) {
		t.Fatal("empty match matched")
	}
}

func TestCompare(t *testing.T) {
	base := Ident{NetID: gHome, AdapterID: "{A}", GatewayIP: "192.168.1.1", GatewayMAC: "aa"}
	noID := Ident{AdapterID: "{A}", GatewayIP: "192.168.1.1", GatewayMAC: "aa"}
	cases := []struct {
		name      string
		base, cur Ident
		want      Relation
	}{
		{"base empty", Ident{}, base, Changed},
		{"same ID other case", base, Ident{NetID: strings.ToLower(gHome), AdapterID: "{B}"}, Same},
		{"other ID", base, Ident{NetID: gCafe, AdapterID: "{A}", GatewayIP: "192.168.1.1"}, Changed},
		{"refined", noID, base, Refined},
		{"refined one MAC empty", Ident{AdapterID: "{A}", GatewayIP: "192.168.1.1"}, base, Refined},
		{"refined other link", noID, Ident{NetID: gHome, AdapterID: "{B}", GatewayIP: "192.168.1.1"}, Changed},
		{"no ID both MACs equal (base with ID)", base, noID, Same},
		{"no ID both MACs equal (base without ID)", noID, noID, Same},
		{"no ID, read MAC empty", base, Ident{AdapterID: "{A}", GatewayIP: "192.168.1.1"}, Unclear},
		{"no ID, base MAC empty", Ident{NetID: gHome, AdapterID: "{A}", GatewayIP: "192.168.1.1"}, noID, Unclear},
		{"no ID, base without ID MAC empty", Ident{AdapterID: "{A}", GatewayIP: "192.168.1.1"}, noID, Unclear},
		{"other adapter", base, Ident{AdapterID: "{B}", GatewayIP: "192.168.1.1", GatewayMAC: "aa"}, Changed},
		{"gateway IP differs", base, Ident{AdapterID: "{A}", GatewayIP: "192.168.0.1", GatewayMAC: "aa"}, Changed},
		{"MACs differ", base, Ident{AdapterID: "{A}", GatewayIP: "192.168.1.1", GatewayMAC: "bb"}, Changed},
	}
	for _, c := range cases {
		if got := Compare(c.base, c.cur); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// Category, SSID and names are not part of the identity.
	a, b := wifi(gHome, true), wifi(gHome, true)
	b.Category, b.SSID, b.Name, b.SSIDDenied = Public, "x", "other", true
	if Compare(a.Ident(), b.Ident()) != Same {
		t.Fatal("attributes changed the identity")
	}
}

func TestIdentFillAndSameRead(t *testing.T) {
	i := Ident{AdapterID: "{A}", GatewayIP: "", GatewayMAC: "mm"}
	i.Fill(Ident{GatewayIP: "10.0.0.1", GatewayMAC: "zz"})
	if i.GatewayIP != "10.0.0.1" || i.GatewayMAC != "mm" {
		t.Fatalf("%+v", i)
	}
	a := Ident{NetID: gHome, AdapterID: "{A}", GatewayIP: "1.1.1.1", GatewayMAC: "m1"}
	if !SameRead(a, Ident{NetID: gHome, AdapterID: "{A}", GatewayIP: "1.1.1.1"}) {
		t.Fatal("missing MAC")
	}
	for _, b := range []Ident{
		{NetID: gCafe, AdapterID: "{A}", GatewayIP: "1.1.1.1"},
		{NetID: gHome, AdapterID: "{B}", GatewayIP: "1.1.1.1"},
		{NetID: gHome, AdapterID: "{A}", GatewayIP: "1.1.1.2"},
		{NetID: gHome, AdapterID: "{A}", GatewayIP: "1.1.1.1", GatewayMAC: "m2"},
		{AdapterID: "{A}", GatewayIP: "1.1.1.1"},
	} {
		if SameRead(a, b) {
			t.Errorf("%+v same as %+v", b, a)
		}
	}
}

func TestIdentUnidentified(t *testing.T) {
	n := Network{ID: gHome, Identified: false, AdapterID: "{A}"}
	if n.Ident().NetID != "" {
		t.Fatal("unidentified ID in the identity")
	}
	m := Match{Networks: []Known{{ID: gHome}}}
	if m.Matches(n) {
		t.Fatal("unidentified network matched")
	}
	n.Identified = true
	if !m.Matches(n) || n.Ident().NetID != gHome {
		t.Fatal("identified network not matched")
	}
	var nilNet *Network
	if !nilNet.Ident().Empty() {
		t.Fatal("nil network")
	}
}

func TestProtective(t *testing.T) {
	cfg := Config{Unknown: Action{Connect: Connect, Ruleset: "aaaaaaaa"}}
	conn := Decision{Name: "Работа", Action: Action{Connect: Connect}}
	disc := Decision{Name: "Дом", Action: Action{Connect: Disconnect}}
	keep := Decision{Name: "Дом"}
	cases := []struct {
		name       string
		cfg        Config
		d          Decision
		identified bool
		active     string
		byNet      bool
		want       Action
	}{
		{"connect", cfg, conn, true, "", false, Action{Connect: Connect}},
		{"disconnect", cfg, disc, true, "", false, Action{}},
		{"unidentified + unknown connect", cfg, disc, false, "", false, Action{Connect: Connect}},
		{"identified keep match", cfg, keep, true, "", false, Action{}},
		{"ruleset by network", cfg, keep, true, "bbbbbbbb", true, Action{Ruleset: "aaaaaaaa"}},
		{"ruleset already active", cfg, keep, true, "aaaaaaaa", true, Action{}},
		{"unknown ruleset keep", Config{}, keep, true, "bbbbbbbb", true, Action{}},
		{"ruleset by the user", cfg, keep, true, "bbbbbbbb", false, Action{}},
	}
	for _, c := range cases {
		if got := Protective(c.cfg, c.d, c.identified, c.active, c.byNet); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestRelaxing(t *testing.T) {
	if !Relaxing(Decision{Action: Action{Connect: Disconnect}}, Action{}) {
		t.Fatal("disconnect")
	}
	if !Relaxing(Decision{Action: Action{Ruleset: "aaaaaaaa"}}, Action{Ruleset: "bbbbbbbb"}) {
		t.Fatal("other ruleset")
	}
	if Relaxing(Decision{Action: Action{Connect: Connect}}, Action{Connect: Connect}) {
		t.Fatal("connect only")
	}
	if Relaxing(Decision{Action: Action{Ruleset: "aaaaaaaa"}}, Action{Ruleset: "aaaaaaaa"}) {
		t.Fatal("protective ruleset only")
	}
}

func TestSelectsRuleset(t *testing.T) {
	cfg := Config{
		Rules: []Rule{
			{Name: "a", Match: Match{Adapters: []string{WiFi}}, Action: Action{Ruleset: "aaaaaaaa"}},
			{Name: "b", Enabled: off(), Match: Match{Adapters: []string{WiFi}}, Action: Action{Ruleset: "bbbbbbbb"}},
		},
		Unknown: Action{Ruleset: "cccccccc"},
	}
	if !SelectsRuleset(cfg, "aaaaaaaa") || SelectsRuleset(cfg, "bbbbbbbb") || SelectsRuleset(cfg, "cccccccc") || SelectsRuleset(cfg, "") {
		t.Fatal("SelectsRuleset")
	}
}

func TestDefaultUnknownConnect(t *testing.T) {
	if Default().Unknown.Connect != Connect || Default().Enabled {
		t.Fatal("default")
	}
	cfg, err := Parse([]byte(`{"version":1,"enabled":true,"rules":[],"unknown":{}}`))
	if err != nil || cfg.Unknown.Connect != Keep {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = Parse([]byte(`{"version":1,"rules":[]}`))
	if err != nil || cfg.Unknown.Connect != Keep {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestIdentHash8(t *testing.T) {
	a := Ident{NetID: gHome, AdapterID: "{ADAPTER}", GatewayIP: "192.168.77.1", GatewayMAC: "aa-bb-cc-dd-ee-ff"}
	same := a
	b := a
	b.GatewayMAC = "11-22-33-44-55-66"
	if a.Hash8() != same.Hash8() || a.Hash8() == b.Hash8() || len(a.Hash8()) != 8 {
		t.Fatal("hash")
	}
	for _, raw := range []string{gHome, "ADAPTER", "192.168", "aa-bb"} {
		if strings.Contains(a.Hash8(), raw) {
			t.Fatal("raw value in the hash")
		}
	}
}

func TestNetworkJSONHidesLinkFields(t *testing.T) {
	b, err := json.Marshal(Network{ID: gHome, AdapterID: "{ADAPTER-GUID}", GatewayIP: "192.168.77.1", GatewayMAC: "aa-bb-cc-dd-ee-ff"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ADAPTER-GUID", "192.168.77.1", "aa-bb-cc"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%s in %s", s, b)
		}
	}
}

func TestSSIDString(t *testing.T) {
	if SSIDString([]byte("Кафе")) != "Кафе" {
		t.Fatal("utf-8")
	}
	if s := SSIDString([]byte{0xff, 0x00}); s != "hex:ff00" {
		t.Fatal(s)
	}
	if s := SSIDString([]byte("a\tb")); s != "hex:610962" {
		t.Fatal(s)
	}
	if SSIDString(nil) != "" {
		t.Fatal("empty")
	}
	if raw, ok := ParseSSID("hex:ff00"); !ok || len(raw) != 2 {
		t.Fatal("parse hex")
	}
	if _, ok := ParseSSID("hex:FF00"); ok {
		t.Fatal("upper-case hex accepted")
	}
	if _, ok := ParseSSID(""); ok {
		t.Fatal("empty accepted")
	}
}

func TestRefsRemap(t *testing.T) {
	cfg := Config{
		Rules: []Rule{
			{Name: "a", Action: Action{Connect: Connect, Ruleset: "aaaaaaaa"}},
			{Name: "b", Action: Action{Ruleset: "aaaaaaaa"}},
			{Name: "c", Action: Action{Connect: Disconnect}},
		},
		Unknown: Action{Ruleset: "bbbbbbbb"},
	}
	if r := cfg.Refs(); strings.Join(r, ",") != "aaaaaaaa,bbbbbbbb" {
		t.Fatal(r)
	}
	cfg.Remap(func(kind, id string) string {
		if kind != "ruleset" {
			t.Fatal(kind)
		}
		if id == "aaaaaaaa" {
			return ""
		}
		return "cccccccc"
	})
	if cfg.Rules[0].Connect != Connect || cfg.Rules[0].Ruleset != "" || cfg.Rules[1].Ruleset != "" || cfg.Unknown.Ruleset != "cccccccc" || cfg.Rules[2].Connect != Disconnect {
		t.Fatalf("%+v", cfg)
	}
}

func TestJSONRoundTripOmitempty(t *testing.T) {
	cfg := Default()
	cfg.Unknown = Action{}
	cfg.Rules = []Rule{{ID: "a1b2c3d4e5f6", Name: "Дом", Match: Match{Adapters: []string{WiFi}}}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"connect"`, `"ruleset"`, `"enabled":true`, `"ssids"`} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%s in %s", s, b)
		}
	}
	back, err := Parse(b)
	if err != nil || len(back.Rules) != 1 || back.Rules[0].Name != "Дом" {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestCanonGUID(t *testing.T) {
	if CanonGUID(" 5e1b9c0a-3c7d-4f0e-9a51-0d2b6b1c7e11 ") != gHome || CanonGUID("{x}") != "" {
		t.Fatal("CanonGUID")
	}
}
