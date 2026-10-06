package settings

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

func TestParseDefaults(t *testing.T) {
	s, set, err := Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"c","app":{"pattern":"curl.exe"},"action":"tunnel"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !s.QUICBlocked() || !s.IPv6TunnelBlocked() || !s.RemoteDNS() || s.SniffTimeout() != 800*time.Millisecond {
		t.Fatalf("%+v", s)
	}
	if set == nil {
		t.Fatal("no set")
	}
	s, _, err = Parse([]byte(`{"defaultAction":"tunnel","blockQUIC":false,"sniffTimeoutMs":300,"rules":[]}`))
	if err != nil || s.QUICBlocked() || s.SniffTimeout() != 300*time.Millisecond || s.DefaultAction != rules.Tunnel {
		t.Fatalf("%+v %v", s, err)
	}
	if _, _, err := Parse([]byte("\xef\xbb\xbf" + `{"defaultAction":"direct","rules":[]}`)); err != nil {
		t.Fatalf("BOM: %v", err)
	}
	if _, _, err := Parse([]byte(`{"defaultAction":"direct","typo":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, _, err := Parse([]byte(`{"rules":[{"name":"x"}]}`)); err == nil {
		t.Fatal("invalid rule accepted")
	}
}

// A hand-edited file without rules loads as an empty list, never null.
func TestParseNoRules(t *testing.T) {
	for _, in := range []string{`{"defaultAction":"tunnel"}`, `{"defaultAction":"tunnel","rules":null}`} {
		s, _, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if s.Rules == nil {
			t.Fatalf("%s: rules nil", in)
		}
		b, _ := json.Marshal(s)
		if !strings.Contains(string(b), `"rules":[]`) {
			t.Fatalf("%s: %s", in, b)
		}
	}
}

func TestExactWebDefault(t *testing.T) {
	_, set, err := Parse([]byte(`{"defaultAction":"direct","rules":[]}`))
	if err != nil || !set.ExactWeb {
		t.Fatalf("default must be on: %v %v", set, err)
	}
	_, set, err = Parse([]byte(`{"defaultAction":"direct","rules":[],"exactWebDomains":false}`))
	if err != nil || set.ExactWeb {
		t.Fatalf("off: %v", err)
	}
}

// TestEngineOptionsCoverSettings: every field of Settings outside the
// embedded rules.Config is an engine option, with the same type and JSON
// key, and Options/SetOptions copy all of them. A new option that is
// missing here would be dropped by one of the two save paths.
func TestEngineOptionsCoverSettings(t *testing.T) {
	st := reflect.TypeOf(Settings{})
	ot := reflect.TypeOf(EngineOptions{})
	n := 0
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if f.Anonymous && f.Type == reflect.TypeOf(rules.Config{}) {
			continue
		}
		n++
		o, ok := ot.FieldByName(f.Name)
		if !ok {
			t.Errorf("EngineOptions lacks %s", f.Name)
			continue
		}
		if o.Type != f.Type || o.Tag.Get("json") != f.Tag.Get("json") {
			t.Errorf("%s: %v %q, want %v %q", f.Name, o.Type, o.Tag.Get("json"), f.Type, f.Tag.Get("json"))
		}
	}
	if n != ot.NumField() {
		t.Errorf("EngineOptions has %d fields, Settings %d options", ot.NumField(), n)
	}

	// Every option set to a non-zero value survives Options -> SetOptions,
	// and the rules part is not touched.
	var s Settings
	v := reflect.ValueOf(&s).Elem()
	for i := 0; i < v.NumField(); i++ {
		if st.Field(i).Anonymous {
			continue
		}
		switch f := v.Field(i); f.Kind() {
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Int:
			f.SetInt(int64(100 + i))
		default:
			t.Fatalf("%s: unexpected kind %v", st.Field(i).Name, f.Kind())
		}
	}
	s.DefaultAction = rules.Tunnel
	s.Rules = []rules.Rule{{Name: "x", Domains: []string{"a.com"}, Action: rules.Block}}
	var got Settings
	got.SetOptions(s.Options())
	if got.Options() != s.Options() {
		t.Fatalf("round trip: %+v != %+v", got.Options(), s.Options())
	}
	gv := reflect.ValueOf(got)
	for i := 0; i < gv.NumField(); i++ {
		if st.Field(i).Anonymous {
			continue
		}
		if !reflect.DeepEqual(gv.Field(i).Interface(), v.Field(i).Interface()) {
			t.Errorf("%s not copied", st.Field(i).Name)
		}
	}
	if got.DefaultAction != rules.Direct || got.Rules != nil {
		t.Fatalf("SetOptions touched the rules: %+v", got.Config)
	}
	// Same JSON as the options part of settings.json.
	a, _ := json.Marshal(s.Options())
	s.Config = rules.Config{}
	b, _ := json.Marshal(s)
	var am, bm map[string]any
	json.Unmarshal(a, &am)
	json.Unmarshal(b, &bm)
	for k := range bm {
		if _, ok := am[k]; !ok && k != "defaultAction" && k != "rules" {
			t.Errorf("settings key %q is not in EngineOptions", k)
		}
	}
	if len(am) == 0 {
		t.Fatal("empty options JSON")
	}
}

// ports: settings.json with port rules.
func TestParsePorts(t *testing.T) {
	for _, ports := range []string{`["443"]`, `[443]`, `[443, "8000-8100"]`} {
		st, set, err := Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"x","ports":` + ports + `,"action":"tunnel"}]}`))
		if err != nil || set == nil || len(st.Rules[0].Ports) == 0 {
			t.Fatalf("%s: %v", ports, err)
		}
	}
	for _, rule := range []string{
		`{"name":"SSH","ports":["0"],"action":"direct"}`,
		`{"name":"SSH","enabled":false,"ports":["0"],"action":"direct"}`,
	} {
		if _, _, err := Parse([]byte(`{"defaultAction":"direct","rules":[` + rule + `]}`)); err == nil || !strings.Contains(err.Error(), "SSH: неверный порт") {
			t.Errorf("%s: %v", rule, err)
		}
	}
	if _, _, err := Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"x","ports":{},"action":"direct"}]}`)); err == nil || !strings.Contains(err.Error(), "ports") {
		t.Errorf("object: %v", err)
	}
}

// A settings.json written by v1.2.0: ports are a string. It loads, the
// rules match as there, and it is written back in the same string form, so
// v1.2.0 still reads it after a downgrade.
func TestParsePortsV120(t *testing.T) {
	const v120 = `{
  "defaultAction": "direct",
  "rules": [
    {"name": "Игра", "apps": [{"pattern": "game.exe"}], "protocol": "udp", "ports": "80,443,27000-27200", "action": "tunnel"},
    {"name": "DNS", "ports": "53", "action": "block"},
    {"name": "SMB", "apps": [{"pattern": "*"}], "ports": "445", "action": "block"},
    {"name": "Веб", "domains": [".example.com"], "protocol": "tcp", "action": "tunnel"},
    {"name": "Sep", "apps": [{"pattern": "chrome.exe"}], "ports": " , ;", "action": "tunnel"}
  ]
}`
	st, set, err := Parse([]byte(v120))
	if err != nil || set == nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.Rules[0].Ports, rules.PortList{"80", "443", "27000-27200"}) || !slices.Equal(st.Rules[1].Ports, rules.PortList{"53"}) || st.Rules[3].Ports != nil || st.Rules[4].Ports != nil {
		t.Fatalf("%q %q %q %q", st.Rules[0].Ports, st.Rules[1].Ports, st.Rules[3].Ports, st.Rules[4].Ports)
	}
	game := &procinfo.Info{PID: 1, Path: `C:\Games\game.exe`, Name: "game.exe"}
	chrome := &procinfo.Info{PID: 2, Path: `C:\Chrome\chrome.exe`, Name: "chrome.exe"}
	for _, c := range []struct {
		sub  rules.Subject
		want string
	}{
		{rules.Subject{Proc: game, Proto: 17, Dst: netip.MustParseAddrPort("203.0.113.5:27015")}, "Игра"},
		{rules.Subject{Proc: game, Proto: 17, Dst: netip.MustParseAddrPort("203.0.113.5:27201")}, "default"},
		{rules.Subject{Proto: 17, Dst: netip.MustParseAddrPort("8.8.8.8:53")}, "DNS"},
		// Separators only: v1.2.0 read no ports, any port (PITFALLS #10
		// is refused on input only).
		{rules.Subject{Proc: chrome, Proto: 6, Dst: netip.MustParseAddrPort("203.0.113.5:12345")}, "Sep"},
	} {
		if got := set.Evaluate(c.sub, nil).Rule; got != c.want {
			t.Errorf("%v: %s, want %s", c.sub.Dst, got, c.want)
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ports":"80,443,27000-27200"`, `"ports":"53"`, `"ports":"445"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s not in %s", want, b)
		}
	}
	if strings.Count(string(b), `"ports"`) != 3 {
		t.Errorf("a rule without ports gained the key: %s", b)
	}
	// As in v1.2.0: separators only with nothing else to match fails; more
	// port items than the editor takes load.
	if _, _, err := Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"P","ports":",","action":"block"}]}`)); err == nil || !strings.Contains(err.Error(), "P: укажите программу, сайт или порт") {
		t.Errorf("separators only, no other condition: %v", err)
	}
	many := make([]string, rules.MaxPortItems+50)
	for i := range many {
		many[i] = fmt.Sprint(1000 + 2*i)
	}
	st, set, err = Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"M","apps":[{"pattern":"m.exe"}],"ports":"` + strings.Join(many, ",") + `","action":"block"}]}`))
	if err != nil || len(st.Rules[0].Ports) != len(many) {
		t.Fatal(err)
	}
	m := &procinfo.Info{PID: 3, Path: `C:\m.exe`, Name: "m.exe"}
	if got := set.Evaluate(rules.Subject{Proc: m, Proto: 6, Dst: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), uint16(1000+2*(len(many)-1)))}, nil).Rule; got != "M" {
		t.Errorf("last of many: %s", got)
	}
}
