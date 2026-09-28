package rules

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The reference table of the TS twin parsePorts (api.ts) too.
func TestParsePortItem(t *testing.T) {
	for in, want := range map[string]PortRange{
		"443": {443, 443}, " 443 ": {443, 443}, "0443": {443, 443}, "000443": {443, 443},
		"8000-8100": {8000, 8100}, "8000–8100": {8000, 8100}, "8000 - 8100": {8000, 8100}, "8000 — 8100": {8000, 8100},
		"1-65535": {1, 65535}, "443-443": {443, 443},
	} {
		if got, err := ParsePortItem(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "65536", "-1", "+443", "0x1bb", "1e3", "443-", "-443", "abc", "1-2-3",
		"99999999999999999999", "0-5", "4 43", "1_000"} {
		if _, err := ParsePortItem(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
	if _, err := ParsePortItem("100-50"); err == nil || !strings.Contains(err.Error(), "наоборот") {
		t.Errorf("reversed: %v", err)
	}
	if _, err := ParsePortItem("65536"); err == nil || !strings.Contains(err.Error(), "неверный порт «65536»: нужно число от 1 до 65535") {
		t.Errorf("message: %v", err)
	}
	// A long item is echoed cut to 24 characters.
	_, err := ParsePortItem(strings.Repeat("ж", 100))
	if err == nil || !strings.Contains(err.Error(), "«"+strings.Repeat("ж", 24)+"…»") {
		t.Errorf("long: %v", err)
	}
	if _, err := ParsePortItem("1\n* -> vpn"); err == nil || strings.Contains(err.Error(), "\n") {
		t.Errorf("control characters echoed: %q", err)
	}
}

func TestParsePortList(t *testing.T) {
	for in, want := range map[string][]string{
		"":                       nil,
		"  ":                     nil,
		"80, 443;8000-8100":      {"80", "443", "8000-8100"},
		"80 443\t22":             {"80", "443", "22"},
		"443, 80, 443, 0443":     {"443", "80"},
		"8000 - 8100":            {"8000-8100"},
		"27000 – 27100":          {"27000-27100"},
		"1—2":                    {"1-2"},
		"80, 8000 - 8100 , 9000": {"80", "8000-8100", "9000"},
	} {
		got, err := ParsePortList(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	// Around a dash, the spaces are the split's (unicode.IsSpace, as the
	// UI's parsePorts): NBSP, ideographic space, NEL.
	nbsp, ideo, nel := string(rune(0xa0)), string(rune(0x3000)), string(rune(0x85))
	if got, err := ParsePortList("8000" + nbsp + "-" + ideo + "8100" + nel + "80"); err != nil || !slices.Equal(got, []string{"8000-8100", "80"}) {
		t.Errorf("unicode spaces: %q %v", got, err)
	}
	if _, err := ParsePortList("80, -443"); err == nil || !strings.Contains(err.Error(), "-443") {
		t.Errorf("-443: %v", err)
	}
	var many []string
	for i := 1; i <= MaxPortItems+1; i++ {
		many = append(many, fmt.Sprint(i))
	}
	if _, err := ParsePortList(strings.Join(many, ",")); err == nil || !strings.Contains(err.Error(), "слишком много портов") {
		t.Errorf("257: %v", err)
	}
	if got, err := ParsePortList(strings.Join(many[:MaxPortItems], ",")); err != nil || len(got) != MaxPortItems {
		t.Errorf("256: %d %v", len(got), err)
	}
}

func TestPortListJSON(t *testing.T) {
	for in, want := range map[string]PortList{
		`["443","8000-8100"]`: {"443", "8000-8100"},
		`[443, "80"]`:         {"443", "80"},
		`["0443"]`:            {"0443"}, // kept as written, validated by Compile
		`[""]`:                {""},
		`[]`:                  {},
		`null`:                nil,
		// The v1.2.0 string form, and lists typed by hand into it.
		`"80,443,27000-27200"`:   {"80", "443", "27000-27200"},
		`"80, 443; 8000 - 8100"`: {"80", "443", "8000-8100"},
		`""`:                     {},
		`","`:                    {","}, // not "any port": Compile rejects it
		`" ; "`:                  {";"},
	} {
		var p PortList
		if err := json.Unmarshal([]byte(in), &p); err != nil || !slices.Equal(p, want) || (p == nil) != (want == nil) {
			t.Errorf("%s: %q %v", in, p, err)
		}
	}
	for _, in := range []string{`443`, `{}`, `true`, `[1.5]`, `[-1]`, `[[1]]`, `[1e3]`, `[null]`, `[true]`} {
		var p PortList
		if err := json.Unmarshal([]byte(in), &p); err == nil || !strings.Contains(err.Error(), "ожидается список портов") {
			t.Errorf("%s: %q %v", in, p, err)
		}
	}
	// Inside a rule: the error names the field.
	var r Rule
	if err := json.Unmarshal([]byte(`{"name":"x","ports":{},"action":"direct"}`), &r); err == nil || !strings.Contains(err.Error(), "ports") {
		t.Errorf("rule: %v", err)
	}
	// Written in the v1.2.0 string form, canonical when the items are
	// valid, so v1.2.0 reads it back after a downgrade.
	for _, c := range []struct {
		in   PortList
		want string
	}{
		{PortList{"443", "8000-8100"}, `"ports":"443,8000-8100"`},
		{PortList{"0443", "8000 – 8100", "443"}, `"ports":"443,8000-8100"`},
		{PortList{"80", "x"}, `"ports":"80,x"`},
	} {
		b, _ := json.Marshal(Rule{Name: "x", Ports: c.in})
		if !strings.Contains(string(b), c.want) {
			t.Errorf("marshal %q: %s", c.in, b)
		}
		var back Rule
		if err := json.Unmarshal(b, &back); err != nil || !SamePorts(back.Ports, c.in) && c.in[1] != "x" {
			t.Errorf("round trip %q: %q %v", c.in, back.Ports, err)
		}
	}
}

// PITFALLS #10: a list of separators only is an error, never "any port".
func TestPortListSeparatorsOnly(t *testing.T) {
	for _, in := range []string{",", ";", " , ", ",;"} {
		if _, err := ParsePortList(in); err == nil || !strings.Contains(err.Error(), "не указан ни один порт") {
			t.Errorf("%q: %v", in, err)
		}
		var r Rule
		if err := json.Unmarshal([]byte(`{"name":"x","apps":[{"pattern":"ssh.exe"}],"ports":`+fmt.Sprintf("%q", in)+`,"action":"block"}`), &r); err != nil {
			t.Fatal(err)
		}
		if _, err := Compile(Config{DefaultAction: Direct, Rules: []Rule{r}}); err == nil || !strings.Contains(err.Error(), "x: неверный порт") {
			t.Errorf("compile %q: %v", in, err)
		}
	}
}

func TestSamePorts(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want bool
	}{
		{[]string{"80", "81-90"}, []string{"80-90"}, true},
		{[]string{"443", "80", "443"}, []string{"80", "443"}, true},
		{nil, []string{}, true},
		{nil, []string{"1-65535"}, false},
		{[]string{"80"}, []string{"81"}, false},
		{[]string{"0"}, []string{"0"}, false},
		{[]string{"80"}, []string{"80", "x"}, false},
	} {
		if got := SamePorts(c.a, c.b); got != c.want {
			t.Errorf("%q %q: %v", c.a, c.b, got)
		}
	}
}

func TestPortsLabel(t *testing.T) {
	for _, c := range []struct {
		proto string
		items []string
		want  string
	}{
		{"tcp", []string{"22"}, "TCP 22"},
		{"", []string{"443"}, "порт 443"},
		{"", []string{"80", "443"}, "порты 80, 443"},
		{"any", []string{"8000-8100"}, "порты 8000-8100"},
		{"udp", []string{"50000-65535"}, "UDP 50000-65535"},
		{"udp", nil, "UDP"},
		{"", []string{"0"}, ""},
		{"tcp", []string{"0443", " 80"}, "TCP 443, 80"},
		{"", nil, ""},
	} {
		if got := PortsLabel(c.proto, c.items); got != c.want {
			t.Errorf("%q %q: %q", c.proto, c.items, got)
		}
	}
}

func ranges(t *testing.T, items ...string) []PortRange {
	t.Helper()
	rs, err := compilePorts(items)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCompilePorts(t *testing.T) {
	if got := ranges(t, "443", "80", "81-90", "85"); !slices.Equal(got, []PortRange{{80, 90}, {443, 443}}) {
		t.Errorf("%v", got)
	}
	if got := ranges(t, "1-10", "5-20", "22", "21"); !slices.Equal(got, []PortRange{{1, 22}}) {
		t.Errorf("%v", got)
	}
	if got := ranges(t, "65535", "1-65534"); !fullPorts(got) {
		t.Errorf("%v", got)
	}
	if got := ranges(t); got != nil {
		t.Errorf("%v", got)
	}
	if _, err := compilePorts([]string{"80", ""}); err == nil || err.Error() != "пустой порт в списке" {
		t.Errorf("empty: %v", err)
	}
	if _, err := compilePorts(make([]string, MaxPortItems+1)); err == nil || !strings.Contains(err.Error(), "слишком много") {
		t.Errorf("many: %v", err)
	}
}

func TestMatchPort(t *testing.T) {
	rs := ranges(t, "80", "8000-8100", "65535")
	for p, want := range map[uint16]bool{0: false, 79: false, 80: true, 81: false, 7999: false, 8000: true, 8050: true, 8100: true, 8101: false, 65534: false, 65535: true} {
		if matchPort(rs, p) != want {
			t.Errorf("%d: %v", p, !want)
		}
	}
	if matchPort(ranges(t, "1-65535"), 0) {
		t.Error("port 0 matched")
	}
}

func TestPortsCoverOverlap(t *testing.T) {
	a := ranges(t, "1-1000", "2000-3000")
	for _, c := range []struct {
		b    []string
		want bool
	}{
		{[]string{"22"}, true},
		{[]string{"22", "2500-2600"}, true},
		{[]string{"900-2100"}, false}, // spans two ranges
		{[]string{"1001"}, false},
		{nil, false},
	} {
		if got := portsCover(a, ranges(t, c.b...)); got != c.want {
			t.Errorf("cover %q: %v", c.b, got)
		}
	}
	if !portsCover(ranges(t, "1-65535"), nil) || !portsCover(nil, ranges(t, "22")) {
		t.Error("full range / any port")
	}
	for _, c := range []struct {
		a, b []string
		want bool
	}{
		{[]string{"80-90"}, []string{"90-100"}, true},
		{[]string{"80-89"}, []string{"90"}, false},
		{[]string{"1", "10", "20"}, []string{"5", "15", "20"}, true},
		{[]string{"1", "10", "20"}, []string{"5", "15", "25"}, false},
		{nil, []string{"22"}, true},
		{[]string{"22"}, nil, true},
	} {
		if got := portsOverlap(ranges(t, c.a...), ranges(t, c.b...)); got != c.want {
			t.Errorf("overlap %q %q: %v", c.a, c.b, got)
		}
		if got := portsOverlap(ranges(t, c.b...), ranges(t, c.a...)); got != c.want {
			t.Errorf("overlap %q %q: %v", c.b, c.a, got)
		}
	}
}

func TestCanonPorts(t *testing.T) {
	if got, err := CanonPorts([]string{"0443", " 80", "8000 – 8100", "80"}); err != nil || !slices.Equal(got, []string{"443", "80", "8000-8100"}) {
		t.Errorf("%q %v", got, err)
	}
	if _, err := CanonPorts([]string{"80", "0"}); err == nil {
		t.Error("0 accepted")
	}
	if got := FormatPorts([]string{"80", "443", "8000-8100"}); got != "80, 443, 8000-8100" {
		t.Error(got)
	}
	if PortWord([]string{"443"}) != "порт" || PortWord([]string{"80", "443"}) != "порты" || PortWord([]string{"1-2"}) != "порты" {
		t.Error("PortWord")
	}
}
