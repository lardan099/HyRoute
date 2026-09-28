package rules

// Ports: destination ports of a rule ("443", "8000-8100"). The list is an
// OR; with the other conditions of a rule it combines by AND. Port 0 means
// unknown and never matches a port condition.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// PortRange is an inclusive range of destination ports, 1 <= Lo <= Hi.
type PortRange struct{ Lo, Hi uint16 }

// MaxPortItems bounds the port list of one rule.
const MaxPortItems = 256

// PortList is Rule.Ports: items "N" or "N-M". It decodes the v1.2.0
// string form ("80,443,27000-27200"), a JSON array of strings and/or
// integers, or null into raw items; validation is compileRule's. It
// encodes as the v1.2.0 string form, so settings.json stays readable by
// v1.2.0 (MarshalJSON).
type PortList []string

var errPortsJSON = errors.New(`ports: ожидается список портов, например "443" или "80,443,8000-8100"`)

// UnmarshalJSON collects the raw items: from a JSON string, its list split
// as people type it (splitPortText); from an array, a string element as is
// and a number made of digits only as its text. Anything else is an error.
// The item count is checked, with the rule name, by compilePorts; memory
// is bounded by the input like every other list in settings.json.
func (p *PortList) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*p = nil
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return errPortsJSON
		}
		items := splitPortText(s)
		if len(items) == 0 && strings.TrimSpace(s) != "" {
			// Separators only (","): one invalid item, never an empty
			// list (= any port); compileRule rejects it.
			items = []string{strings.TrimSpace(s)}
		}
		*p = items
		return nil
	}
	var raw []json.RawMessage
	if len(b) == 0 || b[0] != '[' || json.Unmarshal(b, &raw) != nil {
		return errPortsJSON
	}
	out := make(PortList, 0, len(raw))
	for _, e := range raw {
		switch {
		case len(e) > 0 && e[0] == '"':
			var s string
			if json.Unmarshal(e, &s) != nil {
				return errPortsJSON
			}
			out = append(out, s)
		case len(e) > 0 && strings.Trim(string(e), "0123456789") == "":
			out = append(out, string(e))
		default:
			return errPortsJSON
		}
	}
	*p = out
	return nil
}

// MarshalJSON writes the v1.2.0 string form: canonical items joined by
// commas ("80,443,27000-27200"), or the raw items so joined when one is
// invalid (compileRule reports it on the next load). An empty list is
// omitted by omitempty before this runs.
func (p PortList) MarshalJSON() ([]byte, error) {
	items, err := CanonPorts(p)
	if err != nil {
		items = p
	}
	return json.Marshal(strings.Join(items, ","))
}

// splitPortText splits a port list typed by people or stored by v1.2.0
// into raw items: spaced ranges are one item, items are separated by
// commas, semicolons and/or whitespace.
func splitPortText(s string) []string {
	return strings.FieldsFunc(dashes.ReplaceAllString(s, "-"), func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
}

// errNoPorts: a list made of separators only («порт ,») names no port. It
// must not become an empty list, which means any port.
var errNoPorts = errors.New("не указан ни один порт: например, 443 или 80, 443")

// dashes matches a range dash with the spaces around it: "8000 – 8100" is
// one item. The spaces are exactly unicode.IsSpace, as the list split.
var dashes = regexp.MustCompile(`[\s\v\x{85}\p{Z}]*[-–—][\s\v\x{85}\p{Z}]*`)

// ParsePortItem parses "443", " 443 ", "8000-8100", "8000 – 8100" (en/em
// dash, spaces around the dash allowed).
func ParsePortItem(s string) (PortRange, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return PortRange{}, errors.New("пустой порт в списке")
	}
	t = dashes.ReplaceAllString(t, "-")
	bad := fmt.Errorf("неверный порт «%s»: нужно число от 1 до 65535 или диапазон, например 8000-8100", echoItem(strings.TrimSpace(s)))
	lo, hi, isRange := strings.Cut(t, "-")
	a, ok := portNumber(lo)
	if !ok {
		return PortRange{}, bad
	}
	if !isRange {
		return PortRange{a, a}, nil
	}
	b, ok := portNumber(hi)
	if !ok {
		return PortRange{}, bad
	}
	if a > b {
		return PortRange{}, fmt.Errorf("диапазон «%s» наоборот: меньший порт пишется первым, например 8000-8100", echoItem(strings.TrimSpace(s)))
	}
	return PortRange{a, b}, nil
}

// portNumber is strconv.ParseUint(s, 10, 16) without 0: no sign, no base
// prefix, no exponent.
func portNumber(s string) (uint16, bool) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err == nil && n != 0
}

// echoItem is an item for an error message: at most 24 characters, with
// line breaks and other control characters replaced.
func echoItem(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 24 {
		return string([]rune(s)[:24]) + "…"
	}
	return s
}

var errTooManyPorts = fmt.Errorf("слишком много портов в правиле (больше %d): объедините их в диапазоны", MaxPortItems)

// ParsePortList parses a list typed by people: spaced ranges become one
// item, then items are split by commas, semicolons and/or whitespace.
// Returns canonical items (order kept, duplicates removed); empty input
// gives nil.
func ParsePortList(s string) ([]string, error) {
	items := splitPortText(s)
	if len(items) == 0 && strings.TrimSpace(s) != "" {
		return nil, errNoPorts
	}
	return CanonPorts(items)
}

// CanonPorts validates stored items and returns them canonical (as
// ParsePortList). The single canonicaliser: rules text export, the ACL
// converter, rule labels.
func CanonPorts(items []string) ([]string, error) {
	if len(items) > MaxPortItems {
		return nil, errTooManyPorts
	}
	var out []string
	for _, it := range items {
		pr, err := ParsePortItem(it)
		if err != nil {
			return nil, err
		}
		if c := pr.String(); !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// FormatPorts joins canonical items for people: "80, 443, 8000-8100".
func FormatPorts(items []string) string { return strings.Join(items, ", ") }

// RuleLabel names rule i for people: its name, else «TCP 22» for a rule
// with ports only, else «правило N» (as errors, Explain and the log).
func RuleLabel(i int, r Rule) string { return ruleName(i, r) }

// PortsLabel is the label of a rule by protocol and ports, as the UI's
// portsText: "TCP", "TCP 22", "UDP 50000-65535", "порт 443", "порты 80,
// 443". "" when neither is set or the items are invalid.
func PortsLabel(proto string, items []string) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "any" {
		proto = ""
	}
	ports, err := CanonPorts(items)
	switch {
	case err != nil:
		return ""
	case len(ports) > 0 && proto != "":
		return strings.ToUpper(proto) + " " + FormatPorts(ports)
	case len(ports) > 0:
		return PortWord(ports) + " " + FormatPorts(ports)
	}
	return strings.ToUpper(proto)
}

// PortWord is "порт" for one single port, else "порты" (items as written:
// "8000-8100" is several ports).
func PortWord(items []string) string {
	if len(items) == 1 && !strings.Contains(items[0], "-") {
		return "порт"
	}
	return "порты"
}

// SamePorts reports whether two port lists cover exactly the same ports,
// compared as merged ranges ("80,81-90" == "80-90", order and repeats
// ignored). Empty == empty (any port); empty != [1-65535], which differ on
// port 0 (unknown). An invalid list equals nothing.
func SamePorts(a, b []string) bool {
	ra, err1 := compilePorts(a)
	rb, err2 := compilePorts(b)
	return err1 == nil && err2 == nil && slices.Equal(ra, rb)
}

// compilePorts validates items and returns sorted, merged ranges (adjacent
// ranges merge: 80, 81-90 -> 80-90). nil for an empty list (any port).
func compilePorts(items []string) ([]PortRange, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > MaxPortItems {
		return nil, errTooManyPorts
	}
	rs := make([]PortRange, 0, len(items))
	for _, it := range items {
		pr, err := ParsePortItem(it)
		if err != nil {
			return nil, err
		}
		rs = append(rs, pr)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Lo < rs[j].Lo || rs[i].Lo == rs[j].Lo && rs[i].Hi < rs[j].Hi })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if int(r.Lo) <= int(last.Hi)+1 {
			last.Hi = max(last.Hi, r.Hi)
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out), nil
}

// matchPort reports whether p is in the sorted, merged ranges. Port 0
// (unknown) never matches.
func matchPort(rs []PortRange, p uint16) bool {
	if p == 0 {
		return false
	}
	i := sort.Search(len(rs), func(i int) bool { return rs[i].Hi >= p })
	return i < len(rs) && rs[i].Lo <= p
}

// portsCover reports whether every port of b is in a. An empty a is any
// port; an empty b means every port: covered only by a = [1-65535] (or an
// empty a).
func portsCover(a, b []PortRange) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return fullPorts(a)
	}
	for _, r := range b {
		i := sort.Search(len(a), func(i int) bool { return a[i].Hi >= r.Lo })
		if i == len(a) || a[i].Lo > r.Lo || a[i].Hi < r.Hi {
			return false
		}
	}
	return true
}

// portsOverlap reports whether some port is in both a and b; an empty side
// means every port (overlaps anything).
func portsOverlap(a, b []PortRange) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for i, j := 0, 0; i < len(a) && j < len(b); {
		if a[i].Lo <= b[j].Hi && b[j].Lo <= a[i].Hi {
			return true
		}
		if a[i].Hi < b[j].Hi {
			i++
		} else {
			j++
		}
	}
	return false
}

// fullPorts reports rs == [{1, 65535}].
func fullPorts(rs []PortRange) bool {
	return len(rs) == 1 && rs[0] == PortRange{1, 65535}
}

// String is the canonical item: "443" or "8000-8100".
func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return strconv.Itoa(int(r.Lo)) + "-" + strconv.Itoa(int(r.Hi))
}

// formatRanges writes compiled ranges for people: "80, 443, 8000-8100".
func formatRanges(rs []PortRange) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.String()
	}
	return FormatPorts(parts)
}

// portWordGen is "порта" for one single port, else "портов" (explain
// reasons: "только для порта 22").
func portWordGen(rs []PortRange) string {
	if len(rs) == 1 && rs[0].Lo == rs[0].Hi {
		return "порта"
	}
	return "портов"
}

// explainPort is the port step of an explanation (a rule with ports).
func (r *compiled) explainPort(port uint16) (bool, string) {
	list := formatRanges(r.ports)
	switch {
	case port == 0:
		return false, "порт не указан, а правило только для " + portWordGen(r.ports) + " " + list
	case !matchPort(r.ports, port):
		return false, fmt.Sprintf("порт %d не из списка правила: %s", port, list)
	}
	return true, fmt.Sprintf("порт %d", port)
}

// quicBlock finishes the explanation of a UDP/443 query decided without a
// name (Query.QUICNameless), as applyUDP decides: Evaluate without names,
// and NeedsDomain drops the flow. The winner is then the synthetic step
// StepQUICBlock. crs/errs are Explain's compiled rules. The destination
// keeps the port when the address is unknown, so port rules are judged
// as in the trace.
func (ex *Explanation) quicBlock(c Config, main string, crs []compiled, errs []error, proc *procinfo.Info, q Query, hadName bool) {
	s := &Set{def: c.DefaultAction, defProfile: c.DefaultProfile, defFallback: c.DefaultFallback, Main: main}
	for i := range crs {
		if errs[i] == nil && enabled(c.Rules[i]) {
			s.rules = append(s.rules, crs[i])
		}
	}
	dst := netip.AddrPortFrom(q.IP.Unmap(), q.Port)
	if !s.Evaluate(Subject{Proc: proc, Proto: 17, Dst: dst}, nil).NeedsDomain {
		if hadName {
			ex.Notes = append(ex.Notes, "В QUIC (UDP 443) HyRoute не видит имя сайта: правила по сайтам здесь не срабатывают, ответ дан без имени.")
		}
		return
	}
	for i := range ex.Steps {
		if ex.Steps[i].Winner {
			ex.Steps[i].Winner = false
			ex.Steps[i].Reason += "; но без имени сайта маршрут не определить"
		}
	}
	ex.Winner = Step{Index: StepQUICBlock, Name: "блокировка QUIC", Enabled: true, Matched: true, Winner: true,
		Action: Block, Reason: "маршрут зависит от имени сайта, а в QUIC оно не видно"}
	ex.Steps = append([]Step{ex.Winner}, ex.Steps...)
	ex.Notes = append(ex.Notes, "В QUIC (UDP 443) HyRoute не видит имя сайта: такое соединение блокируется, и браузер переходит на TCP. Проверьте TCP 443 — там сайт определяется по SNI.")
}

// portIssues are the Lint hints of an enabled rule with ports:
//   - info: without a program, a UDP (or any-protocol) range touching the
//     ephemeral ports 49152-65535 also catches the replies of local UDP
//     servers to their remote clients;
//   - warn: a site by name limited to UDP 443 never matches with the
//     default QUIC settings (no name in QUIC).
func (r *compiled) portIssues(i int, o LintOptions) []Issue {
	var out []Issue
	if !r.hasApp() && len(r.ports) > 0 && r.proto != 6 && r.ports[len(r.ports)-1].Hi >= 49152 {
		out = append(out, Issue{Index: i, Severity: "info", Text: "Правило по порту без программы действует и на ответы локальных UDP-серверов (игры, WireGuard, торренты). Для портов 49152–65535 лучше указать программу."})
	}
	if o.QUICNameless && r.proto == 17 && matchPort(r.ports, 443) && r.hasDom() {
		out = append(out, Issue{Index: i, Severity: "warn", Text: "Сайты по имени в UDP 443 (QUIC) не определяются: такое соединение блокируется, и браузер переходит на TCP. Укажите программу вместо сайта или уберите UDP."})
	}
	return out
}
