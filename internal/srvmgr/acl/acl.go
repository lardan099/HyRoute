// Package acl reads and writes the routing rules of a Hysteria server
// (acl.inline, or the text of an acl.file) for the rule editor: typed
// rules that turn back into the very same text while nothing changed,
// the checks Hysteria's own compiler makes (third_party/hysteria-acl) and
// lint for what it accepts but probably does not mean.
//
// Hysteria ignores everything after "#" on a line. HyRoute keeps its own
// marks there: "#~group <name>" starts a group of rules, "#~off <rule>"
// is a disabled rule.
package acl

import (
	"strings"

	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
)

const (
	groupMark = "#~group"
	offMark   = "#~off "
)

// Rule is one rule: outbound(address[, proto/port[, hijack]]).
type Rule struct {
	// Outbound is the name of an outbound of the config or a built-in
	// one (direct, reject, default); Hysteria ignores its case.
	Outbound string `json:"outbound"`
	// Address as written: all or *, an IP, a CIDR, a domain, a wildcard
	// (*.example.com), suffix:<domain>, geoip:<code>,
	// geosite:<name>[@attr...].
	Address string `json:"address"`
	// Proto is tcp, udp or "" (both).
	Proto string `json:"proto,omitempty"`
	// Port is a port, a range lo-hi or "" (every port).
	Port string `json:"port,omitempty"`
	// Hijack is the IP the connection goes to instead.
	Hijack  string `json:"hijack,omitempty"`
	Comment string `json:"comment,omitempty"`
	Group   string `json:"group,omitempty"`
	// Off keeps the rule as a comment: Hysteria does not see it.
	Off bool `json:"off,omitempty"`
	// Text is the line as read. It is written back while the fields
	// above say the same; "" is a new rule. A line Hysteria cannot read
	// has only Text.
	Text string `json:"text,omitempty"`
	// Before are the comment and blank lines above the rule: they move
	// with it.
	Before []string `json:"before,omitempty"`
}

// Bad: the line is not a rule Hysteria can read.
func (r Rule) Bad() bool { return r.Outbound == "" && r.Address == "" && r.Text != "" }

// Document is a whole ACL.
type Document struct {
	Rules []Rule `json:"rules"`
	// Tail are the comment and blank lines after the last rule.
	Tail []string `json:"tail,omitempty"`
}

// Parse reads the text of an ACL: the lines of acl.inline joined with
// "\n", or an acl.file. Text() of the result is text again.
func Parse(text string) Document {
	var d Document
	var pending []string
	group := ""
	for _, line := range strings.Split(text, "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.TrimSpace(code) != "" {
			r, ok := parseLine(line)
			if !ok {
				r = Rule{}
			}
			r.Text, r.Group, r.Before, pending = line, group, pending, nil
			d.Rules = append(d.Rules, r)
			continue
		}
		if name, ok := groupHeader(line); ok {
			group = name
			pending = append(pending, line)
			continue
		}
		if r, ok := readRule(line); ok && r.Off {
			r.Text, r.Group, r.Before, pending = line, group, pending, nil
			d.Rules = append(d.Rules, r)
			continue
		}
		pending = append(pending, line)
	}
	d.Tail = pending
	return d
}

// ParseInline reads acl.inline. A YAML entry with line breaks is several
// lines for Hysteria too.
func ParseInline(lines []string) Document { return Parse(strings.Join(lines, "\n")) }

// Text is the ACL as Hysteria reads it.
func (d Document) Text() string {
	lines, _ := d.render()
	return strings.Join(lines, "\n")
}

// Inline is the ACL as acl.inline (nil: no ACL).
func (d Document) Inline() []string {
	t := d.Text()
	if t == "" {
		return nil
	}
	return strings.Split(t, "\n")
}

// render returns the lines and the line index of every rule.
func (d Document) render() (out []string, at []int) {
	group := ""
	for _, r := range d.Rules {
		before := r.Before
		if after := groupAfter(before, group); after != r.Group {
			before = withoutHeaders(before)
			if r.Group != group {
				out = append(out, header(r.Group))
			}
		}
		group = r.Group
		out = append(out, before...)
		at = append(at, len(out))
		out = append(out, r.line())
	}
	return append(out, d.Tail...), at
}

// line is the rule's line: Text while the fields say the same.
func (r Rule) line() string {
	if r.Bad() {
		return r.Text
	}
	if r.Text != "" {
		if was, ok := readRule(r.Text); ok && same(was, r) {
			return r.Text
		}
	}
	args := r.Address
	pp := joinProtoPort(r.Proto, r.Port)
	if pp != "" || r.Hijack != "" {
		if pp == "" {
			pp = "*"
		}
		args += ", " + pp
	}
	if r.Hijack != "" {
		args += ", " + r.Hijack
	}
	s := r.Outbound + "(" + args + ")"
	if r.Comment != "" {
		s += " # " + r.Comment
	}
	if r.Off {
		s = offMark + s
	}
	return s
}

// same: a and b are the same rule (where it is and what is around it
// aside).
func same(a, b Rule) bool {
	return a.Outbound == b.Outbound && a.Address == b.Address && a.Proto == b.Proto && a.Port == b.Port &&
		a.Hijack == b.Hijack && a.Comment == b.Comment && a.Off == b.Off
}

// readRule reads a rule line or a disabled rule.
func readRule(line string) (Rule, bool) {
	if rest, ok := strings.CutPrefix(strings.TrimSpace(line), offMark); ok {
		r, ok := parseLine(rest)
		r.Off = true
		return r, ok
	}
	return parseLine(line)
}

// parseLine reads code and an optional "# comment" with Hysteria's own
// parser.
func parseLine(line string) (Rule, bool) {
	code, comment, _ := strings.Cut(line, "#")
	code = strings.TrimSpace(code)
	if code == "" {
		return Rule{}, false
	}
	trs, err := hacl.ParseTextRules(code)
	if err != nil || len(trs) != 1 {
		return Rule{}, false
	}
	tr := trs[0]
	r := Rule{Outbound: tr.Outbound, Address: tr.Address, Hijack: tr.HijackAddress, Comment: strings.TrimSpace(comment)}
	r.Proto, r.Port = splitProtoPort(tr.ProtoPort)
	return r, true
}

// splitProtoPort splits proto/port as Hysteria reads it; what it would
// refuse is kept for the check to report.
func splitProtoPort(pp string) (proto, port string) {
	pp = strings.ToLower(pp)
	proto, port, _ = strings.Cut(pp, "/")
	if proto == "*" {
		proto = ""
	}
	if port == "*" {
		port = ""
	}
	return proto, port
}

func joinProtoPort(proto, port string) string {
	switch {
	case port == "":
		return proto
	case proto == "":
		return "*/" + port
	}
	return proto + "/" + port
}

// groupHeader reads a "#~group <name>" line.
func groupHeader(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == groupMark {
		return "", true
	}
	if rest, ok := strings.CutPrefix(t, groupMark+" "); ok {
		return strings.TrimSpace(rest), true
	}
	return "", false
}

func header(group string) string {
	if group == "" {
		return groupMark
	}
	return groupMark + " " + group
}

// groupAfter is the group after the headers among lines, from group.
func groupAfter(lines []string, group string) string {
	for _, l := range lines {
		if name, ok := groupHeader(l); ok {
			group = name
		}
	}
	return group
}

func withoutHeaders(lines []string) []string {
	var out []string
	for _, l := range lines {
		if _, ok := groupHeader(l); !ok {
			out = append(out, l)
		}
	}
	return out
}
