package acl

import (
	"slices"
	"strings"
	"testing"
)

// A line break in a field, or a line around rules that is no comment,
// would put a rule nobody checked into the ACL.
func TestNoUncheckedLines(t *testing.T) {
	for name, d := range map[string]Document{
		"comment": {Rules: []Rule{{Outbound: "direct", Address: "all", Comment: "x\nreject(all)"}}},
		"address": {Rules: []Rule{{Outbound: "direct", Address: "all)\nreject(all"}}},
		"before":  {Rules: []Rule{{Outbound: "direct", Address: "all", Before: []string{"reject(all)"}}}},
		"tail":    {Rules: []Rule{{Outbound: "direct", Address: "all"}}, Tail: []string{"garbage"}},
	} {
		if !slices.ContainsFunc(Check(d, Env{}), func(p Problem) bool { return p.Level == Error }) {
			t.Errorf("%s: no error, inline %q", name, d.Inline())
		}
	}
	// Comments, blank lines and a CRLF file's \r are fine.
	d := Document{Rules: []Rule{{Outbound: "direct", Address: "all", Before: []string{"# c\r", "", "  #~group A"}}}, Tail: []string{"\r", "# end"}}
	for _, p := range Check(d, Env{}) {
		if p.Code == "line" || p.Code == "chars" {
			t.Errorf("%+v", p)
		}
	}
}

// An outbound of the config named like a built-in one is that one.
func TestBuiltinOverridden(t *testing.T) {
	d := Parse("reject(suffix:ru)\nproxy(all, udp)")
	env := Env{Outbounds: []string{"cascade", "Default", "reject", "proxy"}}
	v, err := Match(d, env, Request{Host: "a.com", Port: 443})
	if err != nil || v.Rule != -1 || v.Outbound != "Default" || v.Builtin {
		t.Fatalf("%+v %v", v, err)
	}
	v, _ = Match(d, env, Request{Host: "ya.ru", Port: 443})
	if v.Outbound != "reject" || v.Builtin || strings.Contains(v.Reason, "отклоняется") {
		t.Fatalf("%+v", v)
	}
	// Without rules Hysteria takes the first outbound.
	if v, _ := Match(Document{}, env, Request{Host: "a.com", Port: 1}); v.Outbound != "cascade" {
		t.Fatalf("%+v", v)
	}
	// A config outbound named direct changes where direct rules go.
	ch, err := DryRun(Parse("direct(suffix:ru)"), Parse("direct(suffix:ru)"), Env{}, Env{Outbounds: []string{"direct"}}, nil)
	if err != nil || len(ch) == 0 {
		t.Fatalf("%v %+v", err, ch)
	}
}
