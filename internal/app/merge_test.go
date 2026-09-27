package app

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
)

func p(name, host, auth string) hysteria.Profile {
	return hysteria.Profile{Name: name, Host: host, Ports: "443", Auth: auth}
}

func TestMergeSubscriptionKeepsIDs(t *testing.T) {
	n := 0
	newID := func() string { n++; return fmt.Sprintf("new%d", n) }
	src := "sub:s1"
	manual := hysteria.Profile{ID: "m", Name: "manual", Host: "m.example", Ports: "443"}
	list, st := mergeSubscription([]hysteria.Profile{manual}, src, []hysteria.Profile{
		p("DE #1", "de1.example", "a"), p("DE #2", "de2.example", "a"), p("NL", "nl.example", "a"), p("NL", "nl.example", "a"),
	}, func(string) bool { return false }, newID)
	if st.Added != 3 || len(list) != 4 || list[0].ID != "m" || list[1].Source != src {
		t.Fatalf("%+v %+v", st, list)
	}
	de1, de2, nl := list[1].ID, list[2].ID, list[3].ID

	// Next update: DE #2 renamed and reordered, DE #1 changed its password
	// (same host), NL gone (used by a rule), US new.
	list, st = mergeSubscription(list, src, []hysteria.Profile{
		p("US", "us.example", "a"), p("DE two", "de2.example", "a"), p("DE #1", "de1.example", "b"),
	}, func(id string) bool { return id == nl }, newID)
	if st.Added != 1 || st.Updated != 2 || st.MissingKept != 1 || st.Removed != 0 {
		t.Fatalf("%+v", st)
	}
	byName := map[string]hysteria.Profile{}
	for _, x := range list {
		byName[x.Name] = x
	}
	if byName["DE two"].ID != de2 || byName["DE #1"].ID != de1 || byName["DE #1"].Auth != "b" {
		t.Fatalf("IDs moved: %+v", list)
	}
	if x := byName["NL"]; x.ID != nl || !x.Missing {
		t.Fatalf("NL must be kept as missing: %+v", x)
	}
	if list[0].ID != "m" || len(list) != 5 {
		t.Fatalf("%+v", list)
	}
	// NL comes back: same ID, no longer missing. Unused missing ones go.
	list, st = mergeSubscription(list, src, []hysteria.Profile{p("NL", "nl.example", "a")}, func(string) bool { return false }, newID)
	if len(list) != 2 || list[1].ID != nl || list[1].Missing || st.Removed != 3 {
		t.Fatalf("%+v %+v", st, list)
	}
}

// Two servers on the same host with different ports are told apart.
func TestMergeSameHostDifferentPorts(t *testing.T) {
	n := 0
	newID := func() string { n++; return fmt.Sprintf("id%d", n) }
	a, b := p("A", "h.example", "x"), p("B", "h.example", "x")
	b.Ports = "8443"
	list, _ := mergeSubscription(nil, "sub:1", []hysteria.Profile{a, b}, func(string) bool { return false }, newID)
	a.Auth, b.Auth = "y", "y"
	list2, _ := mergeSubscription(list, "sub:1", []hysteria.Profile{b, a}, func(string) bool { return false }, newID)
	for _, x := range list2 {
		for _, y := range list {
			if x.Name == y.Name && x.ID != y.ID {
				t.Fatalf("%s changed ID", x.Name)
			}
		}
	}
}

// An update must not undo what the user set on a subscription server
// outside the share link, nor restart its Hysteria for nothing.
func TestMergeKeepsLocalSettings(t *testing.T) {
	src := "sub:s1"
	old := hysteria.Profile{ID: "x", Name: "NL", Host: "nl.example", Ports: "443,20000-30000", Auth: "a", Source: src,
		Obfs: hysteria.Obfs{Type: "salamander", Password: "pw"},
		TLS:  hysteria.TLS{SNI: "s.example", Insecure: true, PinSHA256: strings.Repeat("ab", 32), ECH: "e"}}
	// Every other field set, as if edited: a field added to Profile later
	// must either travel in the share link or be kept by keepLocal.
	fillZero(t, reflect.ValueOf(&old).Elem())
	old.PinServerIP, old.Missing = false, false // a parsed link has PinServerIP=true
	fresh, _, err := hysteria.ParseURI(old.URI())
	if err != nil {
		t.Fatal(err)
	}
	none := func(string) bool { return false }
	list, st := mergeSubscription([]hysteria.Profile{old}, src, []hysteria.Profile{fresh}, none, newID)
	if st.Updated != 1 || len(list) != 1 || list[0].ID != "x" || !hysteria.SameConnection(list[0], old) {
		t.Fatalf("%+v\nwant %+v", list, old)
	}
	// What the link carries still comes from the subscription.
	fresh.Auth = "b"
	list, _ = mergeSubscription(list, src, []hysteria.Profile{fresh}, none, newID)
	if x := list[0]; x.ID != "x" || x.Auth != "b" || x.Bandwidth != old.Bandwidth || x.Hop != old.Hop || x.PinServerIP {
		t.Fatalf("%+v", x)
	}
}

// fillZero sets every zero field of the struct v to a non-zero value.
func fillZero(t *testing.T, v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch {
		case f.Kind() == reflect.Struct:
			fillZero(t, f)
		case !f.IsZero():
		case f.Kind() == reflect.String:
			f.SetString("1s") // valid as a duration too
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		case f.CanInt():
			f.SetInt(1)
		case f.CanUint():
			f.SetUint(1)
		default:
			t.Fatalf("%s: unhandled kind %s", v.Type().Field(i).Name, f.Kind())
		}
	}
}
