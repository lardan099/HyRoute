package groups

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const validFile = `{
  "version": 1,
  "main": "grp-3fa1c2d4e5f6",
  "probe": { "url": "http://cp.cloudflare.com/generate_204", "intervalSec": 60 },
  "groups": [
    {
      "id": "grp-3fa1c2d4e5f6",
      "name": "Авто",
      "strategy": "latency",
      "members": ["a1b2c3d4e5f6", "0badc0ffee00", "9f8e7d6c5b4a"],
      "toleranceMs": 50,
      "switchAfterErrors": 3
    },
    {
      "id": "grp-77aa00bb11cc",
      "name": "Резерв",
      "strategy": "failover",
      "members": ["a1b2c3d4e5f6", "9f8e7d6c5b4a"],
      "revert": true
    }
  ]
}`

func TestParseRoundTrip(t *testing.T) {
	f, err := Parse([]byte("\xEF\xBB\xBF" + validFile))
	if err != nil {
		t.Fatal(err)
	}
	if f.Main != "grp-3fa1c2d4e5f6" || len(f.Groups) != 2 || f.Groups[0].Strategy != Latency || !f.Groups[1].Revert {
		t.Fatalf("%+v", f)
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	if f2, err := Parse(b); err != nil || !reflect.DeepEqual(f, f2) {
		t.Fatalf("round trip: %v\n%s", err, b)
	}
	if u, every := f.Probe.Effective(); u != DefaultProbeURL || every != time.Minute {
		t.Fatal(u, every)
	}
	var nilProbe *Probe
	if u, every := nilProbe.Effective(); u != DefaultProbeURL || every != DefaultInterval {
		t.Fatal(u, every)
	}
	if f.Find("grp-77aa00bb11cc").Name != "Резерв" || f.Find("nope") != nil {
		t.Fatal("Find")
	}
}

// A group without "members" or with null loads with an empty list: the UI
// reads an array.
func TestParseNilMembers(t *testing.T) {
	for _, g := range []string{`{"id":"grp-000000000001","name":"a","strategy":"failover"}`,
		`{"id":"grp-000000000001","name":"a","strategy":"failover","members":null}`} {
		f, err := Parse([]byte(`{"version":1,"groups":[` + g + `]}`))
		if err != nil || f.Groups[0].Members == nil {
			t.Fatalf("%s: %+v %v", g, f, err)
		}
		if b, _ := json.Marshal(f.Groups[0]); !strings.Contains(string(b), `"members":[]`) {
			t.Fatalf("%s", b)
		}
	}
}

func group(id, name string, members ...string) string {
	b, _ := json.Marshal(Group{ID: id, Name: name, Strategy: Failover, Members: members})
	return string(b)
}

func file(groups ...string) string {
	return `{"version":1,"groups":[` + strings.Join(groups, ",") + `]}`
}

func TestParseRejects(t *testing.T) {
	many := make([]string, MaxGroups+1)
	for i := range many {
		many[i] = group(fmt.Sprintf("grp-%012x", i), fmt.Sprintf("g%d", i))
	}
	members := make([]string, MaxMembers+1)
	for i := range members {
		members[i] = fmt.Sprintf("%012x", i)
	}
	for name, in := range map[string]string{
		"unknown field":   `{"version":1,"groups":[],"extra":1}`,
		"version 0":       `{"groups":[]}`,
		"version 2":       `{"version":2,"groups":[]}`,
		"bad id":          file(group("grp-XYZ", "a")),
		"plain id":        file(group("a1b2c3d4e5f6", "a")),
		"duplicate id":    file(group("grp-000000000001", "a"), group("grp-000000000001", "b")),
		"duplicate name":  file(group("grp-000000000001", "Авто"), group("grp-000000000002", "авто")),
		"too many":        file(many...),
		"too many member": file(group("grp-000000000001", "a", members...)),
		"long name":       file(group("grp-000000000001", strings.Repeat("я", 65))),
		"control":         file(group("grp-000000000001", "a\tb")),
		"empty name":      file(group("grp-000000000001", "")),
		"padded name":     file(group("grp-000000000001", " a")),
		"bad strategy":    `{"version":1,"groups":[{"id":"grp-000000000001","name":"a","strategy":"best","members":[]}]}`,
		"sae 1":           `{"version":1,"groups":[{"id":"grp-000000000001","name":"a","strategy":"failover","members":[],"switchAfterErrors":1}]}`,
		"sae 21":          `{"version":1,"groups":[{"id":"grp-000000000001","name":"a","strategy":"failover","members":[],"switchAfterErrors":21}]}`,
		"tolerance 5":     `{"version":1,"groups":[{"id":"grp-000000000001","name":"a","strategy":"latency","members":[],"toleranceMs":5}]}`,
		"tolerance 1001":  `{"version":1,"groups":[{"id":"grp-000000000001","name":"a","strategy":"latency","members":[],"toleranceMs":1001}]}`,
		"unknown main":    `{"version":1,"main":"grp-000000000009","groups":[]}`,
		"group member":    file(group("grp-000000000001", "a", "grp-000000000002")),
		"dup member":      file(group("grp-000000000001", "a", "aaaaaaaaaaaa", "aaaaaaaaaaaa")),
		"bad probe":       `{"version":1,"probe":{"url":"ftp://x"},"groups":[]}`,
		"trailing":        `{"version":1,"groups":[]} {}`,
		"garbage":         `nope`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := Parse([]byte(`{"version":2,"groups":[]}`))
	if err == nil || !strings.Contains(err.Error(), "более новой версией HyRoute (формат 2)") {
		t.Fatal(err)
	}
	_, err = Parse([]byte(file(group("grp-000000000001", "a", "grp-000000000002"))))
	if err == nil || err.Error() != "Сервер grp-000000000002 не найден" {
		t.Fatal(err)
	}
}

// Empty groups and dangling members load: they fail closed at runtime, and
// one broken group must not block the others.
func TestParseAcceptsEmptyAndDangling(t *testing.T) {
	f, err := Parse([]byte(file(group("grp-000000000001", "B"), group("grp-000000000002", "C", "deadbeef0000"))))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Groups[0].Members) != 0 || f.Groups[1].Members[0] != "deadbeef0000" {
		t.Fatalf("%+v", f.Groups)
	}
	if f2, err := Parse([]byte(`{"version":1}`)); err != nil || f2.Groups == nil {
		t.Fatal(f2, err)
	}
}

func TestValidateProbe(t *testing.T) {
	for _, ok := range []Probe{
		{}, {URL: DefaultProbeURL}, {URL: "https://www.gstatic.com/generate_204"}, {URL: "http://example.com:8080/a/b?c=d"},
		{URL: "http://203.0.113.9/x"}, {IntervalSec: 30}, {IntervalSec: 600}, {URL: "https://example.com:65535/"},
	} {
		if err := ValidateProbe(ok); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Probe{
		{URL: "ftp://example.com/"}, {URL: "http://user:pw@example.com/"}, {URL: "http:///path"}, {URL: "example.com"},
		{URL: "http://127.0.0.1/"}, {URL: "http://10.1.2.3/"}, {URL: "http://[::1]/"}, {URL: "http://169.254.1.1/"},
		{URL: "http://localhost/"}, {URL: "http://LOCALHOST./"}, {URL: "http://0.0.0.0/"}, {URL: "http://192.168.1.1/"},
		{URL: "http://example.com/" + strings.Repeat("a", 494)}, {IntervalSec: 29}, {IntervalSec: 601},
		{URL: "https://example.com:0/"}, {URL: "http://example.com:70000/"},
	} {
		if err := ValidateProbe(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := ValidateProbe(Probe{URL: "http://example.com/" + strings.Repeat("a", 493)}); err != nil {
		t.Fatal("512 bytes refused:", err)
	}
	if err := ValidateProbe(Probe{URL: "http://10.0.0.1/"}); err == nil || err.Error() != "Адрес проверки не должен вести в локальную сеть или на этот компьютер" {
		t.Fatal(err)
	}
}

func TestValidateEdited(t *testing.T) {
	servers := map[string]bool{"a": true, "b": true}
	has := func(id string) bool { return servers[id] }
	g := Group{ID: "grp-000000000001", Name: "Авто", Strategy: Latency}
	if err := ValidateEdited(g, has); err == nil || err.Error() != "Добавьте в группу хотя бы один сервер" {
		t.Fatal(err)
	}
	g.Members = []string{"a", "zz"}
	if err := ValidateEdited(g, has); err == nil || err.Error() != "Сервер zz не найден" {
		t.Fatal(err)
	}
	g.Members = []string{"a", "grp-000000000002"}
	if err := ValidateEdited(g, has); err == nil || err.Error() != "Сервер grp-000000000002 не найден" {
		t.Fatal(err)
	}
	g.Members = []string{"a", "b"}
	if err := ValidateEdited(g, has); err != nil {
		t.Fatal(err)
	}
	g.Name = " "
	if err := ValidateEdited(g, has); err == nil || err.Error() != "Укажите название группы" {
		t.Fatal(err)
	}
}

func TestPruneRefsRemap(t *testing.T) {
	f := &File{Version: 1, Main: "grp-000000000002", Groups: []Group{
		{ID: "grp-000000000001", Name: "A", Strategy: Failover, Members: []string{"x", "gone", "y"}},
		{ID: "grp-000000000002", Name: "B", Strategy: Random, Members: []string{"gone", "y", "z"}},
	}}
	if got := f.Refs(); !slices.Equal(got, []string{"x", "gone", "y", "z"}) {
		t.Fatal(got)
	}
	c := f.Clone()
	if n := c.Prune(func(id string) bool { return id != "gone" }); n != 2 {
		t.Fatal(n)
	}
	if !slices.Equal(c.Groups[0].Members, []string{"x", "y"}) || !slices.Equal(c.Groups[1].Members, []string{"y", "z"}) {
		t.Fatalf("%+v", c.Groups)
	}
	if len(f.Groups[0].Members) != 3 {
		t.Fatal("Clone shares members")
	}
	f.Remap(func(id string) string {
		if id == "z" {
			return ""
		}
		return "s-" + id
	}, func(id string) string {
		if id == "grp-000000000001" {
			return "grp-00000000000a"
		}
		return "grp-00000000000b"
	})
	if f.Groups[0].ID != "grp-00000000000a" || f.Main != "grp-00000000000b" || !slices.Equal(f.Groups[1].Members, []string{"s-gone", "s-y"}) {
		t.Fatalf("%+v", f)
	}
	// A dropped group takes Main with it.
	f.Remap(func(id string) string { return id }, func(id string) string {
		if id == "grp-00000000000b" {
			return ""
		}
		return id
	})
	if len(f.Groups) != 1 || f.Main != "" {
		t.Fatalf("%+v", f)
	}
}

func TestIDsAndMainOf(t *testing.T) {
	if !ValidID("grp-0123456789ab") || ValidID("grp-0123456789AB") || ValidID("grp-0123") || ValidID("0123456789ab") {
		t.Fatal("ValidID")
	}
	if !IsGroupID(NewID("0123456789ab")) || IsGroupID("0123456789ab") {
		t.Fatal("IsGroupID")
	}
	if got := MainOf([]byte(`{"version":1,"main":"grp-0123456789ab","groups":[{"bad":1}]}`)); got != "grp-0123456789ab" {
		t.Fatal(got)
	}
	if got := MainOf([]byte(`{"version":1,"main":"a1b2c3d4e5f6"}`)); got != "" {
		t.Fatal(got)
	}
	if got := MainOf([]byte(`garbage{`)); got != "" {
		t.Fatal(got)
	}
}

func TestSiteOf(t *testing.T) {
	for _, c := range []struct {
		decided string
		cached  []string
		want    string
	}{
		{"www.youtube.com", []string{"a.com"}, "youtube.com"},
		{"", []string{"m.youtube.com", "youtube.com"}, "youtube.com"},
		{"", []string{"youtube.com", "www.google.com"}, ""},
		{"", nil, ""},
		{"", []string{"www.youtube.com"}, "youtube.com"},
	} {
		if got := SiteOf(c.decided, c.cached); got != c.want {
			t.Errorf("SiteOf(%q, %v) = %q, want %q", c.decided, c.cached, got, c.want)
		}
	}
}
