package rules

import (
	"strings"
	"testing"
)

func TestRegistrable(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"a.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"www.bbc.co.uk", "bbc.co.uk", true},
		{"u.github.io", "u.github.io", true},
		{"x.u.github.io", "u.github.io", true},
		{"WWW.Example.COM.", "example.com", true},
		// IDN: the site is the punycode form.
		{"www.пример.рф", "xn--e1afmkfd.xn--p1ai", true},
		{"xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai", true},
		{"github.io", "", false},
		{"co.uk", "", false},
		{"com", "", false},
		{"router", "", false},
		{"localhost", "", false},
		{"1.2.3.4", "", false},
		{"::1", "", false},
		{"[::1]", "", false},
		{"2001:db8::1", "", false},
		// Short IPv4 forms and names that are no host names.
		{"1.2.3", "", false},
		{"01.02.03.04", "", false},
		{"1.2.3.4.5", "", false},
		{"bad name.com", "", false},
		{"a.123", "", false},
		{"1.example.com", "example.com", true},
		{"example.xn--p1ai", "example.xn--p1ai", true},
		{"", "", false},
		{"  ", "", false},
	} {
		got, ok := Registrable(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Registrable(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSite(t *testing.T) {
	for in, want := range map[string]string{
		"www.youtube.com":  "youtube.com",
		"a.b.co.uk":        "b.co.uk",
		"u.github.io":      "u.github.io",
		"github.io":        "github.io", // not registrable: the name is kept
		"localhost":        "localhost",
		"1.2.3.4":          "1.2.3.4",
		"WWW.YouTube.com.": "youtube.com",
		"пример.рф":        "xn--e1afmkfd.xn--p1ai",
		"":                 "",
	} {
		if got := Site(in); got != want {
			t.Errorf("Site(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostName(t *testing.T) {
	long := strings.Repeat("a", 64) + ".com"
	total := strings.Repeat(strings.Repeat("a", 60)+".", 5) + "com"                   // 308 bytes
	atMax := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61) // 253 bytes
	if len(atMax) != 253 {
		t.Fatal(len(atMax))
	}
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"www.example.com", "www.example.com", true},
		{"WWW.Example.COM.", "www.example.com", true},
		{"_dmarc.example.com", "_dmarc.example.com", true},
		{"a-b.example.com", "a-b.example.com", true},
		{"localhost", "localhost", true},
		{"пример.рф", "xn--e1afmkfd.xn--p1ai", true},
		{"xn--80ak6aa92e.com", "xn--80ak6aa92e.com", true},
		{strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", true},
		{"1.2.3.4", "", false},
		{"::1", "", false},
		{"[::1]", "", false},
		{"fe80::1%eth0", "", false},
		{"", "", false},
		{"a..b", "", false},
		{".example.com", "", false},
		{"bad host!", "", false},
		{"a/b.com", "", false},
		{long, "", false},
		{total, "", false},
		{atMax, atMax, true},
		{atMax + "b", "", false},
		{"1.2.3", "", false},
		{"01.02.03.04", "", false},
		{"123", "", false},
		{"a.b.0x1", "a.b.0x1", true},
		{"3com.com", "3com.com", true},
	} {
		got, ok := HostName(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("HostName(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
