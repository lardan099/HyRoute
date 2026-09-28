package sysdns

import (
	"fmt"
	"slices"
	"testing"
)

func TestParseNames(t *testing.T) {
	got := ParseNames([]string{" Corp.Example. ", ".home.lan", ".", "", "  ", "corp.example", "bad name", "Пример.рф", "a..b", "x_y.local"})
	want := []string{"corp.example", "home.lan", "xn--e1afmkfd.xn--p1ai", "x_y.local"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf("n%d.example", i))
	}
	if n := len(ParseNames(many)); n != 256 {
		t.Fatalf("%d names kept", n)
	}
}

func TestInfoLocal(t *testing.T) {
	var none *Info
	if none.Local("a.corp.example") {
		t.Fatal("nil Info")
	}
	i := &Info{Suffixes: []string{"corp.example", "lan"}}
	for name, want := range map[string]bool{
		"corp.example": true, "Wiki.Corp.Example.": true, "x.lan": true,
		"notcorp.example": false, "example": false, "corp.example.com": false, "": false,
	} {
		if i.Local(name) != want {
			t.Errorf("%q: %v", name, !want)
		}
	}
}

// A network's DNS suffix that is a public suffix ("com", "co.uk" through
// DHCP) must not make a whole namespace local; the administrator's names
// are kept.
func TestLocalSuffixes(t *testing.T) {
	got := LocalSuffixes([]string{"com", " RU. ", "lan", "co.uk", "COM.RU.", "github.io", "corp.example", ".home.lan"}, []string{"corp", "nrpt.example"})
	want := []string{"corp.example", "home.lan", "corp", "nrpt.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	i := &Info{Suffixes: got}
	if i.Local("example.com") || i.Local("yandex.ru") || i.Local("bbc.co.uk") || i.Local("shop.com.ru") || i.Local("u.github.io") {
		t.Fatal("a DHCP suffix made a top-level domain local")
	}
	if !i.Local("wiki.corp.example") || !i.Local("x.corp") {
		t.Fatal("trusted suffixes lost")
	}
}
