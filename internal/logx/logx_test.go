package logx

import (
	"reflect"
	"strings"
	"testing"
)

func TestRedactor(t *testing.T) {
	var r Redactor
	if got := r.Redact("plain"); got != "plain" {
		t.Fatal(got)
	}
	r.Set("s3cr3t/pass", "abc", "", "s3cr3t")
	in := `auth=s3cr3t/pass q=s3cr3t%2Fpass short=abc other=s3cr3t`
	want := `auth=*** q=*** short=abc other=***`
	if got := r.Redact(in); got != want {
		t.Fatalf("got %q", got)
	}
	var nilR *Redactor
	if nilR.Redact("x") != "x" {
		t.Fatal("nil redactor")
	}
}

func TestRing(t *testing.T) {
	r := NewRing[int](3)
	r.Add(1)
	r.Add(2)
	if got := r.Snapshot(); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatal(got)
	}
	r.Add(3)
	r.Add(4)
	r.Add(5)
	if got := r.Snapshot(); !reflect.DeepEqual(got, []int{3, 4, 5}) {
		t.Fatal(got)
	}
}

func TestRedactEscapedForms(t *testing.T) {
	r := &Redactor{}
	secret := `pa"ss\wo/rd<1>`
	r.Set(secret)
	for _, line := range []string{
		`{"auth":"pa\"ss\\wo/rd<1>"}`,  // encoding/json
		`auth="pa\"ss\\wo/rd<1>"`,      // %q
		`url=pa%22ss%5Cwo%2Frd%3C1%3E`, // query escape
		`raw pa"ss\wo/rd<1>`,
	} {
		if got := r.Redact(line); strings.Contains(got, "wo/rd") || strings.Contains(got, "wo%2Frd") {
			t.Errorf("secret left in %q -> %q", line, got)
		}
	}
}
