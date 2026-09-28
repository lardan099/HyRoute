package dnspolicy

import (
	"strings"
	"testing"
	"time"
)

func TestOwnNames(t *testing.T) {
	now := time.Unix(1000, 0)
	o := &OwnNames{Now: func() time.Time { return now }}
	if (*OwnNames)(nil).Has("x.example") {
		t.Fatal("nil set")
	}
	o.Add("GitHub.com.", 2*time.Minute)
	o.Add("203.0.113.9", 2*time.Minute) // IP literals: nothing
	o.Add("[2001:db8::1]", 2*time.Minute)
	if !o.Has("github.com") || o.Len() != 1 {
		t.Fatalf("%v", o.m)
	}
	o.Add("github.com", time.Minute) // a shorter TTL does not shorten it
	now = now.Add(90 * time.Second)
	if !o.Has("github.com") {
		t.Fatal("shortened")
	}
	now = now.Add(30 * time.Second)
	if o.Has("github.com") || o.Len() != 0 {
		t.Fatal("not expired")
	}
	// The cap: the one that expires soonest goes.
	for i := range ownNamesMax + 1 {
		o.Add("n"+strings.Repeat("x", i)+".example", time.Minute+time.Duration(i)*time.Second)
	}
	if o.Has("n.example") || !o.Has("n"+strings.Repeat("x", ownNamesMax)+".example") || o.Len() != ownNamesMax {
		t.Fatal("cap: the oldest goes")
	}
	// At the cap the expired ones go first.
	now = now.Add(time.Hour)
	o.Add("fresh.example", time.Minute)
	if o.Len() != 1 || !o.Has("fresh.example") {
		t.Fatalf("%d held", o.Len())
	}
}
