package store

import (
	"strings"
	"testing"
)

// Pushing the current body again keeps the previous snapshot.
func TestPushSnapshotSameBodyKeepsPrevious(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"good", "bad", "bad"} {
		if err := s.PushSnapshot("x", []byte(b), nil); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "good" {
		t.Fatalf("%q %v", got, err)
	}
}

// A body the caller calls the same as the current one (the same servers,
// other names) replaces the current snapshot and keeps the previous one.
func TestPushSnapshotSameServersKeepsPrevious(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	same := func(cur []byte) bool { return strings.HasPrefix(string(cur), "bad") }
	for _, b := range []string{"good", "bad 4.3GB", "bad 4.1GB"} {
		if err := s.PushSnapshot("x", []byte(b), same); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "good" {
		t.Fatalf("previous %q %v", got, err)
	}
	if err := s.SwapSnapshots("x"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "bad 4.1GB" {
		t.Fatalf("after swap %q %v", got, err)
	}
}
