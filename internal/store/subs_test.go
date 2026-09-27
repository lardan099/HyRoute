package store

import "testing"

// Pushing the current body again keeps the previous snapshot.
func TestPushSnapshotSameBodyKeepsPrevious(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"good", "bad", "bad"} {
		if err := s.PushSnapshot("x", []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.SwapSnapshots("x"); err != nil || string(got) != "good" {
		t.Fatalf("%q %v", got, err)
	}
}
