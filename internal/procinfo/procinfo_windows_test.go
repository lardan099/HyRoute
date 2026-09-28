//go:build windows

package procinfo

import (
	"os"
	"testing"
)

// TestCreatedTimeMatchesQuery: Get compares createdTime with the creation
// time Query stored; if they ever differed every cached entry would be
// thrown away (or kept for another process).
func TestCreatedTimeMatchesQuery(t *testing.T) {
	pid := uint32(os.Getpid())
	_, want, ok := query(pid)
	if !ok {
		t.Fatal("query failed for own process")
	}
	got, ok, gone := createdTime(pid)
	if !ok || gone || got != want {
		t.Fatalf("createdTime = %d ok=%v gone=%v, query = %d", got, ok, gone, want)
	}
	// No process has this PID (they are multiples of 4, far smaller).
	if _, ok, gone := createdTime(0x7ffffffc); ok || !gone {
		t.Fatalf("missing pid: ok=%v gone=%v", ok, gone)
	}
}
