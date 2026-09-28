//go:build windows

package main

import "testing"

// TestTaskName pins the sign-in task's name: internal/autostart names it
// the same way (kind.taskName of its start task).
func TestTaskName(t *testing.T) {
	if got := taskName("S-1-5-21-1-2-3-1001"); got != "HyRoute (S-1-5-21-1-2-3-1001)" {
		t.Fatal(got)
	}
}
