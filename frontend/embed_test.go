package frontend

import (
	"io/fs"
	"testing"
)

func TestDistHasIndex(t *testing.T) {
	if _, err := fs.Stat(Dist, "dist/index.html"); err != nil {
		t.Fatalf("built UI is not embedded: %v", err)
	}
}
