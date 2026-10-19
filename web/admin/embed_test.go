package admin

import (
	"io/fs"
	"testing"
)

func TestDistHasIndex(t *testing.T) {
	if _, err := fs.Stat(FS(), "index.html"); err != nil {
		t.Fatalf("built admin is not embedded: %v", err)
	}
}
