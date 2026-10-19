package model

import "testing"

func TestDriftKey(t *testing.T) {
	for _, c := range []struct {
		kind  DriftKind
		chain int64
		idx   int
		key   string
	}{{DriftConfig, 0, 0, "config"}, {DriftUnit, 0, 0, "unit"}, {DriftBinary, 0, 0, "binary"}, {DriftGeo, 0, 0, "geo"}, {DriftLink, 3, 1, "link/3/1"}} {
		if k := DriftKey(c.kind, c.chain, c.idx); k != c.key {
			t.Errorf("DriftKey(%s, %d, %d) = %q, want %q", c.kind, c.chain, c.idx, k, c.key)
		}
		kind, chain, idx, ok := ParseDriftKey(c.key)
		if !ok || kind != c.kind || chain != c.chain || idx != c.idx {
			t.Errorf("ParseDriftKey(%q) = %s %d %d %v", c.key, kind, chain, idx, ok)
		}
	}
	for _, bad := range []string{"", "link", "link/", "link/3", "link/0/1", "link/3/-1", "link/03/1", "link/3/1/", "Config", "unit "} {
		if _, _, _, ok := ParseDriftKey(bad); ok {
			t.Errorf("ParseDriftKey(%q) accepted", bad)
		}
	}
}
