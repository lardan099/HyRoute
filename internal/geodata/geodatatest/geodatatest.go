// Package geodatatest writes small geosite.dat/geoip.dat files for tests.
package geodatatest

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func varint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func field(b []byte, n int, v []byte) []byte {
	b = varint(b, uint64(n)<<3|2)
	b = varint(b, uint64(len(v)))
	return append(b, v...)
}

func num(b []byte, n int, v uint64) []byte {
	return varint(varint(b, uint64(n)<<3), v)
}

// WriteSite writes dir/geosite.dat. Entries: "domain:x", "full:x",
// "keyword:x", "regexp:x" or a bare "x" (domain), each optionally
// followed by " @attr".
func WriteSite(dir string, cats map[string][]string) error {
	var out []byte
	for _, name := range sorted(cats) {
		e := field(nil, 1, []byte(strings.ToUpper(name)))
		for _, raw := range cats[name] {
			parts := strings.Fields(raw)
			typ, val := 2, parts[0]
			if k, v, ok := strings.Cut(parts[0], ":"); ok {
				val = v
				switch k {
				case "keyword":
					typ = 0
				case "regexp":
					typ = 1
				case "full":
					typ = 3
				}
			}
			m := field(num(nil, 1, uint64(typ)), 2, []byte(val))
			for _, a := range parts[1:] {
				m = field(m, 3, field(nil, 1, []byte(strings.TrimPrefix(a, "@"))))
			}
			e = field(e, 2, m)
		}
		out = field(out, 1, e)
	}
	return write(dir, "geosite.dat", out)
}

// WriteIP writes dir/geoip.dat from CIDRs per category.
func WriteIP(dir string, cats map[string][]string) error {
	var out []byte
	for _, name := range sorted(cats) {
		e := field(nil, 1, []byte(strings.ToUpper(name)))
		for _, c := range cats[name] {
			p := netip.MustParsePrefix(c)
			e = field(e, 2, num(field(nil, 1, p.Addr().AsSlice()), 2, uint64(p.Bits())))
		}
		out = field(out, 1, e)
	}
	return write(dir, "geoip.dat", out)
}

func sorted(m map[string][]string) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

func write(dir, name string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), b, 0o600)
}
