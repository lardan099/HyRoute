package store

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRemoteRefusal(t *testing.T) {
	local := localNames{names: []string{"PC1", "pc1.corp.example"}, ips: []netip.Addr{netip.MustParseAddr("192.168.1.10")}}
	own := []string{"localhost", "LOCALHOST.", "pc1", "PC1.corp.example", "127.0.0.1", "127.5.5.5", "::1", "[::1]",
		"0--1.ipv6-literal.net", "0.0.0.0", "192.168.1.10"}
	for _, h := range own {
		for _, final := range []string{`\\?\UNC\` + h + `\share\x.hyroute-backup`, `\\` + h + `\share\x`} {
			if err := remoteRefusal(final, local); err == nil || !strings.Contains(err.Error(), "общая папка этого компьютера") {
				t.Fatalf("%s: %v", final, err)
			}
		}
	}
	for _, s := range []string{"C$", "admin$", "IPC$", "hidden$"} {
		if err := remoteRefusal(`\\?\UNC\nas\`+s+`\x`, local); err == nil || !strings.Contains(err.Error(), "Скрытые общие папки") {
			t.Fatalf("%s: %v", s, err)
		}
	}
	for _, final := range []string{`\\?\UNC\nas\backup\x`, `\\192.168.1.20\share\x`, `C:\Users\x`} {
		if err := remoteRefusal(final, local); err != nil {
			t.Fatalf("%s: %v", final, err)
		}
	}
}

func TestCheckUserName(t *testing.T) {
	for _, n := range []string{"", ".", "..", "x.hyroute-backup:s", "CON.hyroute-backup", "con", "nul.txt", "COM1.x", "lpt9",
		"a/b", `a\b`, "name.", "name ", "a?b", "COM¹"} {
		if checkUserName(n) == nil {
			t.Fatalf("%q accepted", n)
		}
	}
	for _, n := range []string{"HyRoute-2026-09-28.hyroute-backup", "console.txt", "com10", "Копия.hyroute-backup"} {
		if err := checkUserName(n); err != nil {
			t.Fatalf("%q: %v", n, err)
		}
	}
}
