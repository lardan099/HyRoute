package remote

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "''",
		"hysteria-server":      "hysteria-server",
		"/etc/hysteria/x.yaml": "/etc/hysteria/x.yaml",
		"a b":                  "'a b'",
		"it's":                 `'it'\''s'`,
		"$(reboot)":            "'$(reboot)'",
		"; rm -rf /":           "'; rm -rf /'",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

// The command line survives a real shell with hostile arguments intact:
// every argument arrives as one literal argv entry.
func TestCommandLineThroughShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	hostile := []string{"$(echo pwned)", "`id`", "a'b\"c", "x; echo injected", "*", "~", "line\nbreak", "\\"}
	line, err := CommandLine(Cmd{Args: append([]string{"printf", "%s\\0"}, hostile...)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", line).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(got) != len(hostile) {
		t.Fatalf("%d args, want %d: %q", len(got), len(hostile), got)
	}
	for i := range hostile {
		if got[i] != hostile[i] {
			t.Errorf("arg %d: %q, want %q", i, got[i], hostile[i])
		}
	}
	if _, err := CommandLine(Cmd{Args: []string{"echo", "a\x00b"}}); err == nil {
		t.Fatal("NUL accepted")
	}
	if _, err := CommandLine(Cmd{}); err == nil {
		t.Fatal("empty command accepted")
	}
	if l, _ := CommandLine(Cmd{Args: []string{"true"}, Sudo: true}); !strings.HasPrefix(l, "sudo -n -- env LC_ALL=C") {
		t.Fatalf("sudo line %q", l)
	}
}

func TestCheckPath(t *testing.T) {
	for _, ok := range []string{"/etc/hysteria/config.yaml", "/usr/local/bin/hysteria"} {
		if err := CheckPath(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"etc/x", "/etc/../root/.ssh", "/etc/..", "//x", "/a\nb", ""} {
		if CheckPath(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
