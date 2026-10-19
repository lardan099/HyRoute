package remote

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// userShell runs commands with the local /bin/sh and the PATH of a
// non-root SSH session on Debian: no sbin directories.
type userShell struct{}

func (userShell) Run(ctx context.Context, cmd Cmd) (Result, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", `exec "$@"`, "sh")
	c.Args = append(c.Args, cmd.Args...)
	c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	err := c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{ExitCode: ee.ExitCode()}, nil
	}
	return Result{}, err
}

func (userShell) Stream(context.Context, Cmd, func(string)) error { return errors.ErrUnsupported }
func (userShell) ReadFile(context.Context, string, bool) ([]byte, error) {
	return nil, errors.ErrUnsupported
}
func (userShell) WriteFile(context.Context, string, []byte, FileSpec) error {
	return errors.ErrUnsupported
}
func (userShell) Close() error { return nil }

// sbinOnly finds a program installed only in an sbin directory, as ufw,
// nft and iptables are on Debian.
func sbinOnly() string {
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			name := e.Name()
			if !commandNameRe.MatchString(name) {
				continue
			}
			if st, err := os.Stat(filepath.Join(dir, name)); err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
				continue
			}
			elsewhere := false
			for _, d := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
				if _, err := os.Stat(filepath.Join(d, name)); err == nil {
					elsewhere = true
				}
			}
			if !elsewhere {
				return name
			}
		}
	}
	return ""
}

// Administration programs in /usr/sbin are found although a non-root
// session's PATH lacks it.
func TestHasSystemCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	name := sbinOnly()
	if name == "" {
		t.Skip("no program only in an sbin directory here")
	}
	ctx := context.Background()
	if ok, err := HasCommand(ctx, userShell{}, name); err != nil || ok {
		t.Fatalf("%s on the user's PATH: %v %v", name, ok, err)
	}
	if ok, err := HasSystemCommand(ctx, userShell{}, name); err != nil || !ok {
		t.Fatalf("%s not found in sbin: %v %v", name, ok, err)
	}
	if ok, err := HasSystemCommand(ctx, userShell{}, "no-such-program-hyroute"); err != nil || ok {
		t.Fatalf("a missing program found: %v %v", ok, err)
	}
	if ok, err := HasSystemCommand(ctx, userShell{}, "sh"); err != nil || !ok {
		t.Fatalf("sh not found: %v %v", ok, err)
	}
}

// A backup never writes through a symlink at its name, and a rename never
// moves into a directory a symlink at the target points to.
func TestCopyAndRenameKeepSymlinkTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	ctx := context.Background()
	dir := t.TempDir()
	src, other := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "other")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	backup := src + ".hyroute-prev"
	if err := os.Symlink(other, backup); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(ctx, userShell{}, src, backup, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); string(b) != "keep" {
		t.Fatalf("copied through the link: %q", b)
	}
	if fi, err := os.Lstat(backup); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("backup is not a file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(backup); string(b) != "new" {
		t.Fatalf("backup %q", b)
	}

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, src); err != nil {
		t.Fatal(err)
	}
	if err := Rename(ctx, userShell{}, backup, src, false); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(sub); len(es) != 0 {
		t.Fatalf("moved into the linked directory: %v", es)
	}
	if b, _ := os.ReadFile(src); string(b) != "new" {
		t.Fatalf("renamed %q", b)
	}
}
