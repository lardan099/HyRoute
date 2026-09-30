package remote

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// ErrNotReadOnly: a read-only executor refused a write or a command that
// is not one of the reading commands.
var ErrNotReadOnly = errors.New("read-only executor: refused")

// ReadOnly wraps ex for work that must not change the server (import):
// WriteFile fails, and Run and Stream take only the reading commands of
// this package's typed operations, with their reading flags.
func ReadOnly(ex Executor) Executor { return readOnly{ex} }

type readOnly struct{ ex Executor }

func (r readOnly) check(cmd Cmd) error {
	if !reads(cmd.Args) {
		return fmt.Errorf("%w: %s", ErrNotReadOnly, strings.Join(cmd.Args, " "))
	}
	return nil
}

func (r readOnly) Run(ctx context.Context, cmd Cmd) (Result, error) {
	if err := r.check(cmd); err != nil {
		return Result{}, err
	}
	return r.ex.Run(ctx, cmd)
}

func (r readOnly) Stream(ctx context.Context, cmd Cmd, line func(string)) error {
	if err := r.check(cmd); err != nil {
		return err
	}
	return r.ex.Stream(ctx, cmd, line)
}

func (r readOnly) ReadFile(ctx context.Context, p string, sudo bool) ([]byte, error) {
	return r.ex.ReadFile(ctx, p, sudo)
}

func (r readOnly) WriteFile(ctx context.Context, p string, data []byte, f FileSpec) error {
	return fmt.Errorf("%w: write %s", ErrNotReadOnly, p)
}

func (r readOnly) Close() error { return r.ex.Close() }

// readFlags are the flags each reading command may get; nil: any argument
// that is not a flag.
var readFlags = map[string][]string{
	"true":       {},
	"id":         {"-u", "-un", "--"},
	"hostname":   {},
	"uname":      {"-sr", "-m"},
	"nproc":      {},
	"df":         {"-Pk"},
	"test":       {"-e", "-f", "-d", "-x"},
	"stat":       {"-L", "-c", "--"},
	"cat":        {"--"},
	"sha256sum":  {"--"},
	"ss":         {"-Hlntup"},
	"ps":         {"-o", "-p"},
	"journalctl": {"-u", "-n", "--no-pager", "-o", "-f", journalFields},
	"getent":     {},
}

// readSystemctl are the systemctl verbs that only read.
var readSystemctl = []string{"show", "is-active", "is-enabled", "list-units", "list-unit-files"}

func reads(a []string) bool {
	if len(a) == 0 {
		return false
	}
	if a[0] == "systemctl" {
		return len(a) > 1 && slices.Contains(readSystemctl, a[1]) && flagsIn(a[2:], []string{"--no-pager", "--no-legend", "--plain", "--all", "--type=service", "-p", "--"})
	}
	if a[0] == "sh" {
		return len(a) == 5 && a[1] == "-c" && a[2] == hasCommandScript && a[3] == "sh"
	}
	if len(a) == 2 && a[1] == "version" && strings.HasPrefix(path.Base(a[0]), "hysteria") && path.IsAbs(a[0]) {
		return true
	}
	flags, ok := readFlags[a[0]]
	if !ok {
		return false
	}
	if a[0] == "getent" {
		return len(a) == 3 && a[1] == "passwd" && !strings.HasPrefix(a[2], "-")
	}
	if len(flags) == 0 {
		return len(a) == 1
	}
	return flagsIn(a[1:], flags)
}

// flagsIn: every argument that looks like a flag is one of allowed.
func flagsIn(args, allowed []string) bool {
	for _, x := range args {
		if strings.HasPrefix(x, "-") && !slices.Contains(allowed, x) {
			return false
		}
	}
	return true
}
