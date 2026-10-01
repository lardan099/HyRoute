package remote

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	sysctlKeyRe   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`)
	sysctlValueRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+( [A-Za-z0-9_.-]+)*$`)
	moduleRe      = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// CheckSysctl checks a kernel parameter and its value for SysctlSet.
func CheckSysctl(key, value string) error {
	if !sysctlKeyRe.MatchString(key) || len(key) > 128 {
		return fmt.Errorf("bad sysctl key %q", key)
	}
	if value != "" && (!sysctlValueRe.MatchString(value) || len(value) > 128) {
		return fmt.Errorf("bad sysctl value %q", value)
	}
	return nil
}

// SysctlRead reads kernel parameters (sysctl -e: the ones this kernel
// does not have are left out). Whitespace inside a value becomes one
// space ("4096 131072 6291456").
func SysctlRead(ctx context.Context, ex Executor, keys ...string) (map[string]string, error) {
	args := []string{"sysctl", "-e"}
	for _, k := range keys {
		if err := CheckSysctl(k, ""); err != nil {
			return nil, err
		}
		args = append(args, k)
	}
	res, err := ex.Run(ctx, Cmd{Args: args})
	if err != nil {
		return nil, err
	}
	// Exit 255 on a key it cannot read; what it could read is printed.
	if !res.OK() && len(res.Stdout) == 0 {
		return nil, &ExitError{Op: "sysctl", Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Join(strings.Fields(v), " ")
	}
	return out, nil
}

// SysctlSet sets a kernel parameter now (not across reboots).
func SysctlSet(ctx context.Context, ex Executor, key, value string, sudo bool) error {
	if err := CheckSysctl(key, value); err != nil {
		return err
	}
	_, err := run(ctx, ex, "sysctl", Cmd{Args: []string{"sysctl", "-q", "-w", key + "=" + value}, Sudo: sudo})
	return err
}

// SysctlLoad applies the parameters of a sysctl.d file now.
func SysctlLoad(ctx context.Context, ex Executor, path string, sudo bool) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	_, err := run(ctx, ex, "sysctl", Cmd{Args: []string{"sysctl", "-q", "-p", path}, Sudo: sudo})
	return err
}

// KernelModule reports whether a module of the running kernel is
// available (modinfo finds it; it may not be loaded).
func KernelModule(ctx context.Context, ex Executor, name string) (bool, error) {
	if !moduleRe.MatchString(name) {
		return false, fmt.Errorf("bad module name %q", name)
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"modinfo", "-F", "name", name}})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}
