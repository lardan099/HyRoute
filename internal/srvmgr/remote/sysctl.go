package remote

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// SysctlRead reads kernel parameters from /proc/sys (the ones this
// kernel does not have are left out). No program runs: sysctl is in
// /usr/sbin on Debian, off the PATH of a non-root SSH session. Whitespace
// inside a value becomes one space ("4096 131072 6291456").
func SysctlRead(ctx context.Context, ex Executor, keys ...string) (map[string]string, error) {
	for _, k := range keys {
		if err := CheckSysctl(k, ""); err != nil {
			return nil, err
		}
	}
	out := map[string]string{}
	for _, k := range keys {
		b, err := ex.ReadFile(ctx, sysctlPath(k), false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[k] = strings.Join(strings.Fields(string(b)), " ")
	}
	return out, nil
}

// sysctlPath is the /proc/sys file of a checked key.
func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
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

// modinfoScript runs modinfo from an sbin directory too, where kmod puts
// it on Debian; the module name comes as $1.
const modinfoScript = `PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"; exec modinfo -F name "$1"`

// KernelModule reports whether a module of the running kernel is
// available (modinfo finds it; it may not be loaded).
func KernelModule(ctx context.Context, ex Executor, name string) (bool, error) {
	if !moduleRe.MatchString(name) {
		return false, fmt.Errorf("bad module name %q", name)
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"sh", "-c", modinfoScript, "sh", name}})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}
