package remote

import (
	"context"
	"strconv"
	"strings"
)

// run runs a typed operation's command; a non-zero exit becomes an
// ExitError named after op. Stdout comes back trimmed.
func run(ctx context.Context, ex Executor, op string, cmd Cmd) (string, error) {
	res, err := ex.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", &ExitError{Op: op, Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// Probe is who the controller is on the server and what the machine is.
type Probe struct {
	User     string `json:"user"`
	Root     bool   `json:"root"`
	Sudo     bool   `json:"sudo"` // passwordless sudo works (always true for root)
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"` // uname -sr
	Arch     string `json:"arch"`   // uname -m
}

// Privileged reports whether the controller can act as root.
func (p Probe) Privileged() bool { return p.Root || p.Sudo }

// NeedSudo: commands that need root must go through sudo.
func (p Probe) NeedSudo() bool { return !p.Root }

// RunProbe identifies the SSH user and the machine; it changes nothing.
func RunProbe(ctx context.Context, ex Executor) (Probe, error) {
	var p Probe
	var err error
	if p.User, err = run(ctx, ex, "id -un", Cmd{Args: []string{"id", "-un"}}); err != nil {
		return p, err
	}
	uid, err := run(ctx, ex, "id -u", Cmd{Args: []string{"id", "-u"}})
	if err != nil {
		return p, err
	}
	if n, err := strconv.Atoi(uid); err == nil && n == 0 {
		p.Root, p.Sudo = true, true
	}
	if p.Hostname, err = run(ctx, ex, "hostname", Cmd{Args: []string{"hostname"}}); err != nil {
		return p, err
	}
	if p.Kernel, err = run(ctx, ex, "uname -sr", Cmd{Args: []string{"uname", "-sr"}}); err != nil {
		return p, err
	}
	if p.Arch, err = run(ctx, ex, "uname -m", Cmd{Args: []string{"uname", "-m"}}); err != nil {
		return p, err
	}
	if !p.Root {
		res, err := ex.Run(ctx, Cmd{Args: []string{"true"}, Sudo: true})
		if err != nil {
			return p, err
		}
		p.Sudo = res.OK()
	}
	return p, nil
}
