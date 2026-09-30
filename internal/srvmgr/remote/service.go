package remote

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Typed operations on users, systemd services, the journal and the
// firewall managers.

// UserExists reports whether a system user exists.
func UserExists(ctx context.Context, ex Executor, name string) (bool, error) {
	if !nameRe.MatchString(name) {
		return false, errors.New("bad user name")
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"id", "-u", "--", name}})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}

// CreateSystemUser adds a system user with a home directory (as the
// official Hysteria installer does) and no login shell.
func CreateSystemUser(ctx context.Context, ex Executor, name, home string, sudo bool) error {
	if !nameRe.MatchString(name) {
		return errors.New("bad user name")
	}
	if err := CheckPath(home); err != nil {
		return err
	}
	args := []string{"useradd", "-r", "-d", home, "-m"}
	for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if ok, err := PathExists(ctx, ex, shell, false); err != nil {
			return err
		} else if ok {
			args = append(args, "-s", shell)
			break
		}
	}
	_, err := run(ctx, ex, "useradd", Cmd{Args: append(args, "--", name), Sudo: sudo})
	return err
}

// ServiceAction is a systemctl action on one unit.
type ServiceAction string

const (
	ServiceEnable  ServiceAction = "enable"
	ServiceDisable ServiceAction = "disable"
	ServiceStart   ServiceAction = "start"
	ServiceStop    ServiceAction = "stop"
	ServiceRestart ServiceAction = "restart"
)

// Systemctl runs an action on a unit.
func Systemctl(ctx context.Context, ex Executor, action ServiceAction, unit string, sudo bool) error {
	switch action {
	case ServiceEnable, ServiceDisable, ServiceStart, ServiceStop, ServiceRestart:
	default:
		return fmt.Errorf("bad systemctl action %q", action)
	}
	if err := CheckUnitName(unit); err != nil {
		return err
	}
	_, err := run(ctx, ex, "systemctl "+string(action), Cmd{Args: []string{"systemctl", string(action), "--", unit}, Sudo: sudo})
	return err
}

// DaemonReload makes systemd reread unit files.
func DaemonReload(ctx context.Context, ex Executor, sudo bool) error {
	_, err := run(ctx, ex, "systemctl daemon-reload", Cmd{Args: []string{"systemctl", "daemon-reload"}, Sudo: sudo})
	return err
}

// ActiveState is systemctl is-active of a unit: active, activating,
// inactive, failed…
func ActiveState(ctx context.Context, ex Executor, unit string) (string, error) {
	if err := CheckUnitName(unit); err != nil {
		return "", err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"systemctl", "is-active", "--", unit}})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// JournalTail is the last lines a unit logged (message text only). The
// caller redacts them before showing them.
func JournalTail(ctx context.Context, ex Executor, unit string, lines int, sudo bool) ([]string, error) {
	if err := CheckUnitName(unit); err != nil {
		return nil, err
	}
	if lines < 1 || lines > 1000 {
		return nil, errors.New("bad line count")
	}
	out, err := run(ctx, ex, "journalctl", Cmd{Args: []string{"journalctl", "-u", unit, "-n", fmt.Sprint(lines), "--no-pager", "-o", "cat"}, Sudo: sudo})
	if err != nil {
		return nil, err
	}
	if out == "" || strings.HasPrefix(out, "-- No entries --") {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// PortSpec is a port or an inclusive range with a protocol.
type PortSpec struct {
	From, To int
	Proto    string // udp, tcp
}

func (p PortSpec) check() error {
	if p.From < 1 || p.From > 65535 || p.To < p.From || p.To > 65535 || (p.Proto != "udp" && p.Proto != "tcp") {
		return fmt.Errorf("bad port spec %+v", p)
	}
	return nil
}

// String is "443/udp" or "20000-50000/udp".
func (p PortSpec) String() string {
	if p.To != p.From {
		return fmt.Sprintf("%d-%d/%s", p.From, p.To, p.Proto)
	}
	return fmt.Sprintf("%d/%s", p.From, p.Proto)
}

func (p PortSpec) ufw() string {
	if p.To != p.From {
		return fmt.Sprintf("%d:%d/%s", p.From, p.To, p.Proto)
	}
	return fmt.Sprintf("%d/%s", p.From, p.Proto)
}

// ParsePortSpec reads what PortSpec.String writes.
func ParsePortSpec(s string) (PortSpec, error) {
	var p PortSpec
	ports, proto, ok := strings.Cut(s, "/")
	if !ok {
		return p, fmt.Errorf("bad port spec %q", s)
	}
	from, to, isRange := strings.Cut(ports, "-")
	if !isRange {
		to = from
	}
	var err1, err2 error
	p.From, err1 = strconv.Atoi(from)
	p.To, err2 = strconv.Atoi(to)
	p.Proto = proto
	if err1 != nil || err2 != nil || p.check() != nil {
		return PortSpec{}, fmt.Errorf("bad port spec %q", s)
	}
	return p, nil
}

// UFWAllow opens a port or range in ufw (existing rules are kept as they
// are; ufw skips duplicates).
func UFWAllow(ctx context.Context, ex Executor, p PortSpec, sudo bool) error {
	if err := p.check(); err != nil {
		return err
	}
	_, err := run(ctx, ex, "ufw allow", Cmd{Args: []string{"ufw", "allow", p.ufw()}, Sudo: sudo})
	return err
}

// FirewalldAllow opens a port or range in firewalld, permanently and in
// the running configuration.
func FirewalldAllow(ctx context.Context, ex Executor, p PortSpec, sudo bool) error {
	if err := p.check(); err != nil {
		return err
	}
	arg := "--add-port=" + p.String()
	if _, err := run(ctx, ex, "firewall-cmd", Cmd{Args: []string{"firewall-cmd", "--permanent", arg}, Sudo: sudo}); err != nil {
		return err
	}
	_, err := run(ctx, ex, "firewall-cmd", Cmd{Args: []string{"firewall-cmd", arg}, Sudo: sudo})
	return err
}

// PortAllowed reports whether tool (ufw or firewalld) has a rule that
// allows exactly this port or range. A wider rule does not count: it is
// not the one HyRoute would add or remove.
func PortAllowed(ctx context.Context, ex Executor, tool string, p PortSpec, sudo bool) (bool, error) {
	if err := p.check(); err != nil {
		return false, err
	}
	switch tool {
	case "ufw":
		// The rules as added, whether ufw is active or not.
		out, err := run(ctx, ex, "ufw show added", Cmd{Args: []string{"ufw", "show", "added"}, Sudo: sudo})
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			for _, r := range []string{"ufw allow " + p.ufw(), "ufw allow in " + p.ufw()} {
				if line == r || strings.HasPrefix(line, r+" ") {
					return true, nil
				}
			}
		}
		return false, nil
	case "firewalld":
		res, err := ex.Run(ctx, Cmd{Args: []string{"firewall-cmd", "--permanent", "--query-port=" + p.String()}, Sudo: sudo})
		if err != nil {
			return false, err
		}
		switch strings.TrimSpace(string(res.Stdout)) {
		case "yes":
			return true, nil
		case "no":
			return false, nil
		}
		return false, &ExitError{Op: "firewall-cmd --query-port", Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	return false, fmt.Errorf("unknown firewall %q", tool)
}

// OpenPort adds an allow rule for the port or range to tool.
func OpenPort(ctx context.Context, ex Executor, tool string, p PortSpec, sudo bool) error {
	switch tool {
	case "ufw":
		return UFWAllow(ctx, ex, p, sudo)
	case "firewalld":
		return FirewalldAllow(ctx, ex, p, sudo)
	}
	return fmt.Errorf("unknown firewall %q", tool)
}

// ClosePort removes the allow rule OpenPort added (other rules for the
// port stay).
func ClosePort(ctx context.Context, ex Executor, tool string, p PortSpec, sudo bool) error {
	if err := p.check(); err != nil {
		return err
	}
	switch tool {
	case "ufw":
		_, err := run(ctx, ex, "ufw delete", Cmd{Args: []string{"ufw", "--force", "delete", "allow", p.ufw()}, Sudo: sudo})
		return err
	case "firewalld":
		arg := "--remove-port=" + p.String()
		if _, err := run(ctx, ex, "firewall-cmd", Cmd{Args: []string{"firewall-cmd", "--permanent", arg}, Sudo: sudo}); err != nil {
			return err
		}
		_, err := run(ctx, ex, "firewall-cmd", Cmd{Args: []string{"firewall-cmd", arg}, Sudo: sudo})
		return err
	}
	return fmt.Errorf("unknown firewall %q", tool)
}

// UserHome is a user's home directory from the passwd database ("" when
// there is no such user).
func UserHome(ctx context.Context, ex Executor, name string) (string, error) {
	if !nameRe.MatchString(name) {
		return "", errors.New("bad user name")
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"getent", "passwd", name}})
	if err != nil || !res.OK() {
		return "", err
	}
	f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(f) < 7 || CheckPath(f[5]) != nil {
		return "", nil
	}
	return f[5], nil
}
