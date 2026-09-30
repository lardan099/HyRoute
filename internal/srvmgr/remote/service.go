package remote

import (
	"context"
	"errors"
	"fmt"
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

// UFWAllow opens a port or range in ufw (existing rules are kept as they
// are; ufw skips duplicates).
func UFWAllow(ctx context.Context, ex Executor, p PortSpec, sudo bool) error {
	if err := p.check(); err != nil {
		return err
	}
	spec := fmt.Sprintf("%d/%s", p.From, p.Proto)
	if p.To != p.From {
		spec = fmt.Sprintf("%d:%d/%s", p.From, p.To, p.Proto)
	}
	_, err := run(ctx, ex, "ufw allow", Cmd{Args: []string{"ufw", "allow", spec}, Sudo: sudo})
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
