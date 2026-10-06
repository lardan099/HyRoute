// Package firewall opens and closes the ports of Hysteria in ufw or
// firewalld for the deploy and apply jobs, and keeps track of the rules
// HyRoute itself added: a rollback or a port change closes only those,
// never rules that were there before.
//
// A job calls Open before the service restarts (its Undo closes what it
// opened), records the result with Record once the new config is
// verified, and calls Cleanup last to close the recorded rules the new
// config no longer needs.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Keys in the job's data.
const (
	keyTool  = "fwTool"  // the tool Open worked with
	keyAdded = "fwAdded" // the ports Open added (Set before each is added)
)

// Managed reports whether HyRoute opens ports in tool itself.
func Managed(tool string) bool { return tool == "ufw" || tool == "firewalld" }

// Ports are the ports a config needs reachable: the UDP ports Hysteria
// listens on, the TCP port of its ACME challenge and those of the
// masquerade site on TCP. In Realms mode (listen realm://…) Hysteria has
// no UDP ports of its own.
func Ports(c *hyconfig.Server) ([]remote.PortSpec, error) {
	var out []remote.PortSpec
	if !strings.Contains(c.Listen, "://") {
		l, err := hyconfig.ParseListen(c.Listen)
		if err != nil {
			return nil, err
		}
		rs, err := hy2uri.ParsePorts(l.Ports)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			out = append(out, remote.PortSpec{From: int(r.From), To: int(r.To), Proto: "udp"})
		}
	}
	if a := c.ACME; a != nil {
		tcp := func(port, def int) {
			if port == 0 {
				port = def
			}
			out = append(out, remote.PortSpec{From: port, To: port, Proto: "tcp"})
		}
		switch a.Type {
		case "http":
			tcp(a.HTTP.AltPort, 80)
		case "tls":
			tcp(a.TLS.AltPort, 443)
		case "":
			// Before acme.type: both challenges unless disabled.
			if !a.DisableHTTP {
				tcp(a.AltHTTPPort, 80)
			}
			if !a.DisableTLSALPN {
				tcp(a.AltTLSALPNPort, 443)
			}
		}
	}
	for _, addr := range []string{c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS} {
		if addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(addr)
		n, perr := strconv.Atoi(port)
		if err != nil || perr != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("masquerade: bad address %q", addr)
		}
		ps := remote.PortSpec{From: n, To: n, Proto: "tcp"}
		if !slices.Contains(out, ps) {
			out = append(out, ps)
		}
	}
	return out, nil
}

// List is ports for the job log: "443/udp, 80/tcp".
func List(ps []remote.PortSpec) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, ", ")
}

// set is port specs as strings, sorted and unique.
type set []string

func parse(s string) set {
	var out set
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = out.add(p)
		}
	}
	return out
}

func of(ps []remote.PortSpec) set {
	var out set
	for _, p := range ps {
		out = out.add(p.String())
	}
	return out
}

func (s set) add(p string) set {
	if i, found := slices.BinarySearch(s, p); !found {
		s = slices.Insert(s, i, p)
	}
	return s
}

func (s set) has(p string) bool {
	_, found := slices.BinarySearch(s, p)
	return found
}

func (s set) String() string { return strings.Join(s, ",") }

// Open adds rules to tool for the ports of want it does not allow yet.
// Each port goes into the job's data before its rule is added, so the
// job's Undo closes it even if the controller stops right after.
func Open(ctx context.Context, env *jobs.Env, ex remote.Executor, tool string, want []remote.PortSpec, sudo bool) error {
	if !Managed(tool) {
		return fmt.Errorf("unknown firewall %q", tool)
	}
	if prev := env.Get(keyTool); prev != "" && prev != tool {
		return jobs.Fail("Брандмауэр на сервере сменился во время задания ("+prev+" → "+tool+"). Повторите задание.", nil)
	}
	if err := env.Set(keyTool, tool); err != nil {
		return err
	}
	added := parse(env.Get(keyAdded))
	var opened, existing []remote.PortSpec
	for _, p := range want {
		ok, err := remote.PortAllowed(ctx, ex, tool, p, sudo)
		if err != nil {
			return jobs.Fail("Не удалось прочитать правила "+tool+".", err)
		}
		if ok {
			if !added.has(p.String()) {
				existing = append(existing, p)
			}
			continue
		}
		added = added.add(p.String())
		if err := env.Set(keyAdded, added.String()); err != nil {
			return err
		}
		if err := remote.OpenPort(ctx, ex, tool, p, sudo); err != nil {
			return jobs.Fail("Не удалось открыть порт "+p.String()+" в "+tool+".", err)
		}
		opened = append(opened, p)
	}
	if len(opened) > 0 {
		env.Logf("Открыто в %s: %s.", tool, List(opened))
	}
	if len(existing) > 0 {
		env.Logf("Уже открыто в %s: %s.", tool, List(existing))
	}
	return nil
}

// Undo closes the rules Open added in this job.
func Undo(ctx context.Context, env *jobs.Env, ex remote.Executor, sudo bool) error {
	tool, added := env.Get(keyTool), parse(env.Get(keyAdded))
	if len(added) == 0 {
		return jobs.ErrNothingToUndo
	}
	var left set
	var errs []error
	for _, s := range added {
		p, err := remote.ParsePortSpec(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := closePort(ctx, ex, tool, p, sudo); err != nil {
			left = left.add(s)
			errs = append(errs, fmt.Errorf("порт %s в %s: %w", s, tool, err))
		}
	}
	if err := env.Set(keyAdded, left.String()); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	env.Logf("Закрыто в %s то, что открыло задание: %s.", tool, strings.Join(added, ", "))
	return nil
}

// closePort removes HyRoute's rule if it is still there.
func closePort(ctx context.Context, ex remote.Executor, tool string, p remote.PortSpec, sudo bool) error {
	ok, err := remote.PortAllowed(ctx, ex, tool, p, sudo)
	if err != nil || !ok {
		return err
	}
	return remote.ClosePort(ctx, ex, tool, p, sudo)
}

// Record is what HyRoute owns in the firewall once the job succeeds: the
// previous record and the ports this job added. A record for another tool
// is dropped when this job opened ports with a new one (those rules are
// left as they are).
func Record(env *jobs.Env, prev model.Firewall) model.Firewall {
	tool, added := env.Get(keyTool), parse(env.Get(keyAdded))
	if tool == "" {
		return prev
	}
	fw := model.Firewall{Tool: tool, Keep: prev.Keep}
	ports := added
	if prev.Tool == tool || prev.Tool == "" {
		for _, p := range parse(prev.Ports) {
			ports = ports.add(p)
		}
	}
	fw.Ports = ports.String()
	return fw
}

// Cleanup closes the recorded rules of the ports the config no longer
// needs and returns the record without them. It never fails the job: a
// rule it could not close stays recorded (and is tried again next time)
// with a warning.
func Cleanup(ctx context.Context, env *jobs.Env, ex remote.Executor, fw model.Firewall, tool string, want []remote.PortSpec, sudo bool) model.Firewall {
	if fw.Keep || fw.Tool == "" || fw.Tool != tool {
		return fw
	}
	need := of(want)
	var keep set
	var closed []string
	for _, s := range parse(fw.Ports) {
		if need.has(s) {
			keep = keep.add(s)
			continue
		}
		p, err := remote.ParsePortSpec(s)
		if err == nil {
			err = closePort(ctx, ex, tool, p, sudo)
		}
		if err != nil {
			keep = keep.add(s)
			env.Warnf("Не удалось закрыть в %s старый порт %s: %v. Закройте его вручную, если он больше не нужен.", tool, s, err)
			continue
		}
		closed = append(closed, s)
	}
	if len(closed) > 0 {
		env.Logf("Закрыто в %s то, что HyRoute открывал для прежних портов: %s.", tool, strings.Join(closed, ", "))
	}
	fw.Ports = keep.String()
	return fw
}
