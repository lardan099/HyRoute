// Package hopping is the ports of a Hysteria server: a port, or a list of
// ports and ranges for port hopping. Hysteria listens on the lowest port
// and on Linux redirects the others to it itself (nftables, else
// iptables, for each address family it listens on); clients hop between
// them. The package checks a list before it goes into a config, and the
// server before the config is installed: the redirect tool is there, and
// no other program listens on those UDP ports.
package hopping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Range is a port or a range of ports.
type Range struct{ From, To int }

func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Len is the number of ports.
func (r Range) Len() int { return r.To - r.From + 1 }

func (r Range) has(p int) bool { return p >= r.From && p <= r.To }

// Limits.
const (
	// MaxEntries: each entry is a redirect rule per chain and address
	// family on the server.
	MaxEntries = 16
	// The hop interval of the client links, seconds (hy2uri accepts the
	// same).
	MinInterval = 5
	MaxInterval = 3600
)

// Spec is the ports of a server as the admin sets them.
type Spec struct {
	// Ports: "443", "20000-50000"… one entry each.
	Ports []string `json:"ports"`
	// Host is the address Hysteria listens on: "" (every address, IPv4
	// and IPv6), "0.0.0.0" (IPv4 only) or one address of the server.
	Host string `json:"host,omitempty"`
}

// Parse checks the spec and returns its ranges sorted (the first is the
// port Hysteria listens on). Errors are for the admin.
func (s Spec) Parse() ([]Range, error) {
	var rs []Range
	for _, e := range s.Ports {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		r, err := parseEntry(e)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	switch {
	case len(rs) == 0:
		return nil, errors.New("нужен хотя бы один порт")
	case len(rs) > MaxEntries:
		return nil, fmt.Errorf("не больше %d портов и диапазонов: объедините соседние в один диапазон", MaxEntries)
	}
	slices.SortFunc(rs, func(a, b Range) int { return a.From - b.From })
	for i := 1; i < len(rs); i++ {
		if rs[i].From <= rs[i-1].To {
			return nil, fmt.Errorf("%s и %s пересекаются", rs[i-1], rs[i])
		}
	}
	if _, err := listenHost(s.Host); err != nil {
		return nil, err
	}
	return rs, nil
}

func parseEntry(e string) (Range, error) {
	lo, hi, isRange := strings.Cut(e, "-")
	a, err := port(lo)
	if err != nil {
		return Range{}, fmt.Errorf("%q: %w", e, err)
	}
	b := a
	if isRange {
		if b, err = port(hi); err != nil {
			return Range{}, fmt.Errorf("%q: %w", e, err)
		}
		if b < a {
			return Range{}, fmt.Errorf("%q: начало диапазона больше конца", e)
		}
	}
	return Range{a, b}, nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("порт — число от 1 до 65535")
	}
	return n, nil
}

// listenHost is the host part of listen for h ("" stays "").
func listenHost(h string) (string, error) {
	switch h {
	case "", "0.0.0.0":
		return h, nil
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	if err != nil {
		return "", fmt.Errorf("адрес %q: нужен IP-адрес сервера", h)
	}
	if a.Is6() && !a.Is4In6() {
		return "[" + a.String() + "]", nil
	}
	return a.String(), nil
}

// Hopping: more than one port.
func Hopping(rs []Range) bool { return len(rs) > 1 || (len(rs) == 1 && rs[0].Len() > 1) }

// Count is the number of ports.
func Count(rs []Range) int {
	n := 0
	for _, r := range rs {
		n += r.Len()
	}
	return n
}

// Join is the port list of a listen address and of client links.
func Join(rs []Range) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.String()
	}
	return strings.Join(parts, ",")
}

// Listen is the listen address of the spec (Parse checked it).
func (s Spec) Listen(rs []Range) string {
	h, _ := listenHost(s.Host)
	return h + ":" + Join(rs)
}

// FromListen is the spec of a config's listen address.
func FromListen(listen string) (Spec, []Range, error) {
	l, err := hyconfig.ParseListen(listen)
	if err != nil {
		return Spec{}, nil, err
	}
	s := Spec{Host: l.Host}
	if s.Host == "::" {
		s.Host = "" // both families, as an empty host
	}
	for _, e := range strings.Split(l.Ports, ",") {
		s.Ports = append(s.Ports, strings.TrimSpace(e))
	}
	rs, err := s.Parse()
	return s, rs, err
}

// families are the address families Hysteria redirects for a listen host,
// as it decides (an unspecified address: both).
func families(host string) (v4, v6 bool) {
	h := strings.Trim(host, "[]")
	if h == "" {
		return true, true
	}
	a, err := netip.ParseAddr(h)
	if err != nil || a.IsUnspecified() {
		return true, !(err == nil && a.Is4())
	}
	return a.Is4() || a.Is4In6(), a.Is6() && !a.Is4In6()
}

// Busy are the UDP listeners of other programs on the ports: Hysteria
// could not listen on the first, and the redirect would take the others'
// packets away.
func Busy(ls []remote.Listener, rs []Range) []remote.Listener {
	var out []remote.Listener
	for _, l := range ls {
		if l.Proto != "udp" || strings.HasPrefix(l.Process, "hysteria") {
			continue
		}
		if slices.ContainsFunc(rs, func(r Range) bool { return r.has(l.Port) }) && !slices.ContainsFunc(out, func(o remote.Listener) bool { return o.Port == l.Port && o.Process == l.Process }) {
			out = append(out, l)
		}
	}
	return out
}

// ErrNoSS: the server has no ss, so whether other programs use the ports
// is unknown; Check returns it only when nothing else is wrong.
var ErrNoSS = errors.New("hopping: no ss on the server")

// Error is a server that cannot take the ports.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// toolPaths are where the redirect programs may be.
var toolPaths = map[string][]string{
	"nft":       {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"},
	"iptables":  {"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"},
	"ip6tables": {"/usr/sbin/ip6tables", "/sbin/ip6tables", "/usr/bin/ip6tables"},
}

func have(ctx context.Context, ex remote.Executor, tool string) (bool, error) {
	for _, p := range toolPaths[tool] {
		if ok, err := remote.PathExists(ctx, ex, p, false); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// Check checks the server for the ports: no other program listens on
// them, and for hopping a redirect tool is there for every address family
// Hysteria listens on (nftables covers both; iptables needs ip6tables for
// IPv6). A problem is an *Error; without ss on the server the ports are
// not checked and the result is ErrNoSS.
func Check(ctx context.Context, ex remote.Executor, s Spec, rs []Range, sudo bool) error {
	ls, err := remote.Listeners(ctx, ex, sudo)
	var exit *remote.ExitError
	noSS := errors.As(err, &exit)
	if err != nil && !noSS {
		return err
	}
	if err := tools(ctx, ex, s, rs); err != nil {
		return err
	}
	if noSS {
		return ErrNoSS
	}
	if busy := Busy(ls, rs); len(busy) > 0 {
		var who []string
		for _, l := range busy {
			p := l.Process
			if p == "" {
				p = "другая программа"
			}
			who = append(who, fmt.Sprintf("UDP %d — %s", l.Port, p))
		}
		return &Error{"Порты заняты: " + strings.Join(who, ", ") + ". Hysteria забрала бы их пакеты себе: выберите другие порты или остановите эти программы."}
	}
	return nil
}

// tools: for hopping, a redirect tool for every address family.
func tools(ctx context.Context, ex remote.Executor, s Spec, rs []Range) error {
	if !Hopping(rs) {
		return nil
	}
	if ok, err := have(ctx, ex, "nft"); err != nil || ok {
		return err
	}
	v4, v6 := families(s.Host)
	var missing []string
	for _, t := range []struct {
		tool string
		need bool
	}{{"iptables", v4}, {"ip6tables", v6}} {
		if !t.need {
			continue
		}
		if ok, err := have(ctx, ex, t.tool); err != nil {
			return err
		} else if !ok {
			missing = append(missing, t.tool)
		}
	}
	if len(missing) > 0 {
		msg := "Для смены портов Hysteria нужен nftables или " + strings.Join(missing, " и ") + ", а на сервере их нет."
		if v6 && slices.Contains(missing, "ip6tables") && !slices.Contains(missing, "iptables") {
			msg += " Установите nftables или ip6tables, или слушайте только IPv4."
		}
		return &Error{msg}
	}
	return nil
}
