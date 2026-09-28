package rules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of destination ports.
type PortRange struct{ Lo, Hi uint16 }

func (p PortRange) String() string {
	if p.Lo == p.Hi {
		return strconv.Itoa(int(p.Lo))
	}
	return fmt.Sprintf("%d-%d", p.Lo, p.Hi)
}

func (p PortRange) has(port uint16) bool { return port >= p.Lo && port <= p.Hi }

// ParsePorts parses a port list: "443", "80, 443", "27000-27200 27015"
// (commas, semicolons or spaces between items). "" is no limit (nil).
func ParsePorts(s string) ([]PortRange, error) {
	var out []PortRange
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
		lo, hi, isRange := strings.Cut(f, "-")
		if !isRange {
			hi = lo
		}
		a, err1 := parsePort(lo)
		b, err2 := parsePort(hi)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("неверный порт %q: нужно число от 1 до 65535 или диапазон вида 27000-27200", f)
		}
		if a > b {
			return nil, fmt.Errorf("неверный диапазон портов %q: первое число больше второго", f)
		}
		out = append(out, PortRange{a, b})
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 || strings.HasPrefix(s, "+") {
		return 0, errors.New("bad port")
	}
	return uint16(n), nil
}

// FormatPorts is the canonical form of a port list ("80,443,27000-27200");
// the input is returned as is when it does not parse.
func FormatPorts(s string) string {
	ps, err := ParsePorts(s)
	if err != nil {
		return strings.TrimSpace(s)
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

func (r *compiled) matchPort(port uint16) bool {
	if len(r.ports) == 0 {
		return true
	}
	for _, p := range r.ports {
		if p.has(port) {
			return true
		}
	}
	return false
}

// coversPorts: every port of b is a port of r.
func (r *compiled) coversPorts(b *compiled) bool {
	if len(r.ports) == 0 {
		return true
	}
	if len(b.ports) == 0 {
		return false
	}
	for _, bp := range b.ports {
		// Walk the range through r's ranges, which may be adjacent.
		lo := int(bp.Lo)
		for lo <= int(bp.Hi) {
			next := -1
			for _, rp := range r.ports {
				if rp.has(uint16(lo)) {
					next = int(rp.Hi) + 1
					break
				}
			}
			if next < 0 {
				return false
			}
			lo = next
		}
	}
	return true
}

func portsText(ps []PortRange) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}
