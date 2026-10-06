package remote

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Sample is one reading of a server's counters and gauges. CPU and
// network are counters: a rate needs two samples.
type Sample struct {
	CPUBusy, CPUTotal uint64 // jiffies since boot (/proc/stat)
	MemTotalKiB       uint64
	MemAvailKiB       uint64
	Load              [3]float64
	RxBytes, TxBytes  uint64 // all interfaces except loopback and virtual ones
	UptimeSec         float64
	DiskTotalKiB      uint64 // the filesystem of /
	DiskUsedKiB       uint64
}

// sampleFiles are read with one head(1): it prints "==> file <==" before
// each, so the parts are told apart without guessing.
var sampleFiles = []string{"/proc/stat", "/proc/meminfo", "/proc/loadavg", "/proc/net/dev", "/proc/uptime"}

// ReadSample reads the counters of the machine: two commands, no root.
func ReadSample(ctx context.Context, ex Executor) (Sample, error) {
	var s Sample
	out, err := run(ctx, ex, "head", Cmd{Args: append([]string{"head", "-n", "200", "--"}, sampleFiles...)})
	if err != nil {
		return s, err
	}
	if err := parseSample(&s, out); err != nil {
		return s, err
	}
	df, err := run(ctx, ex, "df", Cmd{Args: []string{"df", "-Pk", "/"}})
	if err != nil {
		return s, err
	}
	s.DiskTotalKiB, s.DiskUsedKiB, err = parseDF(df)
	return s, err
}

func parseSample(s *Sample, out string) error {
	parts := map[string][]string{}
	var cur string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "==> ") && strings.HasSuffix(line, " <==") {
			cur = strings.TrimSuffix(strings.TrimPrefix(line, "==> "), " <==")
			continue
		}
		if cur != "" && line != "" {
			parts[cur] = append(parts[cur], line)
		}
	}
	for _, f := range sampleFiles {
		if len(parts[f]) == 0 {
			return fmt.Errorf("%s: nothing read", f)
		}
	}
	if err := parseStat(s, parts["/proc/stat"]); err != nil {
		return err
	}
	for _, line := range parts["/proc/meminfo"] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			s.MemTotalKiB = kb
		case "MemAvailable:":
			s.MemAvailKiB = kb
		}
	}
	if s.MemTotalKiB == 0 {
		return errors.New("/proc/meminfo: no MemTotal")
	}
	f := strings.Fields(parts["/proc/loadavg"][0])
	if len(f) < 3 {
		return errors.New("/proc/loadavg: short")
	}
	for i := range s.Load {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return fmt.Errorf("/proc/loadavg: %w", err)
		}
		s.Load[i] = v
	}
	parseNetDev(s, parts["/proc/net/dev"])
	if f := strings.Fields(parts["/proc/uptime"][0]); len(f) > 0 {
		s.UptimeSec, _ = strconv.ParseFloat(f[0], 64)
	}
	return nil
}

// parseStat takes the "cpu" line: busy is everything but idle and
// iowait; guest time is already counted in user.
func parseStat(s *Sample, lines []string) error {
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var v [8]uint64
		for i := 0; i < len(v) && i+1 < len(f); i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return fmt.Errorf("/proc/stat: %w", err)
			}
			v[i] = n
		}
		for _, n := range v {
			s.CPUTotal += n
		}
		s.CPUBusy = s.CPUTotal - v[3] - v[4] // idle, iowait
		return nil
	}
	return errors.New("/proc/stat: no cpu line")
}

// virtualIface: traffic of these also passes a real interface (or never
// leaves the machine): containers and bridges, tunnels and VPNs
// (WireGuard, AmneziaWG, OpenVPN, Tailscale, ZeroTier, GRE, IPsec),
// VLANs (eth0.100) and bonds, whose ports are counted.
func virtualIface(name string) bool {
	if name == "lo" || strings.Contains(name, ".") {
		return true
	}
	for _, p := range []string{"veth", "docker", "br", "virbr", "lxdbr", "lxcbr", "vmbr", "cni", "flannel",
		"wg", "awg", "tun", "tap", "ifb", "tailscale", "zt", "gre", "erspan", "ip6gre", "ip_vti", "ip6_vti", "ip6tnl", "sit", "ipsec",
		"vlan", "bond", "team"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func parseNetDev(s *Sample, lines []string) {
	for _, line := range lines {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if virtualIface(name) || len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		s.RxBytes += rx
		s.TxBytes += tx
	}
}

func parseDF(out string) (total, used uint64, err error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0, 0, errors.New("df: no data line")
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 4 {
		return 0, 0, errors.New("df: short line")
	}
	if total, err = strconv.ParseUint(f[1], 10, 64); err != nil {
		return 0, 0, fmt.Errorf("df: %w", err)
	}
	if used, err = strconv.ParseUint(f[2], 10, 64); err != nil {
		return 0, 0, fmt.Errorf("df: %w", err)
	}
	return total, used, nil
}
