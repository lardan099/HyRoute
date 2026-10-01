package remote

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Typed read-only operations that inspect a Linux server. Each builds a
// fixed argv; the only variable arguments are validated names and paths.

// OSRelease is /etc/os-release.
type OSRelease struct {
	ID         string // debian, ubuntu, rocky…
	IDLike     string
	VersionID  string // "12", "22.04"
	PrettyName string
}

// ReadOSRelease parses /etc/os-release (absent: zero value, no error).
func ReadOSRelease(ctx context.Context, ex Executor) (OSRelease, error) {
	b, err := ex.ReadFile(ctx, "/etc/os-release", false)
	if errors.Is(err, fs.ErrNotExist) {
		return OSRelease{}, nil
	}
	if err != nil {
		return OSRelease{}, err
	}
	var r OSRelease
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			r.ID = strings.ToLower(v)
		case "ID_LIKE":
			r.IDLike = strings.ToLower(v)
		case "VERSION_ID":
			r.VersionID = v
		case "PRETTY_NAME":
			r.PrettyName = v
		}
	}
	return r, nil
}

var commandNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)

// hasCommandScript looks a program up on the PATH; the name comes as $1.
const hasCommandScript = `command -v "$1" >/dev/null 2>&1`

// hasSystemCommandScript also looks in the sbin directories: a non-root
// SSH session on Debian runs commands with a PATH without them, while
// root's PATH and sudo's secure_path have them.
const hasSystemCommandScript = `PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"; command -v "$1" >/dev/null 2>&1`

// HasCommand reports whether a program is on the PATH (the name is passed
// as a positional parameter, never spliced into the script).
func HasCommand(ctx context.Context, ex Executor, name string) (bool, error) {
	return hasCommand(ctx, ex, hasCommandScript, name)
}

// HasSystemCommand reports whether an administration program (ufw, nft,
// iptables, ss) is installed: on the PATH or in an sbin directory. Such
// programs run as root, by sudo or in root's session, where those
// directories are on the PATH.
func HasSystemCommand(ctx context.Context, ex Executor, name string) (bool, error) {
	return hasCommand(ctx, ex, hasSystemCommandScript, name)
}

func hasCommand(ctx context.Context, ex Executor, script, name string) (bool, error) {
	if !commandNameRe.MatchString(name) {
		return false, errors.New("bad command name")
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"sh", "-c", script, "sh", name}})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}

// PathExists reports whether a path exists (test -e).
func PathExists(ctx context.Context, ex Executor, path string, sudo bool) (bool, error) {
	if err := CheckPath(path); err != nil {
		return false, err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"test", "-e", path}, Sudo: sudo})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}

// HasSystemd reports whether systemd is the init system.
func HasSystemd(ctx context.Context, ex Executor) (bool, error) {
	return PathExists(ctx, ex, "/run/systemd/system", false)
}

// CPUCount is nproc.
func CPUCount(ctx context.Context, ex Executor) (int, error) {
	out, err := run(ctx, ex, "nproc", Cmd{Args: []string{"nproc"}})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(out)
}

// Memory is MemTotal and MemAvailable from /proc/meminfo, in MiB.
func Memory(ctx context.Context, ex Executor) (total, available int, err error) {
	b, err := ex.ReadFile(ctx, "/proc/meminfo", false)
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.Atoi(f[1])
		switch f[0] {
		case "MemTotal:":
			total = kb / 1024
		case "MemAvailable:":
			available = kb / 1024
		}
	}
	return total, available, nil
}

// DiskFree is the free space, in MiB, of the filesystem holding path.
func DiskFree(ctx context.Context, ex Executor, path string) (int, error) {
	if err := CheckPath(path); err != nil {
		return 0, err
	}
	out, err := run(ctx, ex, "df", Cmd{Args: []string{"df", "-Pk", path}})
	if err != nil {
		return 0, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return 0, errors.New("df: no data line")
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 4 {
		return 0, errors.New("df: short line")
	}
	kb, err := strconv.Atoi(f[3])
	return kb / 1024, err
}

// Resolves reports whether the server resolves a name (getent hosts).
func Resolves(ctx context.Context, ex Executor, host string) (bool, error) {
	if !hostRe.MatchString(host) {
		return false, errors.New("bad host name")
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"getent", "hosts", host}})
	if err != nil {
		return false, err
	}
	return res.OK(), nil
}

var hostRe = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// HTTPStatus fetches a URL from the server with curl (or wget) and returns
// the status code; 0 means no answer. Only https URLs of fixed hosts are
// passed by callers.
func HTTPStatus(ctx context.Context, ex Executor, url string) (int, error) {
	if !strings.HasPrefix(url, "https://") || strings.ContainsAny(url, " \n'\"") {
		return 0, errors.New("bad url")
	}
	if ok, err := HasCommand(ctx, ex, "curl"); err != nil {
		return 0, err
	} else if ok {
		res, err := ex.Run(ctx, Cmd{Args: []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "--", url}})
		if err != nil {
			return 0, err
		}
		code, _ := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
		return code, nil
	}
	if ok, err := HasCommand(ctx, ex, "wget"); err != nil || !ok {
		return 0, err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"wget", "-q", "--spider", "-T", "15", "--", url}})
	if err != nil {
		return 0, err
	}
	if res.OK() {
		return 200, nil
	}
	return 0, nil
}

// Listener is a listening socket from ss.
type Listener struct {
	Proto   string // udp, tcp
	Addr    string // local address without port ("*", "0.0.0.0", "[::]")
	Port    int
	Process string // program name when known
	PID     int    // its process ID when known
}

var ssProcRe = regexp.MustCompile(`users:\(\("([^"]+)"(?:,pid=(\d+))?`)

// Listeners lists listening TCP and UDP sockets (ss -Hlntup), as root so
// the owning programs are known.
func Listeners(ctx context.Context, ex Executor, sudo bool) ([]Listener, error) {
	out, err := run(ctx, ex, "ss", Cmd{Args: []string{"ss", "-Hlntup"}, Sudo: sudo})
	if err != nil {
		return nil, err
	}
	var ls []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		l := Listener{Proto: f[0], Addr: local[:i], Port: port}
		if m := ssProcRe.FindStringSubmatch(line); m != nil {
			l.Process = m[1]
			l.PID, _ = strconv.Atoi(m[2])
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// Firewall is what filters incoming traffic on the server.
type Firewall struct {
	UFW       bool // ufw is active
	Firewalld bool // firewalld is running
	// DropPolicy: nftables or iptables drop incoming by default (without
	// ufw/firewalld managing them): the input chain's policy, or its last
	// rule drops or rejects whatever the rules above did not accept.
	DropPolicy bool
	// FinalRule: that default is the last rule, the policy accepts
	// (Oracle Cloud images: -P INPUT ACCEPT, last -A INPUT -j REJECT).
	FinalRule bool
	Tool      string // ufw, firewalld, nftables, iptables, none
}

// ReadFirewall finds the active firewall manager and whether incoming
// connections are denied by default.
func ReadFirewall(ctx context.Context, ex Executor, sudo bool) (Firewall, error) {
	var fw Firewall
	if ok, err := HasSystemCommand(ctx, ex, "ufw"); err != nil {
		return fw, err
	} else if ok {
		res, err := ex.Run(ctx, Cmd{Args: []string{"ufw", "status"}, Sudo: sudo})
		if err != nil {
			return fw, err
		}
		if strings.Contains(string(res.Stdout), "Status: active") {
			fw.UFW, fw.Tool = true, "ufw"
			return fw, nil
		}
	}
	if ok, err := HasSystemCommand(ctx, ex, "firewall-cmd"); err != nil {
		return fw, err
	} else if ok {
		res, err := ex.Run(ctx, Cmd{Args: []string{"firewall-cmd", "--state"}, Sudo: sudo})
		if err != nil {
			return fw, err
		}
		if strings.TrimSpace(string(res.Stdout)) == "running" {
			fw.Firewalld, fw.Tool = true, "firewalld"
			return fw, nil
		}
	}
	// iptables first: with its nftables backend the same rules show in nft
	// too, and the admin knows them as iptables rules.
	if ok, err := HasSystemCommand(ctx, ex, "iptables"); err != nil {
		return fw, err
	} else if ok {
		res, err := ex.Run(ctx, Cmd{Args: []string{"iptables", "-S", "INPUT"}, Sudo: sudo})
		if err != nil {
			return fw, err
		}
		if res.OK() {
			if deny, final := iptablesDeny(string(res.Stdout)); deny {
				fw.DropPolicy, fw.FinalRule, fw.Tool = true, final, "iptables"
				return fw, nil
			}
		}
	}
	if ok, err := HasSystemCommand(ctx, ex, "nft"); err != nil {
		return fw, err
	} else if ok {
		res, err := ex.Run(ctx, Cmd{Args: []string{"nft", "list", "ruleset"}, Sudo: sudo})
		if err != nil {
			return fw, err
		}
		if res.OK() {
			if deny, final := nftDeny(string(res.Stdout)); deny {
				fw.DropPolicy, fw.FinalRule, fw.Tool = true, final, "nftables"
				return fw, nil
			}
		}
	}
	fw.Tool = "none"
	return fw, nil
}

// quotedRe is a quoted word of iptables -S or nft output (a comment or a
// log prefix), which may hold spaces.
var quotedRe = regexp.MustCompile(`"[^"]*"`)

// words splits a rule into words, a quoted string being one.
func words(rule string) []string {
	return strings.Fields(quotedRe.ReplaceAllString(rule, `""`))
}

// iptablesDeny reads iptables -S INPUT: deny when the policy drops, or
// final when the policy accepts but the last rule drops or rejects
// everything that reached it.
func iptablesDeny(rules string) (deny, final bool) {
	var last string
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "-P INPUT DROP":
			return true, false
		case strings.HasPrefix(line, "-A INPUT "):
			last = line
		}
	}
	if last != "" && iptablesCatchAll(words(last)[2:]) {
		return true, true
	}
	return false, false
}

// iptablesCatchAll: a rule (after "-A INPUT") that drops or rejects every
// packet, optionally of one interface and with a comment.
func iptablesCatchAll(w []string) bool {
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "!":
		case "-i", "--in-interface", "--comment":
			i++
		case "-m":
			if i+1 >= len(w) || w[i+1] != "comment" {
				return false
			}
			i++
		case "-j":
			return i+1 < len(w) && (w[i+1] == "DROP" || w[i+1] == "REJECT")
		default:
			return false
		}
	}
	return false
}

// nftDeny reads nft list ruleset: deny when a filter chain on the input
// hook has policy drop, or final when the last rule of one drops or
// rejects everything that reached it.
func nftDeny(ruleset string) (deny, final bool) {
	var (
		inChain bool
		input   bool
		depth   int // braces open inside the chain
		stmt    string
		last    string
	)
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		if !inChain {
			if strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{") {
				inChain, input, depth, stmt, last = true, false, 1, "", ""
			}
			continue
		}
		if depth == 1 && line == "}" {
			if input && last != "" && nftCatchAll(words(last)) {
				final = true
			}
			inChain = false
			continue
		}
		// A rule may hold a set in braces, split over lines.
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		stmt = strings.TrimSpace(stmt + " " + line)
		if depth > 1 {
			continue
		}
		switch {
		case strings.HasPrefix(stmt, "type filter hook input "):
			input = true
			if strings.Contains(stmt, "policy drop") {
				return true, false
			}
		case stmt == "", strings.HasPrefix(stmt, "type "), strings.HasPrefix(stmt, "#"), strings.HasPrefix(stmt, "comment "):
		default:
			last = stmt
		}
		stmt = ""
	}
	return final, final
}

// nftCatchAll: a rule that drops or rejects every packet, optionally of one
// interface, counted and logged.
func nftCatchAll(w []string) bool {
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "drop", "reject":
			return true
		case "counter", "log", "meta":
		case "packets", "bytes", "prefix", "level", "iif", "iifname":
			i++
		default:
			return false
		}
	}
	return false
}

// SystemdUnit is what systemd knows about a unit.
type SystemdUnit struct {
	Name         string
	LoadState    string // loaded, not-found
	ActiveState  string // active, inactive, failed
	FragmentPath string
	ExecStart    string // raw ExecStart property
	User         string
	Group        string
	// WorkingDirectory as in the unit ("~" is the user's home).
	WorkingDirectory string
	UnitFileState    string // enabled, disabled, static…
	Restart          string // no, on-failure, always…
	SubState         string // running, dead, auto-restart…
	MainPID          int
	NRestarts        int
	// MemoryCurrent in bytes (0: not accounted).
	MemoryCurrent int64
	// ActiveEnter is when the unit last became active, in microseconds
	// since boot (0: never).
	ActiveEnter int64
}

// Exists reports whether systemd has the unit.
func (u SystemdUnit) Exists() bool { return u.LoadState != "" && u.LoadState != "not-found" }

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,200}\.service$`)

// CheckUnitName validates a systemd unit name.
func CheckUnitName(name string) error {
	if !unitRe.MatchString(name) {
		return errors.New("bad unit name")
	}
	return nil
}

// Unit reads a unit's properties (systemctl show).
func Unit(ctx context.Context, ex Executor, name string) (SystemdUnit, error) {
	if err := CheckUnitName(name); err != nil {
		return SystemdUnit{}, err
	}
	out, err := run(ctx, ex, "systemctl show", Cmd{Args: []string{"systemctl", "show", "--no-pager", "-p", "LoadState,ActiveState,SubState,FragmentPath,ExecStart,User,Group,WorkingDirectory,UnitFileState,Restart,MainPID,NRestarts,MemoryCurrent,ActiveEnterTimestampMonotonic", "--", name}})
	if err != nil {
		return SystemdUnit{}, err
	}
	u := SystemdUnit{Name: name}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "LoadState":
			u.LoadState = v
		case "ActiveState":
			u.ActiveState = v
		case "FragmentPath":
			u.FragmentPath = v
		case "ExecStart":
			u.ExecStart = v
		case "User":
			u.User = v
		case "Group":
			u.Group = v
		case "WorkingDirectory":
			u.WorkingDirectory = v
		case "UnitFileState":
			u.UnitFileState = v
		case "Restart":
			u.Restart = v
		case "SubState":
			u.SubState = v
		case "MainPID":
			u.MainPID, _ = strconv.Atoi(v)
		case "NRestarts":
			u.NRestarts, _ = strconv.Atoi(v)
		case "MemoryCurrent":
			u.MemoryCurrent, _ = strconv.ParseInt(v, 10, 64) // "[not set]" stays 0
		case "ActiveEnterTimestampMonotonic":
			u.ActiveEnter, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return u, nil
}

// HysteriaVersion runs "<path> version" and returns the version line
// ("v2.12.3"), or "" when the binary does not answer like Hysteria.
func HysteriaVersion(ctx context.Context, ex Executor, path string) (string, error) {
	if err := CheckPath(path); err != nil {
		return "", err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{path, "version"}})
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", nil
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "Version" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

var unitPatternRe = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,100}\*?$`)

// ServiceUnits are the names of service units matching a pattern
// ("hysteria*"): loaded ones, template instances included, and installed
// unit files. Templates themselves ("name@.service") are left out.
func ServiceUnits(ctx context.Context, ex Executor, pattern string) ([]string, error) {
	if !unitPatternRe.MatchString(pattern) {
		return nil, errors.New("bad unit pattern")
	}
	var names []string
	for _, verb := range []string{"list-units", "list-unit-files"} {
		args := []string{"systemctl", verb, "--no-pager", "--no-legend", "--plain", "--type=service"}
		if verb == "list-units" {
			args = append(args, "--all")
		}
		out, err := run(ctx, ex, "systemctl "+verb, Cmd{Args: append(args, "--", pattern)})
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || !strings.HasSuffix(f[0], ".service") || strings.HasSuffix(f[0], "@.service") || slices.Contains(names, f[0]) {
				continue
			}
			if CheckUnitName(f[0]) == nil {
				names = append(names, f[0])
			}
		}
	}
	return names, nil
}

// UnitOfPID is the systemd unit a process belongs to ("" when none).
func UnitOfPID(ctx context.Context, ex Executor, pid int) (string, error) {
	if pid < 1 {
		return "", errors.New("bad pid")
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"ps", "-o", "unit=", "-p", strconv.Itoa(pid)}})
	if err != nil || !res.OK() {
		return "", err
	}
	u := strings.TrimSpace(string(res.Stdout))
	if CheckUnitName(u) != nil {
		return "", nil
	}
	return u, nil
}

// Uptime is how long the machine has been up, in seconds (/proc/uptime).
func Uptime(ctx context.Context, ex Executor) (float64, error) {
	b, err := ex.ReadFile(ctx, "/proc/uptime", false)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("/proc/uptime: empty")
	}
	return strconv.ParseFloat(f[0], 64)
}

// LoadAverage is the 1, 5 and 15 minute load (/proc/loadavg).
func LoadAverage(ctx context.Context, ex Executor) ([3]float64, error) {
	var l [3]float64
	b, err := ex.ReadFile(ctx, "/proc/loadavg", false)
	if err != nil {
		return l, err
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return l, errors.New("/proc/loadavg: short")
	}
	for i := range l {
		if l[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return l, err
		}
	}
	return l, nil
}

// RouteSource is the source address the server uses to reach the
// internet: the route lookup (ip route get) sends nothing. Behind NAT it
// is the private address.
func RouteSource(ctx context.Context, ex Executor) (string, error) {
	out, err := run(ctx, ex, "ip route", Cmd{Args: []string{"ip", "-o", "route", "get", routeProbe}})
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "src" {
			if ip := net.ParseIP(f[i+1]); ip != nil {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("ip route: no source address")
}

// routeProbe is a public address to look the route up for (TEST-NET would
// take a default route too, but some providers route it nowhere).
const routeProbe = "1.1.1.1"
