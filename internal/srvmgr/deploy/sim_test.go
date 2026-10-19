package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// sim is a small Debian VPS for deploy tests: files, users, a systemd that
// starts Hysteria when its binary and config are sound, listeners, curl,
// ufw. Faults are injected with failOn (a command prefix fails) and
// badConfig (the service dies with this config).
type sim struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
	users map[string]bool
	// modes are "mode owner group" of files and directories ("644 root
	// root" when not set).
	modes     map[string]string
	downloads map[string][]byte // URL → body for curl on the server
	github    bool
	ufw       bool
	ufwRules  map[string]bool // "443/udp", "20000:50000/udp"

	unitLoaded string // unit text after the last daemon-reload
	enabled    bool
	state      string // active, inactive, failed
	running    []byte // config the running service uses

	failOn    map[string]bool
	badConfig func(cfg []byte) bool
	// badBinary: the service dies with this binary.
	badBinary func(bin []byte) bool
	// silent: the service runs but never says it serves (a certificate
	// that is not issued).
	silent bool
	// noSS: iproute2 is not installed.
	noSS bool
	// nonRoot: the SSH user is not root and has no sudo.
	nonRoot bool
	// squatter: another Hysteria (its own unit, a container) holds UDP
	// 443 with this PID, and the service cannot take it; squatsLate: it
	// shows only once the service has started.
	squatter   int
	squatsLate bool
	// before sees every command before it runs (outside the lock).
	before func(line string)
	// written sees every written path after the write (outside the lock).
	written func(path string)

	cmds   []string
	writes []string
}

func newSim() *sim {
	return &sim{
		files: map[string][]byte{
			"/etc/os-release": []byte("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"),
			"/proc/meminfo":   []byte("MemTotal:        1015800 kB\nMemAvailable:     700000 kB\n"),
		},
		dirs:      map[string]bool{"/etc": true, "/tmp": true, "/usr/local/bin": true, "/etc/systemd/system": true},
		users:     map[string]bool{"root": true},
		modes:     map[string]string{},
		downloads: map[string][]byte{},
		ufwRules:  map[string]bool{},
		github:    true,
		state:     "inactive",
		failOn:    map[string]bool{},
	}
}

var _ remote.Executor = (*sim)(nil)

func ok(out string) remote.Result { return remote.Result{Stdout: []byte(out)} }
func fail(code int, stderr string) remote.Result {
	return remote.Result{ExitCode: code, Stderr: []byte(stderr)}
}

func (s *sim) exists(p string) bool {
	_, f := s.files[p]
	return f || s.dirs[p]
}

// start is systemd starting the unit: it runs if the binary, the user and
// a valid config are there.
func (s *sim) start() {
	cfg, okCfg := s.files[ConfigPath]
	bin, okBin := s.files[BinaryPath]
	okBin = okBin && (s.badBinary == nil || !s.badBinary(bin))
	c, err := hyconfig.ParseServer(cfg)
	if !okBin || !okCfg || err != nil || hyconfig.HasErrors(c.Validate()) || !s.users[User] || (s.badConfig != nil && s.badConfig(cfg)) {
		s.state, s.running = "failed", nil
		return
	}
	s.state, s.running = "active", cfg
}

func (s *sim) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	if s.before != nil {
		s.before(strings.Join(cmd.Args, " "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := cmd.Args
	line := strings.Join(a, " ")
	s.cmds = append(s.cmds, line)
	for p := range s.failOn {
		if strings.HasPrefix(line, p) {
			return fail(1, "simulated failure: "+p), nil
		}
	}
	if cmd.Sudo && s.nonRoot {
		return fail(1, "sudo: a password is required"), nil
	}
	last := a[len(a)-1]
	switch a[0] {
	case "true":
		return ok(""), nil
	case "id":
		switch {
		case line == "id -un" && s.nonRoot:
			return ok("deploy\n"), nil
		case line == "id -u" && s.nonRoot:
			return ok("1000\n"), nil
		case line == "id -un":
			return ok("root\n"), nil
		case line == "id -u":
			return ok("0\n"), nil
		case s.users[last]:
			return ok("999\n"), nil
		}
		return fail(1, "no such user"), nil
	case "uname":
		if a[1] == "-n" {
			return ok("vps\n"), nil
		}
		if a[1] == "-m" {
			return ok("x86_64\n"), nil
		}
		return ok("Linux 6.1.0\n"), nil
	case "test":
		if last == "/run/systemd/system" || last == "/usr/sbin/nft" || last == "/usr/sbin/nologin" || s.exists(last) {
			return ok(""), nil
		}
		return fail(1, ""), nil
	case "nproc":
		return ok("2\n"), nil
	case "df":
		return ok("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 20511312 3000000 16448592 16% /\n"), nil
	case "getent":
		return ok("192.0.2.200 github.com\n"), nil
	case "sh":
		switch {
		case last == "curl", last == "ss" && !s.noSS:
			return ok(""), nil
		case last == "ufw":
			if s.ufw {
				return ok(""), nil
			}
		}
		return fail(1, ""), nil
	case "curl":
		if strings.Contains(line, "%{http_code}") {
			if s.github {
				return ok("200"), nil
			}
			return ok("000"), nil
		}
		dest := a[len(a)-3]
		b, found := s.downloads[last]
		if !found || !s.github {
			return fail(22, "curl: (22) The requested URL returned error: 404"), nil
		}
		s.files[dest] = b
		return ok(""), nil
	case "ufw":
		switch {
		case a[1] == "status":
			return ok("Status: active\n"), nil
		case line == "ufw show added":
			out := "Added user rules (see 'ufw status' for running firewall):\n"
			for _, r := range sortedKeys(s.ufwRules) {
				out += "ufw allow " + r + "\n"
			}
			return ok(out), nil
		case a[1] == "allow":
			if s.ufwRules[last] {
				return ok("Skipping adding existing rule\n"), nil
			}
			s.ufwRules[last] = true
			return ok("Rule added\n"), nil
		case strings.HasPrefix(line, "ufw --force delete allow "):
			delete(s.ufwRules, last)
			return ok("Rule deleted\n"), nil
		}
	case "ss":
		if s.noSS {
			return fail(127, "env: 'ss': No such file or directory"), nil
		}
		if s.squatter != 0 && (s.state == "active" || !s.squatsLate) {
			return ok(fmt.Sprintf("udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=%d,fd=3))\n", s.squatter)), nil
		}
		if s.state == "active" {
			port := 443
			if c, err := hyconfig.ParseServer(s.running); err == nil {
				l, _ := hyconfig.ParseListen(c.Listen)
				port = l.First
			}
			return ok(fmt.Sprintf("udp UNCONN 0 0 *:%d *:* users:((\"hysteria\",pid=4242,fd=7))\n", port)), nil
		}
		return ok(""), nil
	case "systemctl":
		return s.systemctl(a[1:])
	case "journalctl":
		if strings.Contains(line, " -o json ") {
			// The running process says it serves, unless it never gets
			// that far.
			if s.state != "active" || s.silent {
				return ok(""), nil
			}
			return ok(`{"MESSAGE":"2026-01-01T00:00:00Z\tINFO\tserver up and running","PRIORITY":"6","_PID":"4242"}` + "\n"), nil
		}
		return ok("server up and running\nfatal error: simulated crash\n"), nil
	case "sha256sum":
		b, found := s.files[last]
		if !found {
			return fail(1, "sha256sum: "+last+": No such file or directory"), nil
		}
		sum := sha256.Sum256(b)
		return ok(hex.EncodeToString(sum[:]) + "  " + last + "\n"), nil
	case "mktemp":
		s.dirs["/tmp/hyroute.abcdefghij"] = true
		return ok("/tmp/hyroute.abcdefghij\n"), nil
	case "rm":
		if a[1] == "-rf" {
			for p := range s.files {
				if strings.HasPrefix(p, last+"/") {
					delete(s.files, p)
				}
			}
			delete(s.dirs, last)
		} else {
			delete(s.files, last)
		}
		return ok(""), nil
	case "install":
		// install [-d] -m MODE -o OWNER -g GROUP -- …
		i := 1
		if a[1] == "-d" {
			i = 2
		}
		mode := strings.TrimPrefix(a[i+1], "0") + " " + a[i+3] + " " + a[i+5]
		if a[1] == "-d" {
			s.dirs[last] = true
			s.modes[last] = mode
			return ok(""), nil
		}
		src := a[len(a)-2]
		b, found := s.files[src]
		if !found {
			return fail(1, "install: cannot stat"), nil
		}
		s.files[last] = append([]byte(nil), b...)
		s.modes[last] = mode
		return ok(""), nil
	case "mv", "cp":
		src := a[len(a)-2]
		b, found := s.files[src]
		if !found {
			return fail(1, a[0]+": cannot stat "+src), nil
		}
		s.files[last] = b
		if m, found := s.modes[src]; found {
			s.modes[last] = m
		} else {
			delete(s.modes, last)
		}
		if a[0] == "mv" {
			delete(s.files, src)
			delete(s.modes, src)
		}
		return ok(""), nil
	case "readlink":
		return ok(last + "\n"), nil
	case "stat":
		if a[3] == "%u %g %a" {
			// The binary and its directories are root's.
			return ok(strings.Repeat("0 0 755\n", len(a)-5)), nil
		}
		if !s.exists(last) {
			return fail(1, "stat: cannot statx '"+last+"': No such file or directory"), nil
		}
		m := s.modes[last]
		if m == "" {
			m = "644 root root"
		}
		return ok(fmt.Sprintf("%s %d\n", m, len(s.files[last]))), nil
	case "chown":
		if !s.exists(last) {
			return fail(1, "chown: No such file or directory"), nil
		}
		f := strings.Fields(s.modeOf(last))
		og := strings.SplitN(a[2], ":", 2)
		s.modes[last] = f[0] + " " + og[0] + " " + og[1]
		return ok(""), nil
	case "chmod":
		if !s.exists(last) {
			return fail(1, "chmod: No such file or directory"), nil
		}
		f := strings.Fields(s.modeOf(last))
		s.modes[last] = strings.TrimPrefix(a[2], "0") + " " + f[1] + " " + f[2]
		return ok(""), nil
	case "useradd":
		s.users[last] = true
		s.dirs[Home] = true
		return ok(""), nil
	case BinaryPath:
		// A fake binary tells the version it was made for.
		if b, found := s.files[BinaryPath]; found {
			v, isFake := strings.CutPrefix(string(b), "#!fake hysteria ")
			if !isFake {
				v = "v2.99.0"
			}
			return ok("Version:\t" + v + "\n"), nil
		}
		return fail(127, "not found"), nil
	}
	return fail(127, "sim: unknown command "+line), nil
}

func (s *sim) systemctl(a []string) (remote.Result, error) {
	switch a[0] {
	case "show":
		if s.unitLoaded == "" {
			return ok("LoadState=not-found\nActiveState=inactive\nFragmentPath=\nExecStart=\nUser=\n"), nil
		}
		pid := "0"
		if s.state == "active" {
			pid = "4242"
		}
		return ok("LoadState=loaded\nActiveState=" + s.state + "\nFragmentPath=" + UnitPath + "\nExecStart=\nUser=hysteria\nMainPID=" + pid + "\n"), nil
	case "is-active":
		if s.state == "active" {
			return ok("active\n"), nil
		}
		return remote.Result{Stdout: []byte(s.state + "\n"), ExitCode: 3}, nil
	case "is-enabled":
		if s.enabled {
			return ok("enabled\n"), nil
		}
		return remote.Result{Stdout: []byte("disabled\n"), ExitCode: 1}, nil
	case "daemon-reload":
		s.unitLoaded = string(s.files[UnitPath])
		return ok(""), nil
	}
	if s.unitLoaded == "" {
		return fail(5, "Unit "+Unit+" not found."), nil
	}
	switch a[0] {
	case "enable":
		s.enabled = true
	case "disable":
		s.enabled = false
	case "restart", "start":
		s.start()
	case "stop":
		s.state, s.running = "inactive", nil
	}
	return ok(""), nil
}

func (s *sim) Stream(ctx context.Context, cmd remote.Cmd, line func(string)) error {
	return fmt.Errorf("sim: no streams")
}

func (s *sim) ReadFile(ctx context.Context, path string, sudo bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sudo && s.nonRoot {
		return nil, fmt.Errorf("cat %s: sudo: a password is required", path)
	}
	b, found := s.files[path]
	if !found {
		return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
	}
	return append([]byte(nil), b...), nil
}

func (s *sim) WriteFile(ctx context.Context, path string, data []byte, f remote.FileSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, fmt.Sprintf("%s %04o %s:%s", path, f.Mode.Perm(), or(f.Owner, "root"), or(f.Group, "root")))
	s.files[path] = append([]byte(nil), data...)
	s.modes[path] = fmt.Sprintf("%o %s %s", f.Mode.Perm(), or(f.Owner, "root"), or(f.Group, "root"))
	hook := s.written
	s.mu.Unlock()
	if hook != nil {
		hook(path)
	}
	s.mu.Lock()
	return nil
}

// modeOf is "mode owner group" of a path (locked).
func (s *sim) modeOf(p string) string {
	if m := s.modes[p]; m != "" {
		return m
	}
	return "644 root root"
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func (s *sim) Close() error { return nil }

// ran reports whether a command starting with prefix ran.
func (s *sim) ran(prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rules are the ufw rules.
func (s *sim) rules() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.ufwRules)
}

func (s *sim) fileList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (s *sim) file(p string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, found := s.files[p]
	return b, found
}

func (s *sim) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds, s.writes = nil, nil
}
