package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// vps is a server for geo tests: files, the commands the job runs, and a
// service that starts unless bad says the files are wrong.
type vps struct {
	mu        sync.Mutex
	files     map[string][]byte
	dirs      map[string]string // path → "mode owner group"
	modes     map[string]string
	downloads map[string][]byte // URL → body
	github    bool
	state     string // active, inactive, failed
	bad       func(files map[string][]byte) bool
	cmds      []string
	writes    []string
	down      bool // the transport fails
	// hook runs before each command (tests block in it).
	hook func(args []string)
	// slow: Hysteria listens that long after a restart (ACME).
	slow    time.Duration
	started time.Time
}

func newVPS() *vps {
	return &vps{files: map[string][]byte{}, dirs: map[string]string{"/etc/hysteria": "755 root root", "/tmp": "1777 root root"}, modes: map[string]string{}, downloads: map[string][]byte{}, github: true, state: "active"}
}

var _ remote.Executor = (*vps)(nil)

func ok(out string) remote.Result { return remote.Result{Stdout: []byte(out)} }

func failed(code int, stderr string) remote.Result {
	return remote.Result{ExitCode: code, Stderr: []byte(stderr)}
}

func (v *vps) Run(_ context.Context, cmd remote.Cmd) (remote.Result, error) {
	v.mu.Lock()
	hook := v.hook
	v.mu.Unlock()
	if hook != nil {
		hook(cmd.Args)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.down {
		return remote.Result{}, errors.New("connection reset")
	}
	a := cmd.Args
	line := strings.Join(a, " ")
	v.cmds = append(v.cmds, line)
	last := a[len(a)-1]
	switch a[0] {
	case "id":
		if line == "id -un" {
			return ok("root\n"), nil
		}
		return ok("0\n"), nil
	case "uname":
		return ok("Linux\n"), nil
	case "sh":
		if last == "curl" {
			return ok("/usr/bin/curl\n"), nil
		}
		return failed(1, ""), nil
	case "curl":
		dest := a[len(a)-3]
		b, found := v.downloads[last]
		if !found || !v.github {
			return failed(22, "curl: (6) Could not resolve host"), nil
		}
		v.files[dest] = b
		return ok(""), nil
	case "sha256sum":
		b, found := v.files[last]
		if !found {
			return failed(1, "sha256sum: "+last+": No such file or directory"), nil
		}
		s := sha256.Sum256(b)
		return ok(hex.EncodeToString(s[:]) + "  " + last + "\n"), nil
	case "mktemp":
		v.dirs["/tmp/hyroute.abcdefghij"] = "700 root root"
		return ok("/tmp/hyroute.abcdefghij\n"), nil
	case "rm":
		if a[1] == "-rf" {
			for p := range v.files {
				if strings.HasPrefix(p, last+"/") {
					delete(v.files, p)
				}
			}
			delete(v.dirs, last)
			return ok(""), nil
		}
		delete(v.files, last)
		return ok(""), nil
	case "install":
		if a[1] == "-d" {
			v.dirs[last] = a[3] + " " + a[5] + " " + a[7]
			return ok(""), nil
		}
		src := a[len(a)-2]
		b, found := v.files[src]
		if !found {
			return failed(1, "install: cannot stat"), nil
		}
		v.files[last] = b
		v.modes[last] = strings.TrimPrefix(a[2], "0") + " " + a[4] + " " + a[6]
		return ok(""), nil
	case "mv":
		src := a[len(a)-2]
		v.files[last] = v.files[src]
		v.modes[last] = v.modes[src]
		delete(v.files, src)
		delete(v.modes, src)
		return ok(""), nil
	case "cp":
		src := a[len(a)-2]
		v.files[last] = v.files[src]
		v.modes[last] = v.modes[src]
		return ok(""), nil
	case "stat":
		b, found := v.files[last]
		if !found {
			return failed(1, "stat: No such file or directory"), nil
		}
		m := v.modes[last]
		if m == "" {
			m = "640 root hysteria"
		}
		return ok(m + " " + itoa(len(b)) + "\n"), nil
	case "systemctl":
		switch a[1] {
		case "restart":
			v.state, v.started = "active", time.Now()
			if v.bad != nil && v.bad(v.files) {
				v.state = "failed"
			}
			return ok(""), nil
		case "is-active":
			return remote.Result{Stdout: []byte(v.state + "\n"), ExitCode: map[bool]int{true: 0, false: 3}[v.state == "active"]}, nil
		}
	case "ss":
		if v.state == "active" && time.Since(v.started) >= v.slow {
			return ok(`udp UNCONN 0 0 *:443 *:* users:(("hysteria",pid=7,fd=3))` + "\n"), nil
		}
		return ok(""), nil
	case "journalctl":
		return ok("FATAL failed to load geo database\n"), nil
	}
	return failed(127, a[0]+": not simulated"), nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func (v *vps) Stream(context.Context, remote.Cmd, func(string)) error {
	return errors.New("not simulated")
}

func (v *vps) ReadFile(_ context.Context, path string, _ bool) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, found := v.files[path]
	if !found {
		return nil, errors.New("no such file")
	}
	return b, nil
}

func (v *vps) WriteFile(_ context.Context, path string, data []byte, spec remote.FileSpec) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.down {
		return errors.New("connection reset")
	}
	v.files[path] = data
	v.writes = append(v.writes, path)
	return nil
}

func (v *vps) Close() error { return nil }

func (v *vps) file(p string) ([]byte, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, found := v.files[p]
	return b, found
}

func (v *vps) ran(prefix string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// count is how many commands started with prefix.
func (v *vps) count(prefix string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, c := range v.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (v *vps) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cmds, v.writes = nil, nil
}
