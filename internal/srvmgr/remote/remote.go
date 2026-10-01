// Package remote is how the server manager acts on a managed machine.
//
// Executor is the low-level transport (SSH in sshexec, scripted in fake):
// it runs an argv, not a shell string, and reads and writes files. It is
// internal: the API and the UI never reach it. Everything above it uses
// the typed operations of this package (ops.go), which build fixed
// commands from validated arguments. There is no "run this command"
// anywhere in the API.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"regexp"
	"strings"
)

// Cmd is one program run on the remote machine.
type Cmd struct {
	// Args is the argv; Args[0] is the program. Each argument is quoted
	// for the remote shell, so no argument can inject another command.
	Args []string
	// Sudo runs the program as root (sudo -n: no password prompt; the
	// SSH user is root or has passwordless sudo).
	Sudo bool
	// Stdin is fed to the program.
	Stdin []byte
}

// Result is what a finished program returned.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// OK reports a zero exit code.
func (r Result) OK() bool { return r.ExitCode == 0 }

// Executor runs programs and moves files on one remote machine.
type Executor interface {
	// Run runs cmd to the end. A non-zero exit is not an error: it is in
	// Result.ExitCode. Errors are transport failures.
	Run(ctx context.Context, cmd Cmd) (Result, error)
	// Stream runs cmd and calls line for every line of its stdout until
	// the program exits or ctx ends (journalctl -f).
	Stream(ctx context.Context, cmd Cmd, line func(string)) error
	// ReadFile reads a remote file (as root when sudo).
	ReadFile(ctx context.Context, path string, sudo bool) ([]byte, error)
	// WriteFile replaces a remote file atomically: the data goes to a
	// temporary file in the same directory, gets mode and owner, then is
	// renamed over path.
	WriteFile(ctx context.Context, path string, data []byte, f FileSpec) error
	Close() error
}

// FileSpec is the mode and owner of a written file.
type FileSpec struct {
	Mode  fs.FileMode
	Owner string // user; "" = root
	Group string // group; "" = root
	Sudo  bool   // write as root
}

// Quote quotes s for a POSIX shell: the whole string in single quotes; an
// embedded single quote closes the quoting, is escaped with a backslash
// and reopens it. Safe for any string without NUL.
func Quote(s string) string {
	if s != "" && safeRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var safeRe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// CommandLine is the shell line for cmd: the environment is fixed to the C
// locale (stable output to parse) and sudo never prompts.
func CommandLine(cmd Cmd) (string, error) {
	if len(cmd.Args) == 0 {
		return "", errors.New("empty command")
	}
	var b strings.Builder
	if cmd.Sudo {
		b.WriteString("sudo -n -- ")
	}
	b.WriteString("env LC_ALL=C LANG=C")
	for _, a := range cmd.Args {
		if strings.IndexByte(a, 0) >= 0 {
			return "", fmt.Errorf("argument with NUL byte")
		}
		b.WriteByte(' ')
		b.WriteString(Quote(a))
	}
	return b.String(), nil
}

// CheckPath accepts absolute, clean paths without shell-special surprises:
// what typed operations pass as file arguments.
func CheckPath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.Contains(p, "//") || strings.ContainsAny(p, "\x00\n\r") {
		return fmt.Errorf("bad remote path %q", p)
	}
	return nil
}

// LoopbackDialer opens a TCP connection from the server itself to a port
// on its loopback (SSH direct-tcpip): what listens on 127.0.0.1 there is
// reachable without opening anything to the network. Only loopback: the
// controller never reaches further through a server.
type LoopbackDialer interface {
	DialLoopback(ctx context.Context, port int) (net.Conn, error)
}

// ErrNoTunnel: the executor cannot open connections on the server.
var ErrNoTunnel = errors.New("remote: no tunnel to the server's loopback")

// DialLoopback opens a connection to 127.0.0.1:port on the server of ex,
// ErrNoTunnel when ex cannot.
func DialLoopback(ctx context.Context, ex Executor, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("remote: bad port %d", port)
	}
	d, ok := ex.(LoopbackDialer)
	if !ok {
		return nil, ErrNoTunnel
	}
	return d.DialLoopback(ctx, port)
}
