//go:build !windows

package hysteria

import (
	"io"
	"os"
	"os/exec"
)

// On non-Windows hosts (development, tests) the child is a plain process.

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error { return p.cmd.Wait() }
func (p execProcess) Kill() error { return p.cmd.Process.Kill() }

func startProcess(exe string, args, env []string, out io.Writer) (process, error) {
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}

// writeSecretFile returns the file still open, as on Windows.
func writeSecretFile(path string, data []byte) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return func() { f.Close() }, nil
}

func hideWindow(*exec.Cmd) {}
