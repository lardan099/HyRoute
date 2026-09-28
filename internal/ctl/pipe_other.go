//go:build !windows

package ctl

import (
	"net"
	"time"
)

// The transport exists on Windows only; these let dependants build and
// test elsewhere.

type Listener struct{}

func (l *Listener) Accept() (net.Conn, Identity, bool, error) {
	return nil, Identity{}, false, ErrUnsupported
}
func (l *Listener) Close() error { return nil }

// Dial reports ErrUnsupported.
func Dial(string, time.Duration, []string) (net.Conn, uint32, error) {
	return nil, 0, ErrUnsupported
}

// FindPipes reports ErrUnsupported.
func FindPipes() ([]string, error) { return nil, ErrUnsupported }

// ProbeRunEvent reports ErrUnsupported.
func ProbeRunEvent(string, []string) (RunState, error) { return RunAbsent, ErrUnsupported }
