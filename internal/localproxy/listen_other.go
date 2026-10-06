//go:build !windows

package localproxy

import (
	"errors"
	"syscall"
)

// classifyReadErr sorts a UDP read error: ECONNREFUSED reports an ICMP
// error for an earlier send.
func classifyReadErr(err error) (tooLarge, transient bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false, false
	}
	switch errno {
	case syscall.EMSGSIZE:
		return true, false
	case syscall.ECONNREFUSED:
		return false, true
	}
	return false, false
}
