//go:build windows

package localproxy

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// classifyReadErr sorts a UDP read error: WSAEMSGSIZE is a datagram too
// large for the buffer; WSAECONNRESET and WSAENETRESET report ICMP errors
// for an earlier send (Go disables SIO_UDP_CONNRESET but not
// SIO_UDP_NETRESET) and say nothing about the socket.
func classifyReadErr(err error) (tooLarge, transient bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false, false
	}
	switch errno {
	case windows.WSAEMSGSIZE:
		return true, false
	case windows.WSAECONNRESET, windows.WSAENETRESET:
		return false, true
	}
	return false, false
}
