//go:build !windows

package relay

import "net"

// sendProgress: the relay runs on Windows only; elsewhere (tests) the
// kernel is not asked and a finished direction is shut down at once.
func sendProgress(net.Conn) (progress, bool) { return progress{}, false }
