//go:build windows

package procinfo

import "testing"

// TestWindowedPIDsReusesCallback: the runtime has room for about 2000
// callbacks and never frees one; a callback per call killed the process
// after that many program lists.
func TestWindowedPIDsReusesCallback(t *testing.T) {
	for range 2500 {
		windowedPIDs()
	}
}
