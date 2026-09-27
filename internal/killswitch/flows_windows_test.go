//go:build windows

package killswitch

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// stun sends a STUN binding request on c and waits for the answer.
func stun(c net.Conn) error {
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 1)          // binding request
	binary.BigEndian.PutUint32(req[4:], 0x2112A442) // magic cookie
	rand.Read(req[8:20])
	if _, err := c.Write(req); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	_, err := c.Read(buf)
	return err
}

func httpGet(c net.Conn) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req, _ := http.NewRequest("GET", "http://1.1.1.1/", nil)
	req.Header.Set("Connection", "keep-alive")
	if err := req.Write(c); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestExistingFlows: flows opened while the pass filters were on must not
// keep working once they are gone (a UDP socket is authorized once).
func TestExistingFlows(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	u, err := net.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		t.Skip(err)
	}
	defer u.Close()
	tc, err := net.DialTimeout("tcp", "1.1.1.1:80", 5*time.Second)
	if err != nil {
		t.Skip(err)
	}
	defer tc.Close()
	k := &Switch{}
	k.Release()
	defer k.Release()
	if err := k.Arm(0); err != nil {
		t.Fatal(err)
	}
	if err := stun(u); err != nil {
		t.Skipf("no STUN answer even with the pass filters: %v", err)
	}
	if err := httpGet(tc); err != nil {
		t.Skipf("no HTTP answer even with the pass filters: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	udpErr, tcpErr := stun(u), httpGet(tc)
	t.Logf("after Close: udp=%v tcp=%v", udpErr, tcpErr)
	if udpErr == nil {
		t.Error("an open UDP flow still reaches the internet")
	}
	if tcpErr == nil {
		t.Error("an open TCP connection still reaches the internet")
	}
}
