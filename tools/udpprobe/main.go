// Command udpprobe checks large UDP datagrams through HyRoute: the manual
// release check of ARCHITECTURE §5 «UDP» (bigudp). Dev-only, not shipped.
//
// On a server with IPv4 and IPv6 (echo):
//
//	udpprobe -listen :9999
//
// On the client, with a rule that sends udpprobe.exe through the VPN, then
// with the rule set to Direct:
//
//	udpprobe -to host:9999 -sizes 1000,1472,1473,3000,4060,limit,limit+1 -count 20
//
// Per size it prints the echoes received of those sent, whether they were
// byte-equal, and the limit socks5.MaxUDPPayload computes for the address.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

func main() {
	listen := flag.String("listen", "", "echo server address, e.g. :9999")
	to := flag.String("to", "", "echo server to probe, host:port")
	sizes := flag.String("sizes", "1000,1472,1473,3000,4060,limit,limit+1", "payload sizes; limit = socks5.MaxUDPPayload for the address")
	count := flag.Int("count", 20, "datagrams per size")
	wait := flag.Duration("wait", 2*time.Second, "how long to wait for the echoes of one size")
	flag.Parse()
	var err error
	switch {
	case *listen != "":
		err = serve(*listen)
	case *to != "":
		err = probe(*to, *sizes, *count, *wait)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "udpprobe:", err)
		os.Exit(1)
	}
}

func serve(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	defer pc.Close()
	fmt.Println("echo on", pc.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		pc.WriteToUDPAddrPort(buf[:n], from)
	}
}

func probe(addr, sizeList string, count int, wait time.Duration) error {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	limit := socks5.MaxUDPPayload(socks5.AddrFromAddrPort(ra.AddrPort()))
	var list []int
	for _, s := range strings.Split(sizeList, ",") {
		s = strings.TrimSpace(s)
		n := 0
		switch {
		case s == "limit":
			n = limit
		case strings.HasPrefix(s, "limit+"):
			d, err := strconv.Atoi(s[len("limit+"):])
			if err != nil {
				return fmt.Errorf("bad size %q", s)
			}
			n = limit + d
		default:
			if n, err = strconv.Atoi(s); err != nil {
				return fmt.Errorf("bad size %q", s)
			}
		}
		if n < 8 || n > 65507 {
			return fmt.Errorf("size %d out of range 8…65507", n)
		}
		list = append(list, n)
	}
	conn, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("to %v, Hysteria limit for this address: %d bytes\n", ra, limit)
	fmt.Printf("%8s %10s %6s\n", "size", "echoed", "equal")
	for i, size := range list {
		got, equal := probeSize(conn, uint32(i), size, count, wait)
		mark := ""
		if size > limit {
			mark = "  (over the limit: expect 0)"
		}
		fmt.Printf("%8d %5d/%-4d %6v%s\n", size, got, count, equal, mark)
	}
	return nil
}

// probeSize sends count datagrams of size bytes and counts the echoes.
// Each datagram starts with (round, index) so that late echoes of another
// size are not counted.
func probeSize(conn *net.UDPConn, round uint32, size, count int, wait time.Duration) (int, bool) {
	sent := make([][]byte, count)
	for k := range sent {
		b := make([]byte, size)
		binary.BigEndian.PutUint32(b, round)
		binary.BigEndian.PutUint32(b[4:], uint32(k))
		for j := 8; j < size; j++ {
			b[j] = byte(j*31 + k)
		}
		sent[k] = b
		conn.Write(b)
		time.Sleep(10 * time.Millisecond)
	}
	seen := make([]bool, count)
	got, equal := 0, true
	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(wait))
	for got < count {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			continue // ICMP errors of earlier sends
		}
		if n < 8 || binary.BigEndian.Uint32(buf) != round {
			continue
		}
		k := int(binary.BigEndian.Uint32(buf[4:]))
		if k >= count || seen[k] {
			continue
		}
		seen[k] = true
		got++
		if !bytes.Equal(buf[:n], sent[k]) {
			equal = false
		}
	}
	return got, equal
}
