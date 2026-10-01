package quicprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// server answers like a QUIC server: version negotiation for an unknown
// version in a packet of at least 1200 bytes, optionally behind
// Salamander (and silence for anything it cannot read).
func server(t *testing.T, key string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			in := buf[:n]
			if key != "" {
				in = deobfuscate([]byte(key), in)
			}
			if len(in) < packetSize || in[0]&0x80 == 0 || binary.BigEndian.Uint32(in[1:5]) == 1 {
				continue
			}
			dl := int(in[5])
			dcid := in[6 : 6+dl]
			sl := int(in[6+dl])
			scid := in[7+dl : 7+dl+sl]
			out := []byte{0x80, 0, 0, 0, 0, byte(len(scid))}
			out = append(out, scid...)
			out = append(out, byte(len(dcid)))
			out = append(out, dcid...)
			out = binary.BigEndian.AppendUint32(out, 1) // QUIC v1
			if key != "" {
				out = obfuscate([]byte(key), out)
			}
			pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func probe(addr, key string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return Probe(ctx, addr, key)
}

func TestProbe(t *testing.T) {
	plain := server(t, "")
	// rtt may be 0 on loopback: the Windows monotonic clock ticks too
	// coarsely for it.
	if rtt, err := probe(plain, ""); err != nil || rtt < 0 {
		t.Fatalf("plain: %v %v", rtt, err)
	}
	obfs := server(t, "fake-obfs-probe-pass")
	if _, err := probe(obfs, "fake-obfs-probe-pass"); err != nil {
		t.Fatalf("salamander: %v", err)
	}
	// A wrong or missing password gets no answer, as on a real server.
	if _, err := probe(obfs, "wrong-password"); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := probe(obfs, ""); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("no password: %v", err)
	}
	// Nothing there: an error either way (no answer or port unreachable).
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()
	if _, err := probe(dead, ""); err == nil {
		t.Fatal("a closed port answered")
	}
}

func TestVersionNegotiationCheck(t *testing.T) {
	d, s := []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}
	good := append(append(append([]byte{0x80, 0, 0, 0, 0, 4}, s...), 4), d...)
	good = binary.BigEndian.AppendUint32(good, 1)
	if !isVersionNegotiation(good, d, s) {
		t.Fatal("good answer refused")
	}
	for i, bad := range [][]byte{
		good[:len(good)-4], // no versions
		append([]byte{0x80, 0, 0, 0, 1}, good[5:]...),                      // not version 0
		append(append(append([]byte{0x80, 0, 0, 0, 0, 4}, d...), 4), s...), // IDs not swapped
		{0x80, 0, 0},
	} {
		if isVersionNegotiation(bad, d, s) {
			t.Errorf("bad answer %d accepted", i)
		}
	}
}
