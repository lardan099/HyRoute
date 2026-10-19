// Package quicprobe checks from the controller that a Hysteria server's
// UDP port answers, without connecting as a client.
//
// It sends one QUIC long-header packet of a reserved version (RFC 9000
// §15: 0x?a?a?a?a) padded to 1200 bytes. A QUIC server must answer a
// version it does not support with a Version Negotiation packet (§6,
// §17.2.1) that echoes the connection IDs, so a valid answer proves the
// port is reachable and a QUIC server listens on it. No client password is
// involved. With Salamander obfuscation the packet goes out obfuscated
// with the obfs password (the server drops anything else) and the answer
// is deobfuscated.
package quicprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/blake2b"
)

// ErrNoAnswer: nothing came back in time (a firewall, nothing listening,
// or a wrong obfs password).
var ErrNoAnswer = errors.New("no answer")

// reservedVersion forces version negotiation (RFC 9000 §15).
const reservedVersion = 0x1a2a3a4a

const packetSize = 1200 // the least a server answers a new version for

// packet is the probe with dcid and scid.
func packet(dcid, scid []byte) []byte {
	b := make([]byte, 0, packetSize)
	b = append(b, 0xc0) // long header, fixed bit
	b = binary.BigEndian.AppendUint32(b, reservedVersion)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	return append(b, make([]byte, packetSize-len(b))...)
}

// isVersionNegotiation checks an answer: version 0 and our connection
// IDs swapped (its DCID is our SCID, its SCID our DCID).
func isVersionNegotiation(b, dcid, scid []byte) bool {
	if len(b) < 7 || b[0]&0x80 == 0 || binary.BigEndian.Uint32(b[1:5]) != 0 {
		return false
	}
	p := 5
	n := int(b[p])
	p++
	if len(b) < p+n || !bytes.Equal(b[p:p+n], scid) {
		return false
	}
	p += n
	if len(b) < p+1 {
		return false
	}
	n = int(b[p])
	p++
	if len(b) < p+n || !bytes.Equal(b[p:p+n], dcid) {
		return false
	}
	p += n
	return len(b) >= p+4 && (len(b)-p)%4 == 0 // the supported versions
}

// Salamander as Hysteria implements it: an 8-byte random salt, then the
// packet XORed with BLAKE2b-256(password || salt), repeated.
const saltLen = 8

func salamander(key, salt []byte) [32]byte {
	return blake2b.Sum256(append(append([]byte{}, key...), salt...))
}

func obfuscate(key, p []byte) []byte {
	out := make([]byte, saltLen+len(p))
	rand.Read(out[:saltLen])
	h := salamander(key, out[:saltLen])
	for i, c := range p {
		out[saltLen+i] = c ^ h[i%len(h)]
	}
	return out
}

func deobfuscate(key, p []byte) []byte {
	if len(p) <= saltLen {
		return nil
	}
	h := salamander(key, p[:saltLen])
	out := make([]byte, len(p)-saltLen)
	for i := range out {
		out[i] = p[saltLen+i] ^ h[i%len(h)]
	}
	return out
}

// Probe sends the packet to addr (host:port) and waits for the version
// negotiation until ctx ends; salamander is the obfs password ("" when
// the server has none). It returns the round trip.
func Probe(ctx context.Context, addr, salamander string) (time.Duration, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	dcid, scid := make([]byte, 8), make([]byte, 8)
	rand.Read(dcid)
	rand.Read(scid)
	out := packet(dcid, scid)
	key := []byte(salamander)
	if len(key) > 0 {
		out = obfuscate(key, out)
	}
	start := time.Now()
	// UDP may lose the first packet: send twice, a moment apart.
	go func() {
		c.Write(out)
		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Millisecond):
			c.Write(out)
		}
	}()
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || ctx.Err() != nil {
				return 0, ErrNoAnswer
			}
			return 0, err // e.g. ICMP port unreachable
		}
		in := buf[:n]
		if len(key) > 0 {
			in = deobfuscate(key, in)
		}
		if isVersionNegotiation(in, dcid, scid) {
			return time.Since(start), nil
		}
	}
}
