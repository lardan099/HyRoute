package sniff

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// realHello captures the first TLS record a Go client sends.
func realHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// splitRecords re-frames a single-record hello into records of size n.
func splitRecords(rec []byte, n int) []byte {
	hs := rec[5:]
	var out []byte
	for len(hs) > 0 {
		k := min(n, len(hs))
		out = append(out, 0x16, 0x03, 0x01, byte(k>>8), byte(k))
		out = append(out, hs[:k]...)
		hs = hs[k:]
	}
	return out
}

// syntheticHello builds a ClientHello with the given extensions.
func syntheticHello(exts ...[]byte) []byte {
	var body []byte
	body = append(body, 3, 3)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session id
	body = append(body, 0, 2, 0x13, 1) // cipher suites
	body = append(body, 1, 0)          // compression
	var ext []byte
	for _, e := range exts {
		ext = append(ext, e...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sniExt(name string) []byte {
	entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(name)))...)
	entry = append(entry, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	list = append(list, entry...)
	e := binary.BigEndian.AppendUint16(nil, 0)
	e = binary.BigEndian.AppendUint16(e, uint16(len(list)))
	return append(e, list...)
}

func TestRealClientHello(t *testing.T) {
	rec := realHello(t, "WWW.Example.COM")
	r := Parse(rec)
	if !r.Done || r.Kind != TLS || r.Host != "www.example.com" {
		t.Fatalf("%+v", r)
	}
}

func TestFragmentedBySegments(t *testing.T) {
	rec := realHello(t, "segments.example.org")
	for i := 1; i < len(rec); i++ {
		if r := Parse(rec[:i]); r.Done {
			t.Fatalf("done too early at %d/%d: %+v", i, len(rec), r)
		}
	}
	if r := Parse(rec); r.Host != "segments.example.org" {
		t.Fatalf("%+v", r)
	}
}

func TestFragmentedByRecords(t *testing.T) {
	multi := splitRecords(realHello(t, "records.example.net"), 100)
	for i := 1; i < len(multi); i++ {
		if r := Parse(multi[:i]); r.Done {
			t.Fatalf("done too early at %d: %+v", i, r)
		}
	}
	if r := Parse(multi); !r.Done || r.Host != "records.example.net" {
		t.Fatalf("%+v", r)
	}
}

func TestNoSNIAndIP(t *testing.T) {
	// Go omits SNI for IP server names.
	if r := Parse(realHello(t, "192.0.2.1")); !r.Done || r.Host != "" || r.Kind != TLS {
		t.Fatalf("ip: %+v", r)
	}
	if r := Parse(syntheticHello()); !r.Done || r.Host != "" {
		t.Fatalf("no ext: %+v", r)
	}
	if r := Parse(syntheticHello(sniExt("1.2.3.4"))); r.Host != "" {
		t.Fatalf("ip sni: %+v", r)
	}
	if r := Parse(syntheticHello(sniExt("bad name!"))); r.Host != "" {
		t.Fatalf("bad sni: %+v", r)
	}
}

func TestECHHidesOuterName(t *testing.T) {
	ech := []byte{0xfe, 0x0d, 0, 1, 0}
	r := Parse(syntheticHello(sniExt("public.cloudflare-ech.com"), ech))
	if !r.Done || !r.ECH || r.Host != "" {
		t.Fatalf("%+v", r)
	}
}

func TestGarbageAndTruncated(t *testing.T) {
	for _, b := range [][]byte{
		{0x00, 0x01, 0x02},
		[]byte("SSH-2.0-OpenSSH_9.0\r\n"),
		{0x16, 3, 1, 0, 0},             // zero-length record
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0}, // ServerHello type
		append(splitRecords(syntheticHello(), 10)[:15], 0x17, 3, 3, 0, 1, 0), // other record mid-hello
	} {
		if r := Parse(b); !r.Done || r.Host != "" {
			t.Fatalf("%q: %+v", b, r)
		}
	}
	// A hello that never completes is abandoned at MaxTLS.
	big := []byte{0x16, 3, 1, 0x40, 0x00, 1, 0x00, 0xff, 0xff}
	big = append(big, make([]byte, MaxTLS)...)
	if r := Parse(big); !r.Done {
		t.Fatal("oversized hello must give up")
	}
	// Truncated extension data does not panic.
	h := syntheticHello(sniExt("x.example"))
	for i := 5; i < len(h); i++ {
		Parse(h[:i])
	}
}

func TestHTTPHost(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nUser-Agent: x\r\nhOsT: Api.Example.com:8080\r\nAccept: */*\r\n\r\n"
	for i := 1; i < len(req); i++ {
		r := Parse([]byte(req[:i]))
		if r.Kind != HTTP && i >= 4 {
			t.Fatalf("kind at %d: %+v", i, r)
		}
		if r.Done && r.Host == "" {
			t.Fatalf("done without host at %d", i)
		}
	}
	if r := Parse([]byte(req)); r.Host != "api.example.com" {
		t.Fatalf("%+v", r)
	}
	if r := Parse([]byte("GET / HTTP/1.0\r\n\r\n")); !r.Done || r.Host != "" {
		t.Fatalf("no host: %+v", r)
	}
	if r := Parse([]byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n")); r.Host != "" {
		t.Fatalf("ipv6 literal: %+v", r)
	}
	if r := Parse([]byte("POST / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")); r.Host != "" {
		t.Fatalf("ipv4 literal: %+v", r)
	}
	if r := Parse([]byte("GE")); r.Done {
		t.Fatal("method prefix must wait for more data")
	}
	long := "GET / HTTP/1.1\r\nX: " + string(make([]byte, MaxHTTP)) + "\r\n"
	if r := Parse([]byte(long)); !r.Done {
		t.Fatal("oversized head must give up")
	}
}
