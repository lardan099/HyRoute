// Package sniff extracts the destination name from the first bytes a client
// sends: the SNI of a TLS ClientHello (reassembled across records and
// segments) or the Host header of a plaintext HTTP request. Nothing is
// modified; the caller forwards the buffered bytes unchanged.
package sniff

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/lardan099/hyroute/internal/rules"
)

type Kind uint8

const (
	Unknown Kind = iota
	TLS
	HTTP
)

func (k Kind) String() string { return [...]string{"unknown", "tls", "http"}[k] }

const (
	// MaxTLS bounds ClientHello reassembly (post-quantum key shares make it
	// ~1.8 KB, larger with many extensions).
	MaxTLS = 16 * 1024
	// MaxHTTP bounds the request head.
	MaxHTTP = 8 * 1024
)

// Result of examining a prefix of the stream.
type Result struct {
	Kind Kind
	Host string // normalized; empty if absent
	// ECH: the ClientHello carries encrypted_client_hello, so the visible
	// SNI is only the public (outer) name and is not reported.
	ECH bool
	// Done: no more data is needed (a verdict was reached).
	Done bool
}

// Parse examines buf, the bytes received so far.
func Parse(buf []byte) Result {
	if len(buf) == 0 {
		return Result{}
	}
	if buf[0] == 0x16 {
		return parseTLS(buf)
	}
	if isHTTPPrefix(buf) {
		return parseHTTP(buf)
	}
	return Result{Done: true}
}

var methods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func isHTTPPrefix(buf []byte) bool {
	for _, m := range methods {
		n := min(len(buf), len(m))
		if string(buf[:n]) == m[:n] {
			return true
		}
	}
	return false
}

func parseHTTP(buf []byte) Result {
	r := Result{Kind: HTTP}
	head := buf
	if len(head) > MaxHTTP {
		head = head[:MaxHTTP]
	}
	end := bytes.Index(head, []byte("\r\n\r\n"))
	lines := head
	if end >= 0 {
		lines = head[:end+2]
	}
	// Request line first, then headers; stop at the first complete Host.
	first := true
	for {
		i := bytes.Index(lines, []byte("\r\n"))
		if i < 0 {
			break
		}
		line := string(lines[:i])
		lines = lines[i+2:]
		if first {
			first = false
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			r.Host = normHost(strings.TrimSpace(v))
			r.Done = true
			return r
		}
	}
	r.Done = end >= 0 || len(buf) >= MaxHTTP
	return r
}

// normHost strips a port and brackets; IP literals are not names.
func normHost(h string) string {
	if strings.HasPrefix(h, "[") {
		return "" // IPv6 literal
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	if isIPv4Literal(h) || !validName(h) {
		return ""
	}
	return rules.NormalizeDomain(h)
}

func isIPv4Literal(h string) bool {
	if h == "" {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func validName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c > 0x7f:
		default:
			return false
		}
	}
	return true
}

// parseTLS reassembles handshake bytes from consecutive handshake records
// until the ClientHello is complete.
func parseTLS(buf []byte) Result {
	r := Result{Kind: TLS}
	var hs []byte
	rest := buf
	for len(rest) >= 5 {
		if rest[0] != 0x16 {
			r.Done = true // other record type before the hello completed
			return r
		}
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if n == 0 || n > 1<<14+2048 {
			r.Done = true
			return r
		}
		body := rest[5:]
		if len(body) > n {
			body = body[:n]
		}
		hs = append(hs, body...)
		if len(body) < n {
			break // record continues in the next segment
		}
		rest = rest[5+n:]
		if done, res := helloFrom(hs, r); done {
			return res
		}
	}
	if done, res := helloFrom(hs, r); done {
		return res
	}
	if len(buf) >= MaxTLS {
		r.Done = true
	}
	return r
}

func helloFrom(hs []byte, r Result) (bool, Result) {
	if len(hs) < 4 {
		return false, r
	}
	if hs[0] != 1 { // not a ClientHello
		r.Done = true
		return true, r
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if n > MaxTLS {
		r.Done = true
		return true, r
	}
	if len(hs) < 4+n {
		return false, r
	}
	host, ech := parseClientHello(hs[4 : 4+n])
	r.Done = true
	r.ECH = ech
	if !ech {
		r.Host = host
	}
	return true, r
}

const (
	extServerName = 0x0000
	extECH        = 0xfe0d
)

func parseClientHello(b []byte) (host string, ech bool) {
	// legacy_version(2) random(32)
	if len(b) < 34 {
		return "", false
	}
	b = b[34:]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		var n int
		if lenBytes == 1 {
			n = int(b[0])
		} else {
			n = int(binary.BigEndian.Uint16(b))
		}
		if len(b) < lenBytes+n {
			return false
		}
		b = b[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session_id, cipher_suites, compression
		return "", false
	}
	if len(b) < 2 {
		return "", false
	}
	ext := b[2:]
	if n := int(binary.BigEndian.Uint16(b)); n < len(ext) {
		ext = ext[:n]
	}
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		n := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			break
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		switch typ {
		case extECH:
			ech = true
		case extServerName:
			host = parseSNI(data)
		}
	}
	return host, ech
}

func parseSNI(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	list := d[2:]
	if n := int(binary.BigEndian.Uint16(d)); n < len(list) {
		list = list[:n]
	}
	for len(list) >= 3 {
		typ := list[0]
		n := int(binary.BigEndian.Uint16(list[1:]))
		if len(list) < 3+n {
			return ""
		}
		name := string(list[3 : 3+n])
		list = list[3+n:]
		if typ == 0 && validName(name) && !isIPv4Literal(name) {
			return rules.NormalizeDomain(name)
		}
	}
	return ""
}
