package ctl

import (
	"unicode/utf16"
	"unicode/utf8"
)

const (
	hexDigits = "0123456789abcdef"
	backslash = 0x5c
)

// ASCIIJSON re-escapes every non-ASCII rune of a JSON document as \uXXXX
// (a surrogate pair above U+FFFF), so the output is 7-bit and decodes to
// the same value: consoles and PowerShell 5.1 redirection keep it intact.
// Non-ASCII bytes can only be inside strings of valid JSON, where the
// escape means the same rune.
func ASCIIJSON(b []byte) []byte {
	out := make([]byte, 0, len(b)+len(b)/4)
	esc := func(r rune) {
		out = append(out, backslash, 'u', hexDigits[r>>12&0xf], hexDigits[r>>8&0xf], hexDigits[r>>4&0xf], hexDigits[r&0xf])
	}
	for len(b) > 0 {
		c := b[0]
		if c < utf8.RuneSelf {
			out = append(out, c)
			b = b[1:]
			continue
		}
		r, n := utf8.DecodeRune(b)
		b = b[n:]
		if r > 0xffff {
			r1, r2 := utf16.EncodeRune(r)
			esc(r1)
			esc(r2)
			continue
		}
		esc(r) // an invalid byte decodes as U+FFFD
	}
	return out
}
