package cli

import (
	"io"
	"unicode/utf8"
)

// cleanWriter neutralises what a console would act on instead of showing:
// names, log lines and messages come from HyRoute and, through
// subscriptions, from a provider (a profile name is the URI fragment, so
// "%1b]52;c;…%07" is an OSC 52 clipboard write). C0 controls except tab
// and newline (and CR right before LF), DEL, C1 and the bidi overrides and
// isolates become U+FFFD. Every Write is one whole message, so a rune is
// never split across calls.
type cleanWriter struct{ w io.Writer }

func (c cleanWriter) Write(p []byte) (int, error) {
	if !needsClean(p) {
		return c.w.Write(p)
	}
	if _, err := c.w.Write(cleanBytes(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t' && r != '\n'
	case r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func needsClean(p []byte) bool {
	for i := 0; i < len(p); {
		r, n := utf8.DecodeRune(p[i:])
		if unsafeRune(r) && !(r == '\r' && i+1 < len(p) && p[i+1] == '\n') {
			return true
		}
		i += n
	}
	return false
}

func cleanBytes(p []byte) []byte {
	out := make([]byte, 0, len(p)+8)
	for i := 0; i < len(p); {
		r, n := utf8.DecodeRune(p[i:])
		if unsafeRune(r) && !(r == '\r' && i+1 < len(p) && p[i+1] == '\n') {
			out = utf8.AppendRune(out, utf8.RuneError)
		} else {
			out = append(out, p[i:i+n]...)
		}
		i += n
	}
	return out
}
