package hysteria

import (
	"encoding/base64"
	"strings"
)

// ECHInline reports whether hysteria takes s as an inline ECHConfigList
// (trimmed; standard, raw standard, URL or raw URL base64; a structurally
// valid list). Any other non-empty value is read by hysteria as a FILE
// PATH (ParseECHConfigList falls back to os.ReadFile) — from hysteria.exe,
// a child of the elevated HyRoute — so imports must treat it as one.
//
// A port of decodeECHConfigList, validateECHConfigList and
// readU16Prefixed of apernet/hysteria app/v2.12.3,
// app/internal/utils/ech.go.
func ECHInline(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && validECHConfigList(b) {
			return true
		}
	}
	return false
}

// validECHConfigList: a uint16-length-prefixed list of at least one
// ECHConfig (uint16 version + uint16-length-prefixed contents), nothing
// after it.
func validECHConfigList(b []byte) bool {
	list, rest, ok := readU16Prefixed(b)
	if !ok || len(rest) != 0 || len(list) == 0 {
		return false
	}
	for len(list) > 0 {
		if len(list) < 2 {
			return false
		}
		if _, list, ok = readU16Prefixed(list[2:]); !ok {
			return false
		}
	}
	return true
}

func readU16Prefixed(b []byte) (body, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(b[0])<<8 | int(b[1])
	if len(b)-2 < n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}
