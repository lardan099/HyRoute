package cli

import (
	"bytes"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/ctl"
)

// DecodeInput turns a rules file into text: a UTF-8 BOM is dropped, UTF-16
// with a BOM (Windows PowerShell 5.1 ">" writes UTF-16 LE) is decoded,
// anything else must be valid UTF-8. NUL and other C0 controls except
// TAB/CR/LF are refused: they are not rules, and they keep the request
// within ctl.MaxRequest.
func DecodeInput(b []byte) (string, error) {
	if len(b) > ctl.MaxImport {
		return "", inputError("Файл больше 1 МБ")
	}
	var s string
	switch {
	case bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}):
		b = b[3:]
		fallthrough
	default:
		if !utf8.Valid(b) {
			return "", inputError("Файл не в кодировке UTF-8 (сохраните его в UTF-8)")
		}
		s = string(b)
	case bytes.HasPrefix(b, []byte{0xff, 0xfe}), bytes.HasPrefix(b, []byte{0xfe, 0xff}):
		le := b[0] == 0xff
		b = b[2:]
		if len(b)%2 != 0 {
			return "", inputError("Файл не в кодировке UTF-8 (сохраните его в UTF-8)")
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			if le {
				u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
			} else {
				u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
			}
		}
		s = string(utf16.Decode(u))
		if len(s) > ctl.MaxImport {
			return "", inputError("Файл больше 1 МБ")
		}
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\r' && r != '\n' || r == 0x7f {
			return "", inputError("В файле есть управляющие символы — это не текст правил")
		}
	}
	return s, nil
}

// inputError is a message about the file, a sentence as printed.
type inputError string

func (e inputError) Error() string { return string(e) }

// readLimited reads at most ctl.MaxImport+1 bytes (enough to tell "too
// big").
func readLimited(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, ctl.MaxImport+1))
}
