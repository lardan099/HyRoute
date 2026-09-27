package geodata

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// span is where one category's message lives in the file.
type span struct {
	off int64
	n   int
}

// buildIndex scans a GeoSiteList/GeoIPList (repeated field 1 of messages
// whose field 1 is the category code) and records every category's
// offset without decoding it.
func buildIndex(path string) (map[string]span, error) {
	f, err := openRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	idx := map[string]span{}
	var off int64
	for {
		key, kn, err := streamVarint(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		off += int64(kn)
		n, ln, err := streamVarint(r)
		if err != nil {
			return nil, err
		}
		off += int64(ln)
		if key>>3 != 1 || key&7 != 2 {
			return nil, fmt.Errorf("geodata: unexpected field %d/%d, not a geosite/geoip file", key>>3, key&7)
		}
		if n > 1<<30 {
			return nil, errors.New("geodata: entry too large")
		}
		head, err := r.Peek(min(int(n), 1024))
		if err != nil && len(head) < min(int(n), 1024) {
			return nil, errTrunc
		}
		code, err := entryCode(head)
		if err != nil {
			return nil, err
		}
		if code != "" {
			idx[strings.ToLower(code)] = span{off: off, n: int(n)}
		}
		if _, err := r.Discard(int(n)); err != nil {
			return nil, errTrunc
		}
		off += int64(n)
	}
	if len(idx) == 0 {
		return nil, errors.New("geodata: no categories in file")
	}
	return idx, nil
}

// entryCode reads field 1 (the category code) from the start of an entry.
func entryCode(head []byte) (string, error) {
	p := pb{head}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return "", err
		}
		if num == 1 && wire == 2 {
			b, err := p.bytes()
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
		if err := p.skip(wire); err != nil {
			return "", err
		}
	}
	return "", errors.New("geodata: entry without a code")
}

func readSpan(path string, s span) ([]byte, error) {
	f, err := openRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, s.n)
	if _, err := f.ReadAt(b, s.off); err != nil {
		return nil, err
	}
	return b, nil
}
