// Package geodata reads v2ray/Xray rule databases (geosite.dat,
// geoip.dat): the domain and IP lists behind "geosite:youtube" and
// "geoip:ru". The files are large (tens of megabytes), so only an index of
// category offsets is kept and a category is decoded when a rule uses it.
package geodata

import (
	"errors"
	"fmt"
	"io"
)

// Minimal protobuf wire reading: the .dat formats need varints and
// length-delimited fields only.

var errTrunc = errors.New("geodata: truncated message")

// recoverDecode turns a panic on a damaged category into an error: a bad
// database must cost a rule warning, not the (elevated) process.
func recoverDecode(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("geodata: damaged category: %v", r)
	}
}

type pb struct {
	b []byte
}

func (p *pb) done() bool { return len(p.b) == 0 }

func (p *pb) varint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if i >= len(p.b) {
			return 0, errTrunc
		}
		c := p.b[i]
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			p.b = p.b[i+1:]
			return v, nil
		}
	}
	return 0, errors.New("geodata: bad varint")
}

// field returns the next field number and wire type.
func (p *pb) field() (int, int, error) {
	k, err := p.varint()
	if err != nil {
		return 0, 0, err
	}
	return int(k >> 3), int(k & 7), nil
}

func (p *pb) bytes() ([]byte, error) {
	n, err := p.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(p.b)) {
		return nil, errTrunc
	}
	b := p.b[:n]
	p.b = p.b[n:]
	return b, nil
}

func (p *pb) skip(wire int) error {
	switch wire {
	case 0:
		_, err := p.varint()
		return err
	case 1:
		if len(p.b) < 8 {
			return errTrunc
		}
		p.b = p.b[8:]
	case 2:
		_, err := p.bytes()
		return err
	case 5:
		if len(p.b) < 4 {
			return errTrunc
		}
		p.b = p.b[4:]
	default:
		return errors.New("geodata: unsupported wire type")
	}
	return nil
}

// streamVarint reads a varint from a byte reader and returns it with its
// encoded length.
func streamVarint(r io.ByteReader) (uint64, int, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		c, err := r.ReadByte()
		if err != nil {
			if i > 0 && err == io.EOF {
				err = errTrunc
			}
			return 0, i, err
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 10, errors.New("geodata: bad varint")
}
