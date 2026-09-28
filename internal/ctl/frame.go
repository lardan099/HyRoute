package ctl

import (
	"encoding/binary"
	"fmt"
	"io"
)

// A frame on the wire: a big-endian uint32 length, then that many bytes of
// UTF-8 JSON.

// ErrFrameTooBig is a frame length over the reader's limit (or 0). The
// body is not read.
type ErrFrameTooBig struct{ N, Max int }

func (e *ErrFrameTooBig) Error() string {
	return fmt.Sprintf("frame of %d bytes (limit %d)", e.N, e.Max)
}

// WriteFrame writes body as one frame with one Write; a body over max is
// refused before anything is written.
func WriteFrame(w io.Writer, body []byte, max int) error {
	if len(body) == 0 || len(body) > max {
		return &ErrFrameTooBig{N: len(body), Max: max}
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame; a length of 0 or over max is refused after
// the 4 length bytes, before anything is allocated for the body.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n == 0 || n > max {
		return nil, &ErrFrameTooBig{N: n, Max: max}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

// WriteJSON marshals v (no HTML escaping) and writes it as a frame.
func WriteJSON(w io.Writer, v any, max int) error {
	b, err := Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, b, max)
}
