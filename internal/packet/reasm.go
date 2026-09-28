package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

var (
	ErrFragOverlap = errors.New("packet: overlapping fragments")
	ErrFragInvalid = errors.New("packet: invalid fragment")
)

// maxPieces bounds the fragments of one datagram (a 64 KB datagram in
// 8-byte pieces would be 8192 of them).
const maxPieces = 128

// Assembly collects the fragments of one datagram (Reassemblable ones)
// together with a caller value per fragment (the engine: its divert
// address), so that the original fragments can be sent on unchanged.
// Not safe for concurrent use.
//
// Everything that ties a fragment to the datagram is checked on Add: no
// overlaps (RFC 5722; an exact duplicate is ignored), the UDP header in the
// first fragment (RFC 7112), and the UDP length of that first fragment
// equal to the assembled size. Any error poisons the datagram: the caller
// drops it whole.
type Assembly[M any] struct {
	raws   [][]byte // fragments in arrival order, owned
	metas  []M      // parallel to raws
	pieces []piece  // sorted by off; data slices into raws
	hdr    []byte   // IP header of the offset-0 fragment (IPv4 with options: ihl bytes; IPv6: 40)
	first  int      // index of the offset-0 fragment in raws
	v6     bool
	fam    bool // v6 is set (the first fragment added)
	want   int  // UDP length from the offset-0 fragment, else -1
	total  int  // data length once the last fragment is seen, else -1
	have   int
	bytes  int
}

type piece struct {
	off, end int
	data     []byte
}

func NewAssembly[M any]() *Assembly[M] { return &Assembly[M]{want: -1, total: -1} }

// maxData is the largest data length the reassembled packet can carry in
// its length field: the IPv4 total length includes the header (of the
// offset-0 fragment, 20 bytes until it is seen), the IPv6 payload length
// does not include the fixed header.
func (a *Assembly[M]) maxData(ihl int) int {
	if a.v6 {
		return 65535
	}
	if ihl == 0 {
		ihl = 20
		if a.hdr != nil {
			ihl = len(a.hdr)
		}
	}
	return 65535 - ihl
}

// Add adds one fragment; raw is kept (the caller passes a copy it no longer
// uses). A nil error with an unchanged Pieces count means an exact
// duplicate, which is ignored.
func (a *Assembly[M]) Add(raw []byte, f *Fragment, m M) error {
	// ParseFragment guarantees this; re-checked so that a violation never
	// reaches the slice expression below.
	if f.HdrLen < 20 || f.HdrLen > f.Data || f.Data > f.Len || f.Len > len(raw) || f.Offset < 0 {
		return ErrFragInvalid
	}
	v6 := raw[0]>>4 == 6
	if a.fam && a.v6 != v6 {
		return ErrFragInvalid
	}
	a.fam, a.v6 = true, v6
	data := raw[f.Data:f.Len]
	off := f.Offset
	end := off + len(data)
	if len(data) == 0 || (f.More && len(data)%8 != 0) {
		return ErrFragInvalid
	}
	ihl := 0
	if off == 0 {
		ihl = f.HdrLen
	}
	lim := a.maxData(ihl)
	if end > lim {
		return ErrFragInvalid
	}
	want := a.want
	if off == 0 {
		if f.UDPLen < 8 || len(data) < 8 || f.UDPLen > lim {
			return ErrFragInvalid
		}
		want = f.UDPLen
	}
	if f.More {
		if a.total >= 0 && end > a.total {
			return ErrFragInvalid
		}
	} else {
		if a.total >= 0 && a.total != end {
			return ErrFragInvalid
		}
		if n := len(a.pieces); n > 0 && a.pieces[n-1].end > end {
			return ErrFragInvalid
		}
	}
	if want >= 0 {
		if end > want || (!f.More && end != want) || (a.total >= 0 && a.total != want) {
			return ErrFragInvalid
		}
		if n := len(a.pieces); off == 0 && n > 0 && a.pieces[n-1].end > want {
			return ErrFragInvalid
		}
	}
	i := sort.Search(len(a.pieces), func(i int) bool { return a.pieces[i].off >= off })
	if i < len(a.pieces) && a.pieces[i].off == off && a.pieces[i].end == end && bytes.Equal(a.pieces[i].data, data) {
		return nil // exact duplicate
	}
	if (i > 0 && a.pieces[i-1].end > off) || (i < len(a.pieces) && a.pieces[i].off < end) {
		return ErrFragOverlap
	}
	if len(a.pieces) == maxPieces {
		return ErrFragInvalid
	}
	if off == 0 {
		a.hdr, a.want, a.first = raw[:f.HdrLen], want, len(a.raws)
	}
	if !f.More {
		a.total = end
	}
	a.pieces = append(a.pieces, piece{})
	copy(a.pieces[i+1:], a.pieces[i:])
	a.pieces[i] = piece{off, end, data}
	a.have += len(data)
	a.bytes += len(raw)
	a.raws = append(a.raws, raw)
	a.metas = append(a.metas, m)
	return nil
}

// HasFirst reports whether the offset-0 fragment was added.
func (a *Assembly[M]) HasFirst() bool { return a.hdr != nil }

// Complete reports whether every byte of the datagram is there.
func (a *Assembly[M]) Complete() bool { return a.hdr != nil && a.total >= 0 && a.have == a.total }

// Pieces is the number of fragments held.
func (a *Assembly[M]) Pieces() int { return len(a.raws) }

// Bytes is the size of the fragments held.
func (a *Assembly[M]) Bytes() int { return a.bytes }

// First is the arrival index of the offset-0 fragment (-1 before it came):
// the index into what Build returns.
func (a *Assembly[M]) First() int {
	if a.hdr == nil {
		return -1
	}
	return a.first
}

// Build returns the whole packet and the original fragments with their
// values, in arrival order. It requires Complete and may run on an
// Assembly no one else holds any more (the engine calls it unlocked).
// IPv4: the header of the offset-0 fragment, options kept (as RFC 791
// reassembly does), total length set, flags and offset cleared, checksum
// recomputed. IPv6: the fixed header with next header UDP and the payload
// length. The UDP header is left as the sender wrote it.
func (a *Assembly[M]) Build() (whole []byte, raws [][]byte, metas []M, err error) {
	if !a.Complete() {
		return nil, nil, nil, ErrFragInvalid
	}
	hl := len(a.hdr)
	whole = make([]byte, hl+a.total)
	copy(whole, a.hdr)
	for _, p := range a.pieces {
		copy(whole[hl+p.off:], p.data)
	}
	if a.v6 {
		whole[6] = ProtoUDP
		binary.BigEndian.PutUint16(whole[4:], uint16(a.total))
	} else {
		binary.BigEndian.PutUint16(whole[2:], uint16(len(whole)))
		whole[6], whole[7] = 0, 0
		whole[10], whole[11] = 0, 0
		binary.BigEndian.PutUint16(whole[10:], ^fold(sum(whole[:hl], 0)))
	}
	if p, err := Parse(whole); err != nil || p.Proto != ProtoUDP {
		return nil, nil, nil, ErrFragInvalid
	}
	return whole, append([][]byte(nil), a.raws...), append([]M(nil), a.metas...), nil
}
