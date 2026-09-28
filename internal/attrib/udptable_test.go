package attrib

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func udpBuf(v6 bool, rows ...UDPRow) []byte {
	size := udpRowSize
	if v6 {
		size = udp6RowSize
	}
	b := make([]byte, 4+len(rows)*size)
	binary.LittleEndian.PutUint32(b, uint32(len(rows)))
	for i, r := range rows {
		o := b[4+i*size:]
		if v6 {
			a := r.Local.Addr().As16()
			copy(o, a[:])
			binary.BigEndian.PutUint16(o[20:], r.Local.Port())
			binary.LittleEndian.PutUint32(o[24:], r.PID)
			continue
		}
		a := r.Local.Addr().As4()
		copy(o, a[:])
		binary.BigEndian.PutUint16(o[4:], r.Local.Port())
		binary.LittleEndian.PutUint32(o[8:], r.PID)
	}
	return b
}

func TestParseUDPRows(t *testing.T) {
	ap := netip.MustParseAddrPort
	v4 := []UDPRow{{ap("127.0.0.1:5000"), 100}, {ap("0.0.0.0:53"), 4}}
	if got := parseUDPRows(udpBuf(false, v4...), false); len(got) != 2 || got[0] != v4[0] || got[1] != v4[1] {
		t.Fatal(got)
	}
	v6 := []UDPRow{{ap("[::ffff:127.0.0.1]:5000"), 100}, {ap("[::]:5000"), 200}}
	got := parseUDPRows(udpBuf(true, v6...), true)
	if len(got) != 2 || got[0].Local != ap("127.0.0.1:5000") || got[1].Local != ap("[::]:5000") || got[1].PID != 200 {
		t.Fatal(got)
	}
	// A count larger than the buffer is cut, not a panic.
	b := udpBuf(false, v4...)
	binary.LittleEndian.PutUint32(b, 1000)
	if got := parseUDPRows(b, false); len(got) != 2 {
		t.Fatal(got)
	}
	if parseUDPRows([]byte{1, 0}, true) != nil {
		t.Fatal("short buffer")
	}
}

func TestUDPOwnerStrict(t *testing.T) {
	ap := netip.MustParseAddrPort
	src := ap("127.0.0.1:5000")
	for _, c := range []struct {
		name string
		rows []UDPRow
		pid  uint32
	}{
		{"exact", []UDPRow{{ap("127.0.0.1:5000"), 100}}, 100},
		{"wildcard", []UDPRow{{ap("0.0.0.0:5000"), 100}}, 100},
		{"both, one owner", []UDPRow{{ap("127.0.0.1:5000"), 100}, {ap("0.0.0.0:5000"), 100}}, 100},
		{"dual-stack", []UDPRow{{ap("[::]:5000"), 100}}, 100},
		{"mapped exact", []UDPRow{{ap("[::ffff:127.0.0.1]:5000"), 100}}, 100},
		{"exact and wildcard of two", []UDPRow{{ap("127.0.0.1:5000"), 100}, {ap("0.0.0.0:5000"), 200}}, 0},
		{"v6 wildcard of another", []UDPRow{{ap("127.0.0.1:5000"), 100}, {ap("[::]:5000"), 200}}, 0},
		{"other port and address ignored", []UDPRow{{ap("127.0.0.1:5001"), 7}, {ap("127.0.0.2:5000"), 8}, {ap("127.0.0.1:5000"), 100}}, 100},
		{"none", []UDPRow{{ap("127.0.0.1:5001"), 7}}, 0},
	} {
		pid, err := udpOwnerStrict(c.rows, src)
		if c.pid == 0 {
			if !errors.Is(err, ErrNoOwner) {
				t.Errorf("%s: %d %v", c.name, pid, err)
			}
			continue
		}
		if err != nil || pid != c.pid {
			t.Errorf("%s: %d %v", c.name, pid, err)
		}
	}
	// 0.0.0.0 does not own an IPv6 source.
	if _, err := udpOwnerStrict([]UDPRow{{ap("0.0.0.0:5000"), 1}}, ap("[::1]:5000")); !errors.Is(err, ErrNoOwner) {
		t.Error(err)
	}
}
