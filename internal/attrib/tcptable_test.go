package attrib

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// tcpTableBuf builds a MIB_TCPTABLE_OWNER_PID (v6: MIB_TCP6TABLE_OWNER_PID)
// as GetExtendedTcpTable fills it.
func tcpTableBuf(v6 bool, rows ...TCPRow) []byte {
	size := tcpRowSize
	if v6 {
		size = tcp6RowSize
	}
	b := make([]byte, 4+len(rows)*size)
	binary.LittleEndian.PutUint32(b, uint32(len(rows)))
	for i, r := range rows {
		o := b[4+i*size:]
		if !v6 {
			binary.LittleEndian.PutUint32(o[0:], r.State)
			a := r.Local.Addr().As4()
			copy(o[4:], a[:])
			binary.BigEndian.PutUint16(o[8:], r.Local.Port())
			a = r.Remote.Addr().As4()
			copy(o[12:], a[:])
			binary.BigEndian.PutUint16(o[16:], r.Remote.Port())
			binary.LittleEndian.PutUint32(o[20:], r.PID)
			continue
		}
		a := r.Local.Addr().As16()
		copy(o[0:], a[:])
		binary.LittleEndian.PutUint32(o[16:], 7) // scope
		binary.BigEndian.PutUint16(o[20:], r.Local.Port())
		a = r.Remote.Addr().As16()
		copy(o[24:], a[:])
		binary.BigEndian.PutUint16(o[44:], r.Remote.Port())
		binary.LittleEndian.PutUint32(o[48:], r.State)
		binary.LittleEndian.PutUint32(o[52:], r.PID)
	}
	return b
}

func TestParseTCPRows(t *testing.T) {
	v4 := []TCPRow{
		{Local: ap("0.0.0.0:445"), Remote: ap("0.0.0.0:0"), State: TCPStateListen, PID: 4},
		{Local: ap("192.168.1.5:40000"), Remote: ap("93.184.216.34:443"), State: 5, PID: 100},
	}
	got := parseTCPRows(tcpTableBuf(false, v4...), false)
	if len(got) != 2 || got[0] != v4[0] || got[1] != v4[1] {
		t.Fatalf("v4: %+v", got)
	}
	v6 := []TCPRow{
		{Local: ap("[2a00::5]:40000"), Remote: ap("[2606:4700::1111]:443"), State: 5, PID: 200},
		{Local: ap("[::ffff:192.168.1.5]:40001"), Remote: ap("[::ffff:93.184.216.34]:80"), State: 5, PID: 300},
	}
	got = parseTCPRows(tcpTableBuf(true, v6...), true)
	// 4in6 addresses come out as IPv4, like every other key of the package.
	if len(got) != 2 || got[0] != v6[0] || got[1].Local != ap("192.168.1.5:40001") || got[1].Remote != ap("93.184.216.34:80") || got[1].PID != 300 {
		t.Fatalf("v6: %+v", got)
	}
	// A count larger than the buffer (the table grew between the calls)
	// reads only the complete rows.
	b := tcpTableBuf(false, v4...)
	binary.LittleEndian.PutUint32(b, 5)
	if got := parseTCPRows(b[:len(b)-1], false); len(got) != 1 {
		t.Fatalf("truncated: %d rows", len(got))
	}
	if got := parseTCPRows(nil, false); len(got) != 0 {
		t.Fatal("empty buffer")
	}
}

func TestTCPSnapshot(t *testing.T) {
	s := NewTCPSnapshot([]TCPRow{
		{Local: ap("0.0.0.0:8080"), State: TCPStateListen, PID: 100},
		{Local: ap("127.0.0.1:40000"), State: TCPStateListen, PID: 200},
		{Local: ap("[::]:3389"), State: TCPStateListen, PID: 300},
		{Local: ap("192.168.1.5:40001"), Remote: ap("93.184.216.34:443"), State: 5, PID: 400},
		{Local: ap("0.0.0.0:40002"), Remote: ap("93.184.216.34:443"), State: 2 + 1, PID: 500}, // SYN_SENT, not bound yet
		{Local: ap("192.168.1.5:40003"), Remote: ap("93.184.216.34:443"), State: 11, PID: 0},  // TIME_WAIT
	})
	for _, c := range []struct {
		local, remote string
		pid           uint32
		ok            bool
	}{
		{"192.168.1.5:40001", "93.184.216.34:443", 400, true},
		{"[::ffff:192.168.1.5]:40001", "93.184.216.34:443", 400, true},
		{"192.168.1.5:40001", "93.184.216.34:80", 0, false},
		{"192.168.1.5:40002", "93.184.216.34:443", 500, true},
		{"192.168.1.5:40003", "93.184.216.34:443", 0, true},
		{"192.168.1.5:8080", "0.0.0.0:0", 0, false}, // listeners own no connection
	} {
		if pid, ok := s.Owner(ap(c.local), ap(c.remote)); pid != c.pid || ok != c.ok {
			t.Errorf("Owner(%s, %s) = %d, %v", c.local, c.remote, pid, ok)
		}
	}
	for _, c := range []struct {
		local string
		pid   uint32
		want  bool
	}{
		{"192.168.1.5:8080", 100, true},   // wildcard listener
		{"[2a00::5]:8080", 100, true},     // a wildcard of the other family counts
		{"192.168.1.5:3389", 300, true},   // dual-stack [::]
		{"127.0.0.1:40000", 200, true},    // its own address
		{"192.168.1.5:40000", 200, false}, // listener on another address
		{"192.168.1.5:40001", 400, false},
		// Another program's client connection that got the port of a
		// [::] listener (IPV6_V6ONLY leaves IPv4 free), or of 0.0.0.0.
		{"192.168.1.5:3389", 400, false},
		{"192.168.1.5:8080", 400, false},
	} {
		if got := s.Listening(ap(c.local), c.pid); got != c.want {
			t.Errorf("Listening(%s, %d) = %v", c.local, c.pid, got)
		}
	}
}
