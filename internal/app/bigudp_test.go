package app

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/session"
)

// The diagnostics line about fragments and datagrams too big for Hysteria
// appears only when something was counted.
func TestFragDiagLine(t *testing.T) {
	if l := fragDiagLine(&session.Stats{FragDropped: 5, UDPDropped: 2}); l != "" {
		t.Fatalf("zero counters printed: %q", l)
	}
	l := fragDiagLine(&session.Stats{FragReassembled: 3, FragIncomplete: 1, FragOrphan: 2, UDPTooBig: 4, FragLegacy: 6})
	want := "   UDP-фрагменты: собрано датаграмм 3, не собрано (неполные или ошибочные) 1, фрагментов без первого 2; " +
		"датаграмм больше предела Hysteria 4; отброшено по первому фрагменту (TCP, заголовки расширения IPv6) 6"
	if l != want {
		t.Fatalf("%q", l)
	}
	if !strings.HasPrefix(fragDiagLine(&session.Stats{UDPTooBig: 1}), "   UDP-фрагменты:") {
		t.Fatal("a single counter is not enough")
	}
}
