package app

import (
	"fmt"

	"github.com/lardan099/hyroute/internal/session"
)

// fragDiagLine is the «Маршрутизация» line of the diagnostics report about
// IP fragments and datagrams too big for Hysteria (bigudp); "" while every
// counter is zero. Counts only: nothing to mask.
func fragDiagLine(s *session.Stats) string {
	if s.FragReassembled+s.FragIncomplete+s.FragOrphan+s.UDPTooBig+s.FragLegacy == 0 {
		return ""
	}
	return fmt.Sprintf("   UDP-фрагменты: собрано датаграмм %d, не собрано (неполные или ошибочные) %d, фрагментов без первого %d; "+
		"датаграмм больше предела Hysteria %d; отброшено по первому фрагменту (TCP, заголовки расширения IPv6) %d",
		s.FragReassembled, s.FragIncomplete, s.FragOrphan, s.UDPTooBig, s.FragLegacy)
}
