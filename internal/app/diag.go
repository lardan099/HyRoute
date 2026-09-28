package app

import (
	"fmt"
	"strings"
	"time"
)

// Diagnostics is a plain-text report for support. Secrets (auth, obfs,
// SOCKS credentials, subscription tokens) are always redacted and
// subscription URLs are masked; privacy additionally masks IPs and server
// hosts. system are platform lines (driver, firewall rule, files).
func (c *Controller) Diagnostics(system []string, privacy bool) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("HyRoute — диагностика, %s", time.Now().Format("2006-01-02 15:04:05 -07:00"))
	w("HyRoute: %s", c.Version)
	if c.CoreVersion != nil {
		w("Hysteria: %s", c.CoreVersion())
	}
	for _, l := range system {
		w("%s", l)
	}

	st := c.Status()
	w("")
	w("== Маршрутизация: %s", st.State)
	if st.Message != "" {
		w("   %s", st.Message)
	}
	if st.KillSwitch != "" || st.KillSwitchError != "" {
		w("   kill switch: %s%s", orDash(st.KillSwitch), msgSuffix(st.KillSwitchError))
	}
	for _, l := range c.rulesetDiagLines() { // rulesets
		w("%s", l)
	}
	if st.Stats != nil {
		s := st.Stats
		w("   WinDivert: драйвер %s; relay: порт %d", orDash(s.Driver), s.RelayPort)
		w("   соединений: туннель %d, напрямую %d, блок %d, отклонено %d, владелец неизвестен %d; UDP: туннель %d, потеряно %d",
			s.RelayTunnel, s.Passed+s.RelayDirect, s.Blocked, s.Rejected, s.Unknown, s.UDPTunneled, s.UDPDropped)
		if s.FragDropped+s.Malformed+s.Panics > 0 {
			w("   отброшено: IP-фрагментов %d, нераспознанных пакетов %d, пакетов с ошибкой обработки %d", s.FragDropped, s.Malformed, s.Panics)
		}
		if l := fragDiagLine(s); l != "" { // bigudp
			w("%s", l)
		}
	}
	for _, l := range c.dnsDiagLines(st.Stats) { // dns
		w("%s", l)
	}
	for _, t := range st.Tunnels {
		w("   профиль %q: %s, SOCKS %s, рестартов %d, отклонено %d, ↑%d ↓%d байт, сервер %s%s",
			t.Name, t.State, orDash(t.SOCKS), t.Restarts, t.Rejected, t.Sent, t.Recv, strings.Join(t.ServerIPs, ","), msgSuffix(t.Message))
	}
	for _, x := range st.Warnings {
		w("   ! правило %q: %s", x.Rule, x.Text)
	}
	for _, p := range c.Proxies() {
		w("   прокси %q: порт %d, сервер %s, %s%s, из сети %v, пароль %v, соединений %d", p.Name, p.Port, orDash(p.ProfileName), p.State,
			msgSuffix(p.Error), p.LAN, p.Username != "", p.Total)
	}

	w("")
	w("== Профили")
	for _, p := range c.Profiles() {
		flags := []string{}
		if p.Main {
			flags = append(flags, "основной")
		}
		if p.Missing {
			flags = append(flags, "нет в подписке")
		}
		if p.Source != "" {
			flags = append(flags, "подписка "+p.SourceName)
		}
		if p.Pinned {
			flags = append(flags, "pinSHA256")
		} else if p.Insecure {
			flags = append(flags, "insecure")
		}
		if p.Obfs != "" {
			flags = append(flags, "obfs "+p.Obfs)
		}
		used := "не используется"
		if len(p.UsedBy) > 0 {
			used = "правила: " + strings.Join(p.UsedBy, ", ")
		}
		w("   %q %s sni=%s [%s] %s", p.Name, p.Server, orDash(p.SNI), strings.Join(flags, ", "), used)
	}
	for _, l := range c.groupDiagLines() {
		w("%s", l)
	}

	subs := c.Subscriptions()
	if len(subs) > 0 {
		w("")
		w("== Подписки")
		for _, s := range subs {
			w("   %q %s вкл=%v интервал=%s обновлена=%s профилей=%d пропущено=%d%s%s",
				s.Name, s.URLMasked, s.Enabled, s.Interval, fmtTime(s.LastUpdate), s.Count, ignoredSum(s.Ignored), msgSuffix(s.LastError),
				subDiagSuffix(s)) // subinfo
		}
	}

	w("")
	w("== Последние предупреждения и ошибки")
	n := 0
	for _, j := range []struct {
		name string
		kind string
	}{{"движок", "engine"}, {"hysteria", "hysteria"}} {
		es := c.journal(j.kind).Since(0, 0)
		var picked []string
		for i := len(es) - 1; i >= 0 && len(picked) < 15; i-- {
			if l := es[i].Level; l == "warn" || l == "error" || l == "fatal" {
				picked = append(picked, fmt.Sprintf("   [%s] %s %s %s", j.name, es[i].Time.Format("01-02 15:04:05"), strings.ToUpper(l), es[i].Msg))
			}
		}
		for i := len(picked) - 1; i >= 0; i-- {
			w("%s", picked[i])
			n++
		}
	}
	if n == 0 {
		w("   нет")
	}

	out := c.Redactor.Redact(b.String())
	if privacy {
		out = c.Sanitize(out)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func msgSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " — " + s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	return t.Format("2006-01-02 15:04")
}

func ignoredSum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
