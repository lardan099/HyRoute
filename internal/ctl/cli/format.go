package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/ctl"
)

// Human output. Wording and number formats follow the window (api.ts);
// Russian texts made by HyRoute are printed as they come.

// Lite views of feature-owned shapes that reach hyroutectl as raw JSON:
// only the fields printed, tolerant of additions. A ctlserver test pins
// them to the real app types (TestLiteContract).

// GroupBriefLite is app.GroupBrief (Status.MainGroup).
type GroupBriefLite struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Strategy   string `json:"strategy"`
	ActiveName string `json:"activeName"`
	Up         int    `json:"up"`
	Total      int    `json:"total"`
}

// SubAlertLite is app.SubAlert (Status.SubAlerts).
type SubAlertLite struct {
	Name  string `json:"name"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// StepLite is rules.Step.
type StepLite struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Matched bool   `json:"matched"`
	Winner  bool   `json:"winner"`
	Reason  string `json:"reason"`
	Action  string `json:"action"`
	Profile string `json:"profile"`
}

// ExplanationLite is app.Explanation (as ctlserver sends it: the DNS
// line's server named).
type ExplanationLite struct {
	Steps       []StepLite      `json:"steps"`
	Winner      StepLite        `json:"winner"`
	Notes       []string        `json:"notes"`
	ProfileName string          `json:"profileName"`
	Group       bool            `json:"group"`
	Via         string          `json:"via"`
	Port        int             `json:"port"`
	DNS         *DNSExplainLite `json:"dns"`
}

// DNSExplainLite is dns' DNSExplain with ProfileName added by ctlserver.
type DNSExplainLite struct {
	Route       string          `json:"route"`
	ProfileName string          `json:"profileName"`
	Upstream    string          `json:"upstream"`
	Rule        string          `json:"rule"`
	Cond        string          `json:"cond"`
	Proto       string          `json:"proto"`
	NoIPv6      bool            `json:"noIPv6"`
	System      *DNSExplainLite `json:"system"`
}

// DNSStatusLite is dns' DNSStatus (Status.DNS).
type DNSStatusLite struct {
	Health     []DNSHealthLite `json:"health"`
	PauseLeft  int             `json:"pauseLeft"`
	NotApplied bool            `json:"notApplied"`
}

// DNSHealthLite is dns' DNSHealth: an upstream server that does not answer.
type DNSHealthLite struct {
	Via      string `json:"via"`
	Profile  string `json:"profile"`
	Upstream string `json:"upstream"`
}

// NetStateLite is netmodes' NetState (Status.Net, NetModesView.State).
type NetStateLite struct {
	Rule     string `json:"rule"`
	Unknown  bool   `json:"unknown"`
	NoNet    bool   `json:"noNet"`
	Pending  bool   `json:"pending"`
	Text     string `json:"text"`
	Error    string `json:"error"`
	Override bool   `json:"override"`
	Restored bool   `json:"restored"`
	Off      bool   `json:"off"`
	OffBy    string `json:"offBy"`
}

// NetActionLite is netmode.Action.
type NetActionLite struct {
	Connect string `json:"connect"`
	Ruleset string `json:"ruleset"`
}

// NetRuleLite is netmode.Rule.
type NetRuleLite struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled"`
	NetActionLite
}

// NetworkLite is netmode.Network.
type NetworkLite struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Adapter  string `json:"adapter"`
	SSID     string `json:"ssid"`
}

// NetMatchLite is netmodes' NetMatchView.
type NetMatchLite struct {
	Name    string `json:"name"`
	Unknown bool   `json:"unknown"`
	NetActionLite
}

// NetRulesetLite is app.NetRuleset.
type NetRulesetLite struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NetConfigLite is netmode.Config.
type NetConfigLite struct {
	Enabled bool          `json:"enabled"`
	Rules   []NetRuleLite `json:"rules"`
	Unknown NetActionLite `json:"unknown"`
}

// NetSnapshotLite is netmode.Snapshot.
type NetSnapshotLite struct {
	Active *NetworkLite `json:"active"`
	Error  string       `json:"error"`
}

// NetModesLite is netmodes' NetModesView (the networks commands).
type NetModesLite struct {
	Config      NetConfigLite    `json:"config"`
	Current     NetSnapshotLite  `json:"current"`
	Match       *NetMatchLite    `json:"match"`
	State       NetStateLite     `json:"state"`
	Unavailable string           `json:"unavailable"`
	LoadError   string           `json:"loadError"`
	Rulesets    []NetRulesetLite `json:"rulesets"`
}

// StatCountersLite is stats.Counters.
type StatCountersLite struct {
	TC int64 `json:"tc"` // through the VPN: connections, bytes up and down
	TU int64 `json:"tu"`
	TD int64 `json:"td"`
	DC int64 `json:"dc"` // direct: attempts, bytes up (approximate)
	DU int64 `json:"du"`
	BC int64 `json:"bc"` // blocked
	F  int64 `json:"f"`  // refused
	FO int64 `json:"fo"` // went to a fallback server
}

// StatRowLite is stats.Row.
type StatRowLite struct {
	Key  string `json:"k"`
	Name string `json:"n"`
	StatCountersLite
	Gone bool `json:"gone"`
}

// StatEventsLite is stats.Events.
type StatEventsLite struct {
	Drops       int64 `json:"drops"`
	EngineFails int64 `json:"engineFails"`
}

// ReportLite is stats.Report.
type ReportLite struct {
	Period     string           `json:"period"`
	From       string           `json:"from"`
	To         string           `json:"to"`
	Total      StatCountersLite `json:"total"`
	Events     StatEventsLite   `json:"events"`
	Apps       []StatRowLite    `json:"apps"`
	Servers    []StatRowLite    `json:"servers"`
	Groups     []StatRowLite    `json:"groups"`
	Since      string           `json:"since"`
	Mode       string           `json:"mode"`
	StoreError string           `json:"storeError"`
	ModeUnread bool             `json:"modeUnread"`
}

// fmtBytes is api.ts fmtBytes.
func fmtBytes(n int64) string {
	if n < 0 {
		return "—"
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	u := []string{"KB", "MB", "GB", "TB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, u[i])
	}
	return fmt.Sprintf("%d %s", int64(math.Round(v)), u[i])
}

// fmtDuration is api.ts fmtDuration (rounded before picking the unit).
func fmtDuration(d time.Duration) string {
	ms := int64(math.Round(float64(d) / 1e6))
	if ms < 1000 {
		return fmt.Sprintf("%d мс", ms)
	}
	ds := int64(math.Round(float64(d) / 1e8))
	if ds < 600 {
		return fmt.Sprintf("%.1f с", float64(ds)/10)
	}
	s := int64(math.Round(float64(d) / 1e9))
	m := s / 60
	if m < 60 {
		return fmt.Sprintf("%d мин %d с", m, s%60)
	}
	return fmt.Sprintf("%d ч %d мин", m/60, m%60)
}

// plural is api.ts plural.
func plural(n int, one, few, many string) string {
	m10, m100 := n%10, n%100
	switch {
	case m10 == 1 && m100 != 11:
		return one
	case m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20):
		return few
	}
	return many
}

func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

var stateWords = map[string]string{
	"disconnected": "отключено", "starting": "запуск…", "connecting": "подключение…", "connected": "подключено",
	"tunnel-down": "сервер недоступен", "error": "ошибка",
}

func tunnelWord(t ctl.TunnelView) string {
	switch t.State {
	case "connected":
		return "подключён"
	case "connecting":
		if t.Restarts > 0 {
			return "переподключение"
		}
		return "подключение"
	case "failed":
		return "ошибка"
	case "stopped":
		return "остановлен"
	}
	return t.State
}

// formatStatus is the status block.
func formatStatus(b *strings.Builder, st ctl.StatusView, now time.Time) {
	if st.LoadError != "" {
		fmt.Fprintf(b, "Настройки не загружены: %s\n", st.LoadError)
	}
	word := stateWords[st.State]
	if word == "" {
		word = st.State
	}
	line := "HyRoute " + st.App + " — " + word
	if since, err := time.Parse(time.RFC3339, st.Since); err == nil && st.Since != "" {
		line += " (" + fmtDuration(now.Sub(since)) + ")"
	}
	b.WriteString(line + "\n")
	var g GroupBriefLite
	switch {
	case len(st.MainGroup) > 0 && json.Unmarshal(st.MainGroup, &g) == nil && g.Name != "":
		l := "Основной: группа «" + g.Name + "»"
		if g.ActiveName != "" {
			l += " (сейчас " + g.ActiveName + ")"
		}
		b.WriteString(l + "\n")
	case st.Main != nil:
		b.WriteString("Основной: " + st.Main.Name + "\n")
	default:
		b.WriteString("Основной: не выбран\n")
	}
	if st.Ruleset != nil && st.Ruleset.Count >= 2 {
		b.WriteString("Профиль правил: " + st.Ruleset.Name + "\n")
	}
	var net NetStateLite
	hasNet := len(st.Net) > 0 && json.Unmarshal(st.Net, &net) == nil
	if hasNet {
		b.WriteString("Сеть: " + netLine(net) + "\n")
		if net.Off && st.State == "disconnected" {
			b.WriteString(netOffLine(net) + "\n")
		}
	}
	if st.Message != "" {
		if st.State == "error" || st.State == "tunnel-down" {
			b.WriteString("Причина: " + st.Message + "\n")
		} else {
			b.WriteString(st.Message + "\n")
		}
	}
	if st.GroupsNote != "" {
		b.WriteString(st.GroupsNote + "\n")
	}
	if len(st.Tunnels) > 0 {
		b.WriteString("Серверы:\n")
		nw, sw := 0, 0
		for _, t := range st.Tunnels {
			nw = max(nw, utf8.RuneCountInString(t.Name))
			sw = max(sw, utf8.RuneCountInString(tunnelWord(t)))
		}
		for _, t := range st.Tunnels {
			l := "  " + pad(t.Name, nw) + "   " + pad(tunnelWord(t), sw)
			var extra []string
			if t.Sent > 0 || t.Recv > 0 {
				extra = append(extra, "↑ "+fmtBytes(t.Sent)+"  ↓ "+fmtBytes(t.Recv))
			}
			if t.Rejected > 0 {
				extra = append(extra, fmt.Sprintf("отклонено %d", t.Rejected))
			}
			if len(extra) > 0 {
				l += "   " + strings.Join(extra, "   ")
			}
			if t.Message != "" {
				l += ": " + t.Message
			}
			b.WriteString(strings.TrimRight(l, " ") + "\n")
		}
	}
	switch {
	case st.KillSwitchError != "":
		b.WriteString("Kill switch: ошибка: " + st.KillSwitchError + "\n")
	case st.KillSwitch == "armed":
		b.WriteString("Kill switch: включён\n")
	case st.KillSwitch == "blocking":
		b.WriteString("Kill switch: интернет закрыт (kill switch). Подключитесь или выполните hyroutectl disconnect\n")
	default:
		b.WriteString("Kill switch: выключен\n")
	}
	var alerts []SubAlertLite
	if len(st.SubAlerts) > 0 && json.Unmarshal(st.SubAlerts, &alerts) == nil {
		for _, a := range alerts {
			b.WriteString("Подписка «" + a.Name + "»: " + a.Text + "\n")
		}
	}
	for _, w := range st.Warnings {
		b.WriteString("Внимание: " + w + "\n")
	}
	if hasNet && net.Error != "" {
		b.WriteString("Внимание: правило сети «" + net.Rule + "» не выполнено: " + net.Error + "\n")
	}
	var dns DNSStatusLite
	if len(st.DNS) > 0 && json.Unmarshal(st.DNS, &dns) == nil {
		formatDNSStatus(b, st, dns)
	}
}

// online: a session exists (Home's check).
func online(st ctl.StatusView) bool {
	return st.State != "disconnected" && !(st.State == "error" && len(st.Stats) == 0)
}

// formatDNSStatus is Home's DNS notes: the running session did not take
// the settings, a tunnel's DNS server does not answer (the tunnel itself
// works), the encrypted direct DNS does not work, the portal pause.
func formatDNSStatus(b *strings.Builder, st ctl.StatusView, d DNSStatusLite) {
	if !online(st) {
		return
	}
	if d.NotApplied {
		b.WriteString("Внимание: настройки DNS не применены к подключению: имена сайтов спрашиваются у DNS-сервера сети, как без них. Переподключитесь.\n")
	}
	name := map[string]string{}
	up := map[string]bool{}
	for _, t := range st.Tunnels {
		name[t.ID] = t.Name
		up[t.ID] = up[t.ID] || t.State == "connected"
	}
	direct := false
	for _, h := range d.Health {
		switch {
		case h.Via == "direct":
			direct = true
		case h.Via == "tunnel" && up[h.Profile]:
			b.WriteString("Внимание: DNS-сервер для VPN (" + h.Upstream + ") не отвечает через " + name[h.Profile] + ": сайты через VPN не открываются.\n")
		}
	}
	if direct {
		b.WriteString("DNS: шифрование прямых DNS-запросов не работает: DNS-сервер не отвечает\n")
	}
	if d.PauseLeft > 0 {
		fmt.Fprintf(b, "DNS: имена через VPN сейчас разрешаются напрямую, пока VPN недоступен — ещё %d мин.\n", (d.PauseLeft+59)/60)
	}
}

// netLine is Home's «Сеть: …»: the rule of the current network.
func netLine(n NetStateLite) string {
	var s string
	switch {
	case n.Pending:
		s = "определяется"
	case n.NoNet:
		s = "нет подключения"
	case n.Unknown:
		s = "неизвестная"
	case n.Rule != "":
		s = "правило «" + n.Rule + "»"
	default:
		s = "определяется"
	}
	switch {
	case n.Restored:
		s += " · как до обновления, до смены сети"
	case n.Override:
		s += " · вручную до смены сети"
	}
	return s
}

// netOffLine: routing is off because a network rule turned it off.
func netOffLine(n NetStateLite) string {
	by := n.OffBy
	if by == "" {
		by = n.Rule
	}
	if n.OffBy != "" && n.OffBy != n.Rule {
		return "Отключено правилом сети «" + by + "». Правило этой сети («" + n.Rule + "») подключение не меняет — весь трафик идёт напрямую. hyroutectl connect подключит до следующей смены сети."
	}
	return "Отключено правилом сети «" + by + "»: весь трафик идёт напрямую, kill switch не действует. hyroutectl connect подключит до следующей смены сети."
}

// connectLine is the first line after connect/reconnect and its exit code.
func connectLine(v ctl.ConnectView, reconnect bool, wait int) (string, int) {
	st := v.Status
	why := st.Message
	switch {
	case v.WaitedOut:
		if why == "" {
			why = "серверы ещё подключаются"
		}
		return fmt.Sprintf("Не дождались подключения за %d с: %s", wait, why), 5
	case st.State == "error" || st.State == "disconnected":
		if why == "" {
			why = "HyRoute отключился"
		}
		return "Не подключено: " + why, 1
	case v.Already && wait == 0 && (st.State == "starting" || st.State == "connecting"):
		return "Уже подключается…", 0
	case v.Already && wait == 0:
		return "Уже подключено.", 0
	case st.State == "connected":
		if reconnect {
			return "Переподключено.", 0
		}
		return "Подключено.", 0
	case st.State == "tunnel-down":
		return "Подключено, но сервер недоступен.", 0
	}
	return "Фильтры включены, серверы подключаются…", 0
}

func formatServers(b *strings.Builder, list []ctl.ServerView) {
	if len(list) == 0 {
		b.WriteString("Серверов нет. Добавьте сервер в HyRoute (страница «Серверы»).\n")
		return
	}
	names := make([]string, len(list))
	srcs := make([]string, len(list))
	withState := false
	iw, nw, aw, sw := 2, 6, 5, 8
	for i, s := range list {
		names[i] = s.Name
		if s.Missing {
			names[i] += " (нет в подписке)"
		}
		srcs[i] = "вручную"
		if s.Source != "" {
			srcs[i] = "Подписка «" + s.Source + "»"
		}
		withState = withState || s.State != ""
		iw = max(iw, utf8.RuneCountInString(s.ID))
		nw = max(nw, utf8.RuneCountInString(names[i]))
		aw = max(aw, utf8.RuneCountInString(s.Address))
		sw = max(sw, utf8.RuneCountInString(srcs[i]))
	}
	head := "  " + pad("ID", iw) + "  " + pad("Сервер", nw) + "  " + pad("Адрес", aw) + "  "
	if withState {
		head += pad("Источник", sw) + "  Состояние"
	} else {
		head += "Источник"
	}
	b.WriteString(head + "\n")
	for i, s := range list {
		mark := "  "
		if s.Main {
			mark = "* "
		}
		l := mark + pad(s.ID, iw) + "  " + pad(names[i], nw) + "  " + pad(s.Address, aw) + "  "
		if withState {
			st := s.State
			if w := tunnelWord(ctl.TunnelView{State: s.State}); st != "" {
				st = w
			}
			l += pad(srcs[i], sw) + "  " + st
		} else {
			l += srcs[i]
		}
		b.WriteString(strings.TrimRight(l, " ") + "\n")
	}
}

var strategyWords = map[string]string{"failover": "по порядку", "latency": "наименьшая задержка", "roundrobin": "по кругу",
	"random": "случайно", "sticky": "закреплённо"}

func formatGroups(b *strings.Builder, v ctl.GroupsView) {
	if len(v.Groups) == 0 {
		b.WriteString("Групп нет.\n")
		return
	}
	for _, g := range v.Groups {
		mark := "  "
		if g.Main {
			mark = "* "
		}
		sw := strategyWords[g.Strategy]
		if sw == "" {
			sw = g.Strategy
		}
		l := fmt.Sprintf("%s%s — %s, %d %s", mark, g.Name, sw, g.Total, plural(g.Total, "сервер", "сервера", "серверов"))
		if g.ActiveName != "" {
			l += ", сейчас " + g.ActiveName
		}
		if !g.Running {
			l += ", не используется"
		}
		b.WriteString(l + "\n")
		nw := 0
		for _, m := range g.Members {
			nw = max(nw, utf8.RuneCountInString(m.Name))
		}
		for _, m := range g.Members {
			var s string
			switch {
			case m.Missing:
				s = "нет в списке серверов"
			case m.Skipped && m.Errors > 0:
				s = fmt.Sprintf("пропускается: ошибок подряд %d", m.Errors)
			case m.Skipped:
				s = "пропускается"
			case m.ProbeError != "":
				s = "нет ответа: " + m.ProbeError
			case m.LatencyMs > 0:
				s = fmt.Sprintf("%d мс", m.LatencyMs)
			default:
				s = "—"
			}
			name := m.Name
			if name == "" {
				name = m.ID
			}
			b.WriteString("    " + pad(name, nw) + "   " + s + "\n")
		}
	}
}

func formatCheck(b *strings.Builder, v ctl.CheckView) {
	for _, s := range v.Steps {
		switch {
		case s.Skip:
			b.WriteString("– " + s.Name + " (пропущено)\n")
		case s.OK:
			l := "✓ " + s.Name
			if s.Detail != "" {
				l += " — " + s.Detail
			}
			if s.Ms > 0 {
				l += fmt.Sprintf(" (%d мс)", s.Ms)
			}
			b.WriteString(l + "\n")
		default:
			l := "✗ " + s.Name
			if s.Detail != "" {
				l += " — " + s.Detail
			}
			b.WriteString(l + "\n")
		}
	}
	if v.ExternalIP != "" {
		b.WriteString("Внешний IP: " + v.ExternalIP + "\n")
	}
	if v.LatencyMs > 0 {
		fmt.Fprintf(b, "Задержка: %d мс\n", v.LatencyMs)
	}
}

var defaultWords = map[string]string{"tunnel": "через VPN", "direct": "напрямую", "block": "блокировка"}

func formatRulesets(b *strings.Builder, v ctl.RulesetsView) {
	for _, e := range v.List {
		mark := "  "
		if e.Active {
			mark = "* "
		}
		l := fmt.Sprintf("%s%s — %d %s, «Всё остальное»: %s", mark, e.Name, e.Rules, plural(e.Rules, "правило", "правила", "правил"), defaultWords[e.DefaultAction])
		if e.Warnings > 0 {
			l += fmt.Sprintf(", требуют внимания: %d", e.Warnings)
		}
		if e.Error != "" {
			l += ", не загружается: " + e.Error
		}
		b.WriteString(l + "\n")
	}
}

// explainRoute words the winner's route.
func explainRoute(ex ExplanationLite) string {
	switch ex.Winner.Action {
	case "direct":
		return "напрямую"
	case "block":
		return "блокировка"
	}
	if ex.Group {
		l := "через группу «" + ex.ProfileName + "»"
		if ex.Via != "" {
			l += " (сейчас " + ex.Via + ")"
		}
		return l
	}
	if ex.ProfileName == "" {
		return "через VPN: основной сервер не выбран — соединение будет отклонено"
	}
	return "через VPN: " + ex.ProfileName
}

func stepTitle(s StepLite) string {
	if s.Index < 0 {
		return "«Всё остальное»"
	}
	t := fmt.Sprintf("%d", s.Index+1)
	if s.Name != "" {
		t += " «" + s.Name + "»"
	}
	return t
}

func formatExplain(b *strings.Builder, ex ExplanationLite, inv *Invocation) {
	head := inv.Target
	switch {
	case inv.Port > 0 && inv.UDP:
		head += fmt.Sprintf(", UDP %d", inv.Port)
	case inv.Port > 0:
		head += fmt.Sprintf(", TCP %d", inv.Port)
	case inv.UDP:
		head += ", UDP"
	}
	b.WriteString(head + " → " + explainRoute(ex) + "\n")
	if ex.Winner.Index < 0 {
		b.WriteString("Сработало: «Всё остальное»")
	} else {
		b.WriteString("Сработало: правило " + stepTitle(ex.Winner))
	}
	if ex.Winner.Reason != "" {
		b.WriteString(" — " + ex.Winner.Reason)
	}
	b.WriteString("\n")
	if d := ex.DNS; d != nil {
		if d.System != nil {
			b.WriteString(dnsText(*d, "DNS, если программа спрашивает DNS сама") + "\n")
			b.WriteString(dnsText(*d.System, "DNS через службу DNS Windows (так спрашивает большинство программ)") + "\n")
		} else {
			b.WriteString(dnsText(*d, "DNS") + "\n")
		}
		if d.NoIPv6 {
			b.WriteString("DNS: IPv6-адреса для него не выдаются («Не пускать IPv6 в VPN»).\n")
		}
	}
	if inv.Steps {
		b.WriteString("Шаги:\n")
		for _, s := range ex.Steps {
			mark := "  · "
			if s.Winner {
				mark = "  ✓ "
			}
			l := mark + stepTitle(s)
			if !s.Enabled && s.Index >= 0 {
				l += " (выключено)"
			}
			if s.Reason != "" {
				l += ": " + s.Reason
			}
			b.WriteString(l + "\n")
		}
	}
	if len(ex.Notes) > 0 {
		b.WriteString("Заметки:\n")
		for _, n := range ex.Notes {
			b.WriteString("  • " + n + "\n")
		}
	}
}

// lineLabel is how a problem's place is named: a line of text, a rule of
// JSON, nothing for the JSON file itself.
func lineLabel(l ctl.ErrorLine, isJSON bool) string {
	switch {
	case isJSON && l.Line == 0:
		return "  " + l.Text
	case isJSON:
		return fmt.Sprintf("  правило %d: %s", l.Line, l.Text)
	}
	return fmt.Sprintf("  строка %d: %s", l.Line, l.Text)
}

func formatImport(b *strings.Builder, v ctl.RulesImportView, dry bool) {
	if v.Summary != "" {
		b.WriteString(v.Summary + "\n")
	}
	if len(v.Warnings) > 0 {
		b.WriteString("Предупреждения:\n")
		for _, w := range v.Warnings {
			b.WriteString(lineLabel(w, v.JSON) + "\n")
		}
	}
	switch {
	case dry:
		b.WriteString("Ошибок нет. Ничего не сохранено (--dry-run).\n")
	case v.Replace:
		fmt.Fprintf(b, "Сохранено: правила заменены (%d).\n", v.Rules)
	case v.Rules > 0 && v.Skipped == v.Rules:
		// Nothing new: editRulesIn saved nothing.
		fmt.Fprintf(b, "Ничего не добавлено: все правила уже есть в списке (%d).\n", v.Skipped)
	default:
		fmt.Fprintf(b, "Сохранено: правил добавлено %d.\n", v.Rules-v.Skipped-v.Enabled)
		if v.Skipped > 0 || v.Enabled > 0 {
			fmt.Fprintf(b, "Уже были в списке и не добавлены: %d%s.\n", v.Skipped, enabledNote(v.Enabled))
		}
	}
}

// enabledNote: the rules whose copy was off and was switched on.
func enabledNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; были выключены и включены: %d", n)
}

func formatSubs(b *strings.Builder, list []ctl.SubLine) {
	if len(list) == 0 {
		b.WriteString("Подписок нет.\n")
		return
	}
	for _, s := range list {
		l := fmt.Sprintf("%s — %d %s", s.Name, s.Profiles, plural(s.Profiles, "сервер", "сервера", "серверов"))
		if s.Missing > 0 {
			l += fmt.Sprintf(" (%d нет в подписке)", s.Missing)
		}
		if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err == nil {
			l += ", обновлено " + t.Local().Format("02.01 15:04")
		} else {
			l += ", ещё не обновлялась"
		}
		if !s.Enabled {
			l += " (выключена)"
		}
		b.WriteString(l + "\n")
		if s.Summary != "" {
			b.WriteString("  " + s.Summary + "\n")
		}
		if s.LastError != "" {
			b.WriteString("  ошибка: " + s.LastError + "\n")
		}
	}
}

// formatSubUpdates prints the results; false when any failed.
func formatSubUpdates(b *strings.Builder, list []ctl.SubUpdateView) bool {
	if len(list) == 0 {
		b.WriteString("Нет включённых подписок.\n")
		return true
	}
	ok := true
	for _, u := range list {
		if !u.OK {
			ok = false
			b.WriteString(u.Name + ": ошибка: " + u.Error + "\n")
			continue
		}
		p := []string{fmt.Sprintf("новых %d", u.Added), fmt.Sprintf("обновлено %d", u.Updated)}
		if u.Removed > 0 {
			p = append(p, fmt.Sprintf("удалено %d", u.Removed))
		}
		if u.MissingKept > 0 {
			p = append(p, fmt.Sprintf("оставлено с пометкой «нет в подписке» %d (их используют правила)", u.MissingKept))
		}
		b.WriteString(u.Name + ": " + strings.Join(p, ", ") + "\n")
	}
	return ok
}

// logEntry is logx.Entry as it arrives.
type logEntry struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

func formatLog(b *strings.Builder, e logEntry) {
	fmt.Fprintf(b, "%s %-5s %s\n", e.Time.Local().Format("15:04:05"), strings.ToUpper(e.Level), e.Msg)
}
