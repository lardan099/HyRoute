package cli

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Human output of `stats` (stats feature), worded as the page
// «Статистика».

var monthNames = []string{"январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь",
	"ноябрь", "декабрь"}

// dmy is "YYYY-MM-DD" as 28.09.2026.
func dmy(day string) string {
	if len(day) != 10 {
		return day
	}
	return day[8:10] + "." + day[5:7] + "." + day[0:4]
}

// statsPeriod words a report's period: «сегодня (28.09.2026)», «7 дней
// (22.09.2026 – 28.09.2026)», «сентябрь 2026».
func statsPeriod(r ReportLite) string {
	span := dmy(r.From)
	if r.To != r.From {
		span += " – " + dmy(r.To)
	}
	switch r.Period {
	case "today":
		return "сегодня (" + span + ")"
	case "yesterday":
		return "вчера (" + span + ")"
	case "7d":
		return "7 дней (" + span + ")"
	case "30d":
		return "30 дней (" + span + ")"
	}
	var y, m int
	if _, err := fmt.Sscanf(r.Period, "%4d-%2d", &y, &m); err == nil && m >= 1 && m <= 12 {
		return fmt.Sprintf("%s %d", monthNames[m-1], y)
	}
	return r.Period + " (" + span + ")"
}

// statConns: every connection of a row (VPN, direct attempts, blocked,
// refused); statVPN: bytes through the VPN (api.ts).
func statConns(c StatCountersLite) int64 { return c.TC + c.DC + c.BC + c.F }
func statVPN(c StatCountersLite) int64   { return c.TU + c.TD }

func count(n int64, one, few, many string) string {
	return fmt.Sprintf("%d %s", n, plural(int(n%100), one, few, many))
}

// statLabel is the page's name of a row of table t.
func statLabel(t string, r StatRowLite) string {
	if r.Key == "*" {
		return "Остальные"
	}
	switch t {
	case "apps":
		switch {
		case r.Key == "":
			return "Программа не определена"
		case strings.HasPrefix(r.Key, "proxy:"):
			n := r.Name
			if n == "" {
				n = strings.TrimPrefix(r.Key, "proxy:")
			}
			if r.Gone {
				return "Прокси «" + n + "» (удалён)"
			}
			return "Прокси «" + n + "»"
		case r.Name != "":
			return r.Name
		}
		return r.Key[strings.LastIndex(r.Key, `\`)+1:]
	case "servers":
		switch {
		case r.Key == "":
			return "Сервер не выбран"
		case r.Gone && r.Name == "":
			return "сервер (удалён)"
		case r.Gone:
			return r.Name + " (удалён)"
		case r.Name != "":
			return r.Name
		}
	case "groups":
		switch {
		case r.Gone && r.Name == "":
			return "группа (удалена)"
		case r.Gone:
			return r.Name + " (удалена)"
		case r.Name != "":
			return r.Name
		}
	}
	return r.Key
}

// statsTopN is how many rows of each table are printed.
const statsTopN = 10

// formatStatTable prints the top rows by VPN traffic («Остальные» last).
func formatStatTable(b *strings.Builder, title, t string, rows []StatRowLite) {
	if len(rows) == 0 {
		return
	}
	rows = append([]StatRowLite(nil), rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		a, c := rows[i], rows[j]
		if (a.Key == "*") != (c.Key == "*") {
			return c.Key == "*"
		}
		if d := statVPN(a.StatCountersLite) - statVPN(c.StatCountersLite); d != 0 {
			return d > 0
		}
		return statConns(a.StatCountersLite) > statConns(c.StatCountersLite)
	})
	more := 0
	if len(rows) > statsTopN {
		more, rows = len(rows)-statsTopN, rows[:statsTopN]
	}
	labels := make([]string, len(rows))
	traffic := make([]string, len(rows))
	lw, tw := 0, 0
	for i, r := range rows {
		labels[i] = statLabel(t, r)
		traffic[i] = "↑ " + fmtBytes(r.TU) + " ↓ " + fmtBytes(r.TD)
		lw = max(lw, utf8.RuneCountInString(labels[i]))
		tw = max(tw, utf8.RuneCountInString(traffic[i]))
	}
	b.WriteString(title + ":\n")
	for i, r := range rows {
		conns := statConns(r.StatCountersLite)
		if t == "servers" || t == "groups" {
			conns = r.TC + r.F // the page's count for servers and groups
		}
		fmt.Fprintf(b, "  %s   %s   %d\n", pad(labels[i], lw), pad(traffic[i], tw), conns)
	}
	if more > 0 {
		fmt.Fprintf(b, "  … и ещё %d (все — в окне HyRoute, «Статистика»)\n", more)
	}
}

// formatStats is `stats`: the summary cards, the error lines and the top
// of each table.
func formatStats(b *strings.Builder, r ReportLite) {
	b.WriteString("Статистика: " + statsPeriod(r) + "\n")
	if r.Since != "" && r.Since > r.From {
		b.WriteString("Статистика собирается с " + dmy(r.Since) + "\n")
	}
	switch {
	case r.ModeUnread:
		b.WriteString("Внимание: не удалось прочитать режим сбора статистики, поэтому сбор выключен. Выберите режим в окне HyRoute: «Статистика» → «Сбор статистики».\n")
	case r.Mode == "off":
		b.WriteString("Статистика выключена в окне HyRoute. Уже собранная статистика показана ниже.\n")
	}
	if r.StoreError != "" && !r.ModeUnread {
		b.WriteString("Внимание: не всё в порядке с файлами статистики: " + r.StoreError + "\n")
	}
	t := r.Total
	fmt.Fprintf(b, "Через VPN: %s (↑ %s · ↓ %s), %s\n", fmtBytes(statVPN(t)), fmtBytes(t.TU), fmtBytes(t.TD),
		count(t.TC, "соединение", "соединения", "соединений"))
	fmt.Fprintf(b, "Напрямую: ↑ %s (примерно, входящий не считается), %s\n", fmtBytes(t.DU), count(t.DC, "попытка", "попытки", "попыток"))
	fmt.Fprintf(b, "Заблокировано: %s\n", count(t.BC, "соединение", "соединения", "соединений"))
	for _, e := range []struct {
		n int64
		l string
	}{
		{t.F, "Отклонено соединений"},
		{t.FO, "Ушло на запасной сервер"},
		{r.Events.Drops, "Обрывы связи с сервером"},
		{r.Events.EngineFails, "Сбои перехвата"},
	} {
		if e.n > 0 {
			fmt.Fprintf(b, "%s: %d\n", e.l, e.n)
		}
	}
	if len(r.Apps)+len(r.Servers)+len(r.Groups) == 0 && statConns(t) == 0 && statVPN(t) == 0 && t.DU == 0 {
		b.WriteString("За этот период статистики нет. Она собирается, пока HyRoute подключён.\n")
		return
	}
	formatStatTable(b, "Программы", "apps", r.Apps)
	formatStatTable(b, "Серверы", "servers", r.Servers)
	formatStatTable(b, "Группы", "groups", r.Groups)
}
