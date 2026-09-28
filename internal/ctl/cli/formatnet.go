package cli

import (
	"fmt"
	"strings"
)

// Human output of the DNS line of explain (dns) and of the networks
// commands (netmodes), worded as the window words them.

// dnsRuleLabel: the rule texts of HyRoute's own DNS answers (api.ts).
var dnsRuleLabel = map[string]string{
	"dns: DoH canary":              "DoH браузеров отключён",
	"dns: ECH off":                 "ECH отключён",
	"dns: IPv6 not through tunnel": "IPv6 не через VPN",
	"dns: browser DoH":             "DoH браузера заблокирован",
}

// dnsText is Explain.svelte's dnsText: how the name resolves; p leads.
func dnsText(d DNSExplainLite, p string) string {
	rule := func(r string) string {
		if r == "" || r == "default" {
			return "Всё остальное"
		}
		if l, ok := dnsRuleLabel[r]; ok {
			return l
		}
		return r
	}
	cond := ""
	switch d.Cond {
	case "app":
		cond = " Так решает правило «" + rule(d.Rule) + "» для программы: спрашивает служба DNS Windows, и программа неизвестна."
	case "proto":
		proto := d.Proto
		if proto == "" {
			proto = "некоторых портов"
		}
		cond = " Так решает правило «" + rule(d.Rule) + "» для " + proto + "."
	}
	switch d.Route {
	case "tunnel":
		return p + ": имя разрешается через " + d.ProfileName + " (" + d.Upstream + ")." + cond
	case "block":
		return p + ": имя не разрешается — правило «" + rule(d.Rule) + "»." + cond
	case "upstream":
		return p + ": напрямую через " + d.Upstream + "."
	case "addr":
		return p + ": как обычно, через DNS-сервер сети: выше есть правило «" + rule(d.Rule) + "» по IP/geoip, и через VPN адрес сайта мог бы оказаться другим."
	case "server":
		return p + ": адрес сервера Hysteria — всегда через DNS-сервер сети."
	case "local":
		return p + ": локальное имя — как обычно."
	case "service":
		return p + ": имя нужно Windows или самому HyRoute — всегда через DNS-сервер сети."
	}
	return p + ": как обычно, через DNS-сервер сети."
}

var (
	netAdapterWords  = map[string]string{"wifi": "Wi-Fi", "ethernet": "Ethernet", "mobile": "мобильная сеть", "other": "другая сеть"}
	netCategoryWords = map[string]string{"private": "частная сеть", "public": "общедоступная сеть", "domain": "доменная сеть"}
)

// netAction words a rule's action: «профиль правил «Работа», подключиться».
func netAction(a NetActionLite, rulesets []NetRulesetLite) string {
	var parts []string
	if a.Ruleset != "" {
		name := ""
		for _, r := range rulesets {
			if r.ID == a.Ruleset {
				name = r.Name
			}
		}
		if name != "" {
			parts = append(parts, "профиль правил «"+name+"»")
		} else {
			parts = append(parts, "профиль правил (удалён)")
		}
	}
	switch a.Connect {
	case "connect":
		parts = append(parts, "подключиться")
	case "disconnect":
		parts = append(parts, "отключиться (всё напрямую)")
	}
	if len(parts) == 0 {
		return "ничего"
	}
	return strings.Join(parts, ", ")
}

// netNow words the current network: «Wi-Fi «Home» (частная сеть)».
func netNow(n *NetworkLite) string {
	if n == nil {
		return "нет сети"
	}
	s := netAdapterWords[n.Adapter]
	if s == "" {
		s = "сеть"
	}
	name := n.Name
	if n.SSID != "" {
		name = n.SSID
	}
	if name != "" {
		s += " «" + name + "»"
	}
	if c := netCategoryWords[n.Category]; c != "" {
		s += " (" + c + ")"
	}
	return s
}

func onOff(on bool) string {
	if on {
		return "включено"
	}
	return "выключено"
}

// formatNetworks is `networks`: the switch, the current network, its rule
// and the rules in order.
func formatNetworks(b *strings.Builder, v NetModesLite) {
	if v.LoadError != "" {
		b.WriteString("Недоступно: networks.json не загружен: " + v.LoadError + "\n")
	}
	b.WriteString("Действовать по сети: " + onOff(v.Config.Enabled) + "\n")
	if v.Unavailable != "" {
		b.WriteString("Недоступно: " + v.Unavailable + "\n")
	}
	b.WriteString("Сейчас: " + netNow(v.Current.Active) + "\n")
	if v.Current.Error != "" {
		b.WriteString("Не удалось определить сеть полностью: " + v.Current.Error + "\n")
	}
	if m := v.Match; m != nil {
		name := m.Name
		if m.Unknown {
			name = "Неизвестная сеть"
		}
		l := "Правило: " + name + " → " + netAction(m.NetActionLite, v.Rulesets)
		switch {
		case !v.Config.Enabled:
		case v.State.Restored:
			l += " · как до обновления, до смены сети"
		case v.State.Override:
			l += " · вручную до смены сети"
		}
		b.WriteString(l + "\n")
	}
	if v.State.Pending {
		b.WriteString("Сеть определяется — отключение и смена профиля правил ждут, пока Windows её опознает.\n")
	}
	if v.State.Text != "" {
		b.WriteString("Последнее действие: " + v.State.Text + "\n")
	}
	if v.State.Error != "" {
		b.WriteString("Внимание: правило сети «" + v.State.Rule + "» не выполнено: " + v.State.Error + "\n")
	}
	b.WriteString("Правила:\n")
	for i, r := range v.Config.Rules {
		l := fmt.Sprintf("  %d. «%s» → %s", i+1, r.Name, netAction(r.NetActionLite, v.Rulesets))
		if r.Enabled != nil && !*r.Enabled {
			l += " (выключено)"
		}
		b.WriteString(l + "\n")
	}
	b.WriteString("  Неизвестная сеть → " + netAction(v.Config.Unknown, v.Rulesets) + "\n")
}

// formatNetworksSet is `networks on|off`: saving never acts.
func formatNetworksSet(b *strings.Builder, v NetModesLite) {
	if v.Config.Enabled {
		b.WriteString("Действовать по сети: включено.\n")
		b.WriteString("Применится при смене сети; применить сейчас: hyroutectl networks apply\n")
		return
	}
	b.WriteString("Действовать по сети: выключено. Текущее подключение не меняется.\n")
}

// formatNetworksApply is `networks apply`.
func formatNetworksApply(b *strings.Builder, v NetModesLite) {
	text := v.State.Text
	if text == "" {
		text = "правило сети ничего не меняет"
	}
	b.WriteString("Применено: " + text + "\n")
	if v.State.Error != "" {
		b.WriteString("Внимание: правило сети «" + v.State.Rule + "» не выполнено: " + v.State.Error + "\n")
	}
}
