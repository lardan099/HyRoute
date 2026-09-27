package geodata

// Category is a well-known category with a human description, for the
// rule editor's picker and examples.
type Category struct {
	Name  string `json:"name"`  // "youtube"
	Kind  string `json:"kind"`  // "site" (geosite:) or "ip" (geoip:)
	Title string `json:"title"` // "YouTube"
	Hint  string `json:"hint"`
	Group string `json:"group"`
	// Sources are the presets that have the category (see onlyIn).
	Sources []string `json:"sources"`
}

// Categories missing from some presets (checked against their releases);
// every other popular category is in all of them.
var onlyIn = map[string][]string{
	"site:ru-blocked":               {"runetfreedom"},
	"ip:ru-blocked":                 {"runetfreedom"},
	"site:ru-blocked-all":           {"runetfreedom"},
	"site:ru-available-only-inside": {"runetfreedom"},
	"site:win-spy":                  {"runetfreedom", "loyalsoldier", "hysteria-geodata"},
	"ip:telegram":                   {"runetfreedom", "loyalsoldier", "hysteria-geodata"},
	"ip:cloudflare":                 {"runetfreedom", "loyalsoldier", "hysteria-geodata"},
	"site:whitelist":                {"hysteria-geodata"},
	"ip:direct":                     {"hysteria-geodata"},
	"site:category-geoblock-ru":     {"hysteria-geodata"},
	"site:torrent":                  {"hysteria-geodata"},
}

func init() {
	for i := range Popular {
		c := &Popular[i]
		if s, ok := onlyIn[c.Kind+":"+c.Name]; ok {
			c.Sources = s
			continue
		}
		for _, s := range Sources {
			c.Sources = append(c.Sources, s.ID)
		}
	}
}

// Popular categories; all present in the runetfreedom databases (the
// default). Russian lists (ru-*) are missing from the other sources.
var Popular = []Category{
	{"ru-blocked", "site", "Заблокированное в России", "Сайты из реестра блокировок (РКН и др.), без мусорных записей. Обычно — через VPN.", "Россия", nil},
	{"ru-blocked", "ip", "Заблокированные IP в России", "Адреса из реестра блокировок: сервисы, к которым обращаются по IP.", "Россия", nil},
	{"ru-blocked-all", "site", "Весь реестр блокировок", "Полный список (≈1,4 млн доменов). Тяжёлый: +50 МБ памяти.", "Россия", nil},
	{"ru-available-only-inside", "site", "Работает только из России", "Госуслуги, банки, сервисы, которые не открываются из-за границы. Обычно — напрямую.", "Россия", nil},
	{"category-ru", "site", "Российские сайты", "Популярные сайты в зоне .ru и российские сервисы.", "Россия", nil},
	{"ru", "ip", "IP-адреса России", "Все адреса российских сетей. Обычно — напрямую.", "Россия", nil},
	{"category-gov-ru", "site", "Госсайты России", "Госуслуги, ФНС, суды и другие государственные сайты.", "Россия", nil},
	{"category-bank-ru", "site", "Российские банки", "Сайты и приложения банков.", "Россия", nil},
	{"yandex", "site", "Яндекс", "Все сервисы Яндекса.", "Россия", nil},
	{"vk", "site", "VK", "ВКонтакте и сервисы VK.", "Россия", nil},
	{"whitelist", "site", "Белый список RoscomVPN", "Российские сайты и проверки IP, которые должны видеть российский адрес. Обычно — напрямую.", "Россия", nil},
	{"direct", "ip", "Российские IP (RoscomVPN)", "IP России и Беларуси без заблокированных сетей и зарубежных CDN. Обычно — напрямую.", "Россия", nil},
	{"category-geoblock-ru", "site", "Не работает с российским IP", "Сайты, которые ограничивают доступ из России (Adobe, habr и др.). Обычно — через VPN.", "Россия", nil},

	{"youtube", "site", "YouTube", "Сайт, видео (googlevideo.com), превью, приложение.", "Сервисы", nil},
	{"google", "site", "Google", "Поиск, Gmail, Диск, Карты и другие сервисы Google (YouTube отдельно).", "Сервисы", nil},
	{"telegram", "site", "Telegram", "Сайты Telegram (t.me, telegram.org).", "Сервисы", nil},
	{"telegram", "ip", "Telegram (IP)", "Серверы Telegram: приложение подключается к ним по IP, без имени сайта.", "Сервисы", nil},
	{"discord", "site", "Discord", "Сайт, приложение, голосовые серверы.", "Сервисы", nil},
	{"whatsapp", "site", "WhatsApp", "", "Сервисы", nil},
	{"instagram", "site", "Instagram", "", "Сервисы", nil},
	{"facebook", "site", "Facebook", "", "Сервисы", nil},
	{"meta", "site", "Meta целиком", "Facebook, Instagram, WhatsApp, Threads.", "Сервисы", nil},
	{"twitter", "site", "X (Twitter)", "", "Сервисы", nil},
	{"tiktok", "site", "TikTok", "", "Сервисы", nil},
	{"linkedin", "site", "LinkedIn", "", "Сервисы", nil},
	{"reddit", "site", "Reddit", "", "Сервисы", nil},
	{"signal", "site", "Signal", "", "Сервисы", nil},
	{"netflix", "site", "Netflix", "", "Сервисы", nil},
	{"spotify", "site", "Spotify", "", "Сервисы", nil},
	{"twitch", "site", "Twitch", "", "Сервисы", nil},
	{"github", "site", "GitHub", "", "Сервисы", nil},
	{"microsoft", "site", "Microsoft", "Windows, Office, Outlook, Xbox и др.", "Сервисы", nil},
	{"apple", "site", "Apple", "", "Сервисы", nil},
	{"steam", "site", "Steam", "", "Сервисы", nil},
	{"cloudflare", "ip", "Cloudflare (IP)", "Адреса Cloudflare: через них работает огромная часть сайтов.", "Сервисы", nil},

	{"openai", "site", "ChatGPT / OpenAI", "", "ИИ", nil},
	{"anthropic", "site", "Claude / Anthropic", "", "ИИ", nil},
	{"category-ai-!cn", "site", "Все ИИ-сервисы", "ChatGPT, Claude, Gemini, Copilot, Perplexity и другие (кроме китайских).", "ИИ", nil},

	{"category-ads-all", "site", "Реклама", "Рекламные сети и баннеры. Обычно — блок.", "Прочее", nil},
	{"torrent", "site", "Торрент-трекеры", "Трекеры и сайты торрентов. Лучше напрямую, чтобы не нагружать VPN-сервер.", "Прочее", nil},
	{"win-spy", "site", "Телеметрия Windows", "Серверы сбора данных Windows. Обычно — блок.", "Прочее", nil},
	{"private", "ip", "Локальная сеть", "Роутер, принтер, 192.168.x.x, 10.x.x.x. Всегда — напрямую. Работает без скачивания баз.", "Прочее", nil},
}
