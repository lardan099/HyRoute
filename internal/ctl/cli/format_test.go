package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/lardan099/hyroute/internal/ctl"
)

// golden compares out with testdata/<name>.golden (-update rewrites it).
func golden(t *testing.T, name, out string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *update {
		os.WriteFile(p, []byte(out), 0o644)
		return
	}
	want, err := os.ReadFile(p)
	if err != nil || string(want) != out {
		t.Errorf("%s differs:\n%s", name, out)
	}
}

func rawOf(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// runOut runs args against a fake HyRoute answering with v.
func runOut(t *testing.T, v any, args ...string) (string, int) {
	t.Helper()
	r := newRig(func(ctl.Request) []ctl.Frame { return result(v) })
	code := r.run(args...)
	return r.stdout.String() + r.stderr.String(), code
}

func TestFormatStatus(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	connected := ctl.StatusView{App: "v1.3.0", State: "connected", Since: now.Add(-72 * time.Minute).Format(time.RFC3339),
		Main:       &ctl.TargetView{Kind: "group", ID: "grp-1", Name: "Auto"},
		MainGroup:  rawOf(map[string]any{"id": "grp-1", "name": "Auto", "strategy": "latency", "activeName": "DE-2", "up": 2, "total": 3}),
		Ruleset:    &ctl.RulesetBrief{ID: "r1", Name: "Дом", Count: 2},
		KillSwitch: "armed",
		Tunnels: []ctl.TunnelView{{ID: "a", Name: "🇩🇪 DE-1", State: "connected", Sent: 13002342, Recv: 325058560},
			{ID: "b", Name: "NL", State: "connecting", Restarts: 2, Rejected: 3, Message: "timeout"}},
		Warnings:  []string{"правило «YouTube»: сервер удалён — соединения будут отклоняться"},
		SubAlerts: rawOf([]map[string]any{{"id": "s", "name": "Панель", "level": "low", "text": "осталось 8.0 ГБ из 100 ГБ (8 %)"}}),
		Net:       rawOf(map[string]any{"rule": "Дом", "ruleId": "n1", "override": true, "error": "не подключено: нет серверов"}),
		DNS: rawOf(map[string]any{"byRules": true, "notApplied": false, "pauseLeft": 61, "health": []map[string]any{
			{"via": "tunnel", "profile": "a", "upstream": "Cloudflare", "kind": "timeout"},
			{"via": "tunnel", "profile": "b", "upstream": "Cloudflare", "kind": "timeout"},
			{"via": "direct", "upstream": "Quad9", "kind": "tls"}}}),
		Stats: rawOf(map[string]any{"passed": 1}),
	}
	out, _ := runOut(t, connected, "status")
	golden(t, "status-connected", out)

	// Off by a network rule: why, and how to connect.
	off := ctl.StatusView{App: "v1.3.0", State: "disconnected", Main: &ctl.TargetView{Kind: "server", ID: "a", Name: "DE"},
		Net: rawOf(map[string]any{"rule": "Дом", "off": true, "offBy": "Дом"}), Warnings: []string{}}
	out, _ = runOut(t, off, "status")
	if !strings.Contains(out, "Сеть: правило «Дом»\nОтключено правилом сети «Дом»: весь трафик идёт напрямую, kill switch не действует. hyroutectl connect подключит до следующей смены сети.\n") {
		t.Fatal(out)
	}

	blocked := ctl.StatusView{App: "v1.3.0", State: "error", Message: "драйвер WinDivert не загрузился", KillSwitch: "blocking",
		Main: &ctl.TargetView{Kind: "server", ID: "a", Name: "🇩🇪 DE-1"}, LoadError: "settings.json: плохой JSON", Warnings: []string{}}
	out, _ = runOut(t, blocked, "status")
	golden(t, "status-error", out)
}

func TestFormatLists(t *testing.T) {
	servers := []ctl.ServerView{
		{ID: "a1b2c3d4e5f6", Name: "🇩🇪 DE-1", Address: "de1.example.com:443", Source: "Панель", Main: true, State: "connected"},
		{ID: "d4e5f6a7b8c9", Name: "NL", Address: "203.0.113.7:8443"},
		{ID: "778899aabbcc", Name: "US", Address: "us.example.com:443", Source: "Панель", Missing: true},
	}
	out, _ := runOut(t, servers, "servers")
	golden(t, "servers", out)
	out, _ = runOut(t, []ctl.ServerView{}, "servers")
	if out != "Серверов нет. Добавьте сервер в HyRoute (страница «Серверы»).\n" {
		t.Fatal(out)
	}

	groups := ctl.GroupsView{Groups: []ctl.GroupLine{
		{ID: "grp-1", Name: "Auto", Strategy: "latency", ActiveName: "DE-2", Main: true, Running: true, Total: 3, Members: []ctl.MemberLine{
			{Name: "DE-1", LatencyMs: 42}, {Name: "DE-2", ProbeError: "timeout"}, {Name: "NL", Skipped: true, Errors: 3}}},
		{ID: "grp-2", Name: "Резерв", Strategy: "failover", Total: 1, Members: []ctl.MemberLine{{ID: "x", Missing: true}}},
	}}
	out, _ = runOut(t, groups, "groups")
	golden(t, "groups", out)

	check := ctl.CheckView{Profile: "a", OK: false, ExternalIP: "198.51.100.4", LatencyMs: 120, Steps: []ctl.CheckStep{
		{Name: "TCP через сервер", OK: true, Detail: "соединение есть", Ms: 820}, {Name: "UDP", Detail: "нет ответа"}, {Name: "IPv6", Skip: true}}}
	out, code := runOut(t, check, "check", "DE")
	golden(t, "check", out)
	if code != 1 {
		t.Fatal("a failed check exits 1:", code)
	}

	rs := ctl.RulesetsView{Active: "r1", Saved: true, List: []ctl.RulesetLine{
		{ID: "r1", Name: "Дом", Rules: 12, DefaultAction: "tunnel", Active: true},
		{ID: "r2", Name: "Работа", Rules: 1, DefaultAction: "direct", Warnings: 2},
		{ID: "r3", Name: "Старый", Rules: 3, DefaultAction: "block", Error: "не компилируется"}}}
	out, _ = runOut(t, rs, "ruleset")
	golden(t, "rulesets", out)

	subs := []ctl.SubLine{{Name: "Панель", Enabled: true, Profiles: 12, Missing: 1, UpdatedAt: "2026-09-28T10:12:00Z", Summary: "Осталось 86 ГБ / 12 дней"},
		{Name: "Старая", Profiles: 1, LastError: "HTTP 404"}}
	out, _ = runOut(t, subs, "subs")
	if !strings.Contains(out, "Панель — 12 серверов (1 нет в подписке), обновлено 28.09 ") || !strings.Contains(out, "  Осталось 86 ГБ / 12 дней\n") ||
		!strings.Contains(out, "Старая — 1 сервер, ещё не обновлялась (выключена)\n  ошибка: HTTP 404\n") {
		t.Fatal(out)
	}
	upd := []ctl.SubUpdateView{{Name: "Панель", OK: true, Added: 2, Updated: 1}, {Name: "Старая", Error: "HTTP 404"}}
	out, code = runOut(t, upd, "subs", "update")
	if out != "Панель: новых 2, обновлено 1\nСтарая: ошибка: HTTP 404\n" || code != 1 {
		t.Fatal(out, code)
	}
}

func TestFormatExplain(t *testing.T) {
	steps := []StepLite{
		{Index: 0, Name: "Реклама", Enabled: false, Reason: "сайт не подходит", Action: "block"},
		{Index: 1, Name: "GitHub", Enabled: true, Matched: true, Winner: true, Reason: "сайт github.com в списке", Action: "tunnel"},
		{Index: -1, Enabled: true, Reason: "не проверялось", Action: "direct"},
	}
	cases := map[string]struct {
		ex   ExplanationLite
		args []string
	}{
		"explain-tunnel": {ExplanationLite{Steps: steps, Winner: steps[1], ProfileName: "🇩🇪 DE-1", Notes: []string{"Для правил по IP взят адрес 140.82.121.4."}},
			[]string{"explain", "github.com", "--port", "443", "--steps"}},
		"explain-group":   {ExplanationLite{Winner: steps[1], ProfileName: "Auto", Group: true, Via: "DE-2"}, []string{"explain", "github.com", "--udp"}},
		"explain-default": {ExplanationLite{Winner: StepLite{Index: -1, Action: "direct"}}, []string{"explain", "example.org"}},
		"explain-nomain":  {ExplanationLite{Winner: StepLite{Index: -1, Action: "tunnel"}}, []string{"explain", "example.org", "--udp", "--port=53"}},
		"explain-block":   {ExplanationLite{Winner: StepLite{Index: 0, Action: "block", Reason: "реклама"}}, []string{"explain", "ads.example"}},
		"explain-dns": {ExplanationLite{Winner: steps[1], ProfileName: "🇩🇪 DE-1", DNS: &DNSExplainLite{Route: "tunnel", ProfileName: "🇩🇪 DE-1",
			Upstream: "Cloudflare", Rule: "GitHub", Cond: "proto", Proto: "tcp", NoIPv6: true, System: &DNSExplainLite{Route: "addr", Rule: "default"}}},
			[]string{"explain", "github.com", "--app", "git.exe"}},
	}
	for name, c := range cases {
		out, _ := runOut(t, c.ex, c.args...)
		golden(t, name, out)
	}
}

func TestFormatRulesAndLogs(t *testing.T) {
	imp := ctl.RulesImportView{Summary: "Правил в файле: 2", Rules: 2, JSON: true, Saved: true,
		Warnings: []ctl.ErrorLine{{Line: 2, Text: "«Old»: сервер не найден — соединения будут отклоняться"}, {Line: 0, Text: "«Всё остальное» из файла не применено"}}}
	out, _ := runOut(t, imp, "rules", "import", "testdata/help.golden")
	golden(t, "rules-import", out)

	r := newRig(func(ctl.Request) []ctl.Frame {
		return failFrames("rules", "В файле ошибки, ничего не сохранено",
			ctl.ErrorLine{Line: 1, Text: "«A»: сервер «US» не найден — добавьте его в HyRoute или поправьте файл"}, ctl.ErrorLine{Line: 0, Text: "Неизвестное поле «x»"})
	})
	r.d.Stdin = strings.NewReader(`{"hyroute":"rules"}`)
	if code := r.run("rules", "import", "-", "--replace"); code != 6 ||
		r.stderr.String() != "В файле ошибки, ничего не сохранено:\n  правило 1: «A»: сервер «US» не найден — добавьте его в HyRoute или поправьте файл\n  Неизвестное поле «x»\n" {
		t.Fatalf("%d %q", code, r.stderr.String())
	}

	r = newRig(func(ctl.Request) []ctl.Frame {
		t0 := time.Date(2026, 9, 28, 15, 4, 5, 0, time.Local)
		page, _ := json.Marshal([]logEntry{{Seq: 1, Time: t0, Level: "info", Msg: "connected: filters active"}, {Seq: 2, Time: t0, Level: "error", Msg: "boom"}})
		return append([]ctl.Frame{{V: 1, OK: true, Event: page}}, result(struct{}{})...)
	})
	r.run("logs", "-n", "2")
	if r.stdout.String() != "15:04:05 INFO  connected: filters active\n15:04:05 ERROR boom\n" {
		t.Fatalf("%q", r.stdout.String())
	}
}

func TestFmtHelpers(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KB", 13002342: "12 MB", 325058560: "310 MB", 5 << 40: "5.0 TB"} {
		if got := fmtBytes(n); got != want {
			t.Errorf("fmtBytes(%d) = %s", n, got)
		}
	}
	for d, want := range map[time.Duration]string{500 * time.Millisecond: "500 мс", 1500 * time.Millisecond: "1.5 с",
		725 * time.Second: "12 мин 5 с", 72 * time.Minute: "1 ч 12 мин", 119600 * time.Millisecond: "2 мин 0 с"} {
		if got := fmtDuration(d); got != want {
			t.Errorf("fmtDuration(%v) = %s", d, got)
		}
	}
}

// A provider-controlled name or a log line never reaches the console with
// escape sequences in it; --json keeps the value (escaped).
func TestHumanOutputNeutralisesControls(t *testing.T) {
	evil := "DE\x1b]52;c;aGk=\x07\u202e1\u0085"
	out, _ := runOut(t, []ctl.ServerView{{ID: "a1b2c3d4e5f6", Name: evil, Address: "de.example.com:443"}}, "servers")
	if strings.ContainsAny(out, "\x1b\x07\u202e\u0085") || !strings.Contains(out, "DE\uFFFD]52;c;aGk=\uFFFD\uFFFD1\uFFFD") {
		t.Fatalf("%q", out)
	}
	r := newRig(func(ctl.Request) []ctl.Frame {
		page, _ := json.Marshal([]logEntry{{Seq: 1, Level: "info", Msg: "a\x1b[2Kb\rc"}})
		return append([]ctl.Frame{{V: 1, OK: true, Event: page}}, result(struct{}{})...)
	})
	r.run("logs")
	if s := r.stdout.String(); strings.ContainsAny(s, "\x1b\r") || !strings.Contains(s, "a\uFFFD[2Kb\uFFFDc\n") {
		t.Fatalf("%q", s)
	}
	r = newRig(func(ctl.Request) []ctl.Frame { return failFrames("failed", "Не подключено: \x1b[31mX") })
	r.run("connect")
	if s := r.stderr.String(); strings.Contains(s, "\x1b") || !strings.Contains(s, "\uFFFD[31mX") {
		t.Fatalf("%q", s)
	}
	out, _ = runOut(t, []ctl.ServerView{{ID: "a1b2c3d4e5f6", Name: evil}}, "servers", "--json")
	var got struct{ Result []ctl.ServerView }
	if json.Unmarshal([]byte(out), &got) != nil || len(got.Result) != 1 || got.Result[0].Name != evil || strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("%q", out)
	}
}

// A UTF-16 file with an error: hyroutectl decodes it, sends it once for
// the server to parse, and reports exit 6 (the server saves nothing with
// errors: ctlserver's TestCommands).
func TestRulesImportUTF16Errors(t *testing.T) {
	text := "a.example -> direct\r\nbad line\r\n"
	b := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(text)) {
		b = append(b, byte(u), byte(u>>8))
	}
	p := filepath.Join(t.TempDir(), "rules.txt")
	os.WriteFile(p, b, 0o644)
	var got []ctl.RulesImportArgs
	r := newRig(func(req ctl.Request) []ctl.Frame {
		var a ctl.RulesImportArgs
		json.Unmarshal(req.Args, &a)
		got = append(got, a)
		return failFrames("rules", "Правила не сохранены", ctl.ErrorLine{Line: 2, Text: "непонятная строка"})
	})
	if code := r.run("rules", "import", p); code != 6 {
		t.Fatalf("exit %d: %s", code, r.stderr.String())
	}
	if len(got) != 1 || got[0].DryRun || got[0].Content != text {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(r.stderr.String(), "строка 2: непонятная строка") {
		t.Fatal(r.stderr.String())
	}
}

func TestFormatNetworks(t *testing.T) {
	yes := false
	v := NetModesLite{
		Config: NetConfigLite{Enabled: true, Rules: []NetRuleLite{
			{Name: "Дом", NetActionLite: NetActionLite{Connect: "disconnect"}},
			{Name: "Офис", NetActionLite: NetActionLite{Ruleset: "r2", Connect: "connect"}},
			{Name: "Кафе", Enabled: &yes, NetActionLite: NetActionLite{Ruleset: "gone"}},
			{Name: "Гости"}},
			Unknown: NetActionLite{Connect: "connect"}},
		Current:  NetSnapshotLite{Active: &NetworkLite{Name: "Сеть 3", Category: "private", Adapter: "wifi", SSID: "Home"}},
		Match:    &NetMatchLite{Name: "Дом", NetActionLite: NetActionLite{Connect: "disconnect"}},
		State:    NetStateLite{Rule: "Дом", Override: true, Text: "Сеть сменилась: правило «Дом»"},
		Rulesets: []NetRulesetLite{{ID: "r1", Name: "Дом"}, {ID: "r2", Name: "Работа"}},
	}
	out, _ := runOut(t, v, "networks")
	golden(t, "networks", out)

	none := NetModesLite{Unavailable: "HyRoute не получает сведения о сетях Windows", Config: NetConfigLite{Unknown: NetActionLite{Connect: "connect"}}}
	out, _ = runOut(t, none, "networks")
	if out != "Действовать по сети: выключено\nНедоступно: HyRoute не получает сведения о сетях Windows\nСейчас: нет сети\nПравила:\n  Неизвестная сеть → подключиться\n" {
		t.Fatalf("%q", out)
	}

	out, _ = runOut(t, v, "networks", "on")
	if out != "Действовать по сети: включено.\nПрименится при смене сети; применить сейчас: hyroutectl networks apply\n" {
		t.Fatalf("%q", out)
	}
	out, _ = runOut(t, NetModesLite{}, "networks", "off")
	if out != "Действовать по сети: выключено. Текущее подключение не меняется.\n" {
		t.Fatalf("%q", out)
	}
	out, code := runOut(t, v, "networks", "apply", "--yes")
	if out != "Применено: Сеть сменилась: правило «Дом»\n" || code != 0 {
		t.Fatalf("%q %d", out, code)
	}
	// The rule's action failed: said, exit 1.
	v.State.Error = "не подключено: нет серверов"
	out, code = runOut(t, v, "networks", "apply")
	if !strings.Contains(out, "Внимание: правило сети «Дом» не выполнено: не подключено: нет серверов\n") || code != 1 {
		t.Fatalf("%q %d", out, code)
	}
}

func TestFormatStats(t *testing.T) {
	c := func(tc, tu, td int64) StatCountersLite { return StatCountersLite{TC: tc, TU: tu, TD: td} }
	rep := ReportLite{Period: "7d", From: "2026-09-22", To: "2026-09-28", Since: "2026-09-24", Mode: "",
		Total:  StatCountersLite{TC: 3412, TU: 1288490189, TD: 15032385536, DC: 9100, DU: 859832320, BC: 212, F: 3, FO: 1},
		Events: StatEventsLite{Drops: 2},
		Apps: []StatRowLite{{Key: `c:\program files\google\chrome.exe`, StatCountersLite: c(1204, 1181116006, 10522669875)},
			{Key: "proxy:p1", Name: "Прокси 1080", StatCountersLite: c(5, 1024, 2048)}, {Key: "*", StatCountersLite: c(1, 1, 1)},
			{Key: "", StatCountersLite: c(2, 2048, 4096)}},
		Sites:   []StatRowLite{{Key: "youtube.com", StatCountersLite: c(300, 1, 900000000)}, {Key: "", StatCountersLite: c(1, 0, 0)}},
		Servers: []StatRowLite{{Key: "a", Name: "🇩🇪 DE-1", StatCountersLite: StatCountersLite{TC: 10, F: 2, TU: 5, TD: 6}}, {Key: "b", Name: "US", Gone: true}},
	}
	for i := 0; i < 12; i++ {
		rep.Sites = append(rep.Sites, StatRowLite{Key: fmt.Sprintf("s%02d.example", i), StatCountersLite: c(1, 0, int64(i))})
	}
	out, _ := runOut(t, rep, "stats", "7d")
	golden(t, "stats", out)

	empty := ReportLite{Period: "2026-08", From: "2026-08-01", To: "2026-08-31", Mode: "off"}
	out, _ = runOut(t, empty, "stats", "2026-08")
	if out != "Статистика: август 2026\nСтатистика выключена в окне HyRoute. Уже собранная статистика показана ниже.\n"+
		"Через VPN: 0 B (↑ 0 B · ↓ 0 B), 0 соединений\nНапрямую: ↑ 0 B (примерно, входящий не считается), 0 попыток\nЗаблокировано: 0 соединений\n"+
		"За этот период статистики нет. Она собирается, пока HyRoute подключён.\n" {
		t.Fatalf("%q", out)
	}
	for p, want := range map[string]string{"today": "сегодня (28.09.2026)", "yesterday": "вчера (28.09.2026)", "30d": "30 дней (28.09.2026)"} {
		if got := statsPeriod(ReportLite{Period: p, From: "2026-09-28", To: "2026-09-28"}); got != want {
			t.Errorf("%s: %s", p, got)
		}
	}
}
