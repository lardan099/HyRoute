// Package cli is hyroutectl's logic without Windows: arguments, input
// decoding, finding HyRoute, the exchange and the output. cmd/hyroutectl
// wires the real pipe, console and signals.
package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/ctl"
)

// entry is one line (or block) of the help, and the words that select it
// for "hyroutectl <cmd> --help".
type entry struct {
	cmd   string // first word
	sub   string // second word ("" = any)
	usage string
	desc  []string
}

type section struct {
	title   string
	entries []entry
}

// help is the command table: both help outputs are generated from it.
var help = []section{
	{"Подключение", []entry{
		{"status", "", "status", []string{"состояние подключения"}},
		{"connect", "", "connect [--wait[=СЕК]]", []string{"подключить; --wait — дождаться серверов (по умолчанию 30 с)"}},
		{"disconnect", "", "disconnect", []string{"отключить; снимает блокировку kill switch, как кнопка «Отключить»"}},
		{"reconnect", "", "reconnect [--wait[=СЕК]]", []string{"переподключить"}},
		{"start", "", "start [--no-wait]", []string{"запустить HyRoute, если он не запущен"}},
		{"show", "", "show", []string{"открыть окно HyRoute"}},
	}},
	{"Серверы и правила", []entry{
		{"servers", "", "servers", []string{"список серверов"}},
		{"groups", "", "groups", []string{"группы серверов"}},
		{"server", "", "server [ИМЯ]", []string{"показать или сменить основной сервер (или группу)"}},
		{"check", "", "check ИМЯ", []string{"проверить сервер"}},
		{"ruleset", "", "ruleset [ИМЯ] [--reconnect]", []string{"список профилей правил или включить профиль"}},
		{"explain", "", "explain АДРЕС [--app ПРОГРАММА.exe] [--port N] [--udp] [--steps]", []string{"куда пойдёт соединение и почему"}},
		{"rules", "export", "rules export [--format text|json] [-o ФАЙЛ]", []string{"правила текстом или в JSON — в консоль или в файл"}},
		{"rules", "import", "rules import ФАЙЛ|- [--format text|json] [--replace] [--dry-run]", []string{
			"добавить правила из файла («-» — из ввода);", "--replace заменяет все; --dry-run только проверяет"}},
	}},
	{"Прочее", []entry{
		{"subs", "", "subs", []string{"подписки"}},
		{"subs", "update", "subs update [ИМЯ]", []string{"обновить подписку (без имени — все включённые)"}},
		{"networks", "", "networks", []string{"правила сетей и текущая сеть"}},
		{"networks", "apply", "networks apply [--yes]", []string{"применить правило текущей сети сейчас;", "--yes — даже если правило отключает HyRoute"}},
		{"networks", "on", "networks on|off", []string{"включить или выключить «Действовать по сети»"}},
		{"stats", "", "stats [today|yesterday|7d|30d|ГГГГ-ММ]", []string{"статистика трафика (по умолчанию today)"}},
		{"logs", "", "logs [engine|hysteria|СЕРВЕР] [-n N] [--follow]", []string{"журнал (по умолчанию engine, последние 50 строк)"}},
		{"version", "", "version", []string{"версии hyroutectl, HyRoute и Hysteria"}},
	}},
}

const helpHead = `hyroutectl — управление запущенным HyRoute из командной строки

Использование: hyroutectl <команда> [параметры]
`

const helpTail = `Общие параметры:
  --json          вывод для скриптов: {"ok":true,"result":…} или {"ok":false,…},
                  JSON только из ASCII-символов
  --private       скрыть IP, домены, адреса серверов и ссылки, как «Скрыть данные»
  --timeout=СЕК   сколько ждать ответа HyRoute
  --user=SID      HyRoute другой учётной записи (только из окна администратора)
  -h, --help      эта справка

Коды выхода: 0 — успех; 1 — команда не выполнена; 2 — неверные аргументы или имя не найдено;
3 — HyRoute не запущен; 4 — нет доступа; 5 — время ожидания истекло; 6 — в файле правил ошибки;
7 — эта версия HyRoute не поддерживает команду; 130 — прервано (Ctrl+C).
`

// helpCol is where descriptions start.
const helpCol = 28

func (e entry) lines() string {
	var b strings.Builder
	u := "  " + e.usage
	pad := helpCol - utf8.RuneCountInString(u)
	for i, d := range e.desc {
		switch {
		case i == 0 && pad >= 2:
			b.WriteString(u + strings.Repeat(" ", pad) + d + "\n")
		case i == 0:
			b.WriteString(u + "\n" + strings.Repeat(" ", helpCol) + d + "\n")
		default:
			b.WriteString(strings.Repeat(" ", helpCol) + d + "\n")
		}
	}
	return b.String()
}

// HelpText is the full help.
func HelpText() string {
	var b strings.Builder
	b.WriteString(helpHead)
	for _, s := range help {
		b.WriteString("\n" + s.title + ":\n")
		for _, e := range s.entries {
			b.WriteString(e.lines())
		}
	}
	b.WriteString("\n" + helpTail)
	return b.String()
}

// commandHelp is the help lines of one command ("" when unknown).
func commandHelp(cmd string) string {
	var b strings.Builder
	for _, s := range help {
		for _, e := range s.entries {
			if e.cmd == cmd {
				b.WriteString(e.lines())
			}
		}
	}
	return b.String()
}

// Invocation is a parsed command line.
type Invocation struct {
	Help    string // non-empty: print it and exit 0
	Name    string // the command as the user wrote it ("rules import")
	Wire    string // the request's cmd ("" = handled locally: start)
	Args    any    // the request's args
	JSON    bool
	Private bool
	Timeout time.Duration // 0 = the command's default
	User    string        // --user SID

	Wait    int    // connect/reconnect --wait seconds
	NoWait  bool   // start --no-wait
	File    string // rules import: the file ("-" = stdin)
	Out     string // rules export -o
	Steps   bool   // explain --steps
	Follow  bool   // logs --follow
	Target  string // explain: the address as typed (for the output)
	Port    int
	UDP     bool
	Enabled bool // networks on|off
	Yes     bool // networks apply --yes
}

// UsageError is a bad command line (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usagef(f string, a ...any) error { return &UsageError{fmt.Sprintf(f, a...)} }

var (
	sidRe    = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
	periodRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}$`)
)

// valueFlags need a value (--x=v or --x v).
var valueFlags = map[string]bool{"--app": true, "--port": true, "-o": true, "-n": true, "--timeout": true, "--format": true, "--user": true}

// cmdFlags: the flags each command takes besides the common ones.
var cmdFlags = map[string][]string{
	"connect": {"--wait"}, "reconnect": {"--wait"}, "start": {"--no-wait"},
	"ruleset": {"--reconnect"}, "explain": {"--app", "--port", "--udp", "--tcp", "--steps"},
	"rules export": {"--format", "-o"}, "rules import": {"--format", "--replace", "--dry-run"},
	"logs": {"-n", "--follow"}, "networks apply": {"--yes"},
}

// Parse reads the arguments after the program name. env is HYROUTE_PRIVATE.
func Parse(argv []string, envPrivate string) (*Invocation, error) {
	inv := &Invocation{Private: envPrivate == "1"}
	var pos []string
	flags := map[string]string{}
	var order []string
	noMore := false
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if noMore || !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		if a == "--" {
			noMore = true
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		switch name {
		case "-h", "--help":
			flags["--help"] = ""
			continue
		case "--json", "--private", "--udp", "--tcp", "--steps", "--replace", "--dry-run", "--follow", "--reconnect", "--no-wait", "--yes":
			if hasVal {
				return nil, usagef("Параметр %s пишется без значения", name)
			}
		case "--wait":
			// Only --wait=N: "--wait 60" would read 60 as an argument.
		default:
			if !valueFlags[name] {
				return nil, usagef("Неизвестный параметр %s", name)
			}
			if !hasVal {
				if i+1 >= len(argv) {
					return nil, usagef("У параметра %s нет значения", name)
				}
				i++
				val = argv[i]
			}
		}
		if _, dup := flags[name]; dup {
			return nil, usagef("Параметр %s указан дважды", name)
		}
		if name == "--wait" && !hasVal {
			val = ""
		} else if name == "--wait" && val == "" {
			return nil, usagef("--wait=СЕК: число секунд от 1 до 600")
		}
		flags[name] = val
		order = append(order, name)
	}

	_, inv.JSON = flags["--json"]
	if _, ok := flags["--private"]; ok {
		inv.Private = true
	}
	if v, ok := flags["--timeout"]; ok {
		n, err := seconds(v)
		if err != nil {
			return nil, usagef("--timeout: число секунд от 1 до 600")
		}
		inv.Timeout = time.Duration(n) * time.Second
	}
	if v, ok := flags["--user"]; ok {
		if !sidRe.MatchString(v) {
			return nil, usagef("Неверный SID")
		}
		inv.User = v
	}

	if len(pos) == 0 || pos[0] == "help" {
		if len(pos) > 1 {
			if h := commandHelp(pos[1]); h != "" {
				inv.Help = h
				return inv, nil
			}
		}
		inv.Help = HelpText()
		return inv, nil
	}
	cmd, rest := pos[0], pos[1:]
	if _, ok := flags["--help"]; ok {
		if h := commandHelp(cmd); h != "" {
			inv.Help = h
		} else {
			inv.Help = HelpText()
		}
		return inv, nil
	}
	name := cmd
	switch cmd {
	case "rules":
		if len(rest) == 0 || rest[0] != "export" && rest[0] != "import" {
			return nil, usagef("Укажите rules export или rules import")
		}
		name, rest = "rules "+rest[0], rest[1:]
	case "subs":
		if len(rest) > 0 && rest[0] == "update" {
			name, rest = "subs update", rest[1:]
		}
	case "networks":
		if len(rest) > 0 && (rest[0] == "apply" || rest[0] == "on" || rest[0] == "off") {
			name, rest = "networks "+rest[0], rest[1:]
		}
	}
	inv.Name = name

	// Flags that belong to other commands.
	for _, f := range order {
		switch f {
		case "--json", "--private", "--timeout", "--user":
			continue
		case "--format":
			if name != "rules export" && name != "rules import" {
				return nil, usagef("Параметр --format есть только у rules export и rules import")
			}
		}
		ok := false
		for _, g := range cmdFlags[name] {
			ok = ok || g == f
		}
		if !ok {
			return nil, usagef("Параметр %s не подходит к команде «%s»", f, name)
		}
	}
	joined := strings.Join(rest, " ")
	noArgs := func() error {
		if len(rest) > 0 {
			return usagef("Лишний аргумент «%s»", rest[0])
		}
		return nil
	}

	switch name {
	case "status", "disconnect", "show", "servers", "groups", "version", "subs":
		inv.Wire, inv.Args = name, struct{}{}
		return inv, noArgs()
	case "connect", "reconnect":
		if v, ok := flags["--wait"]; ok {
			inv.Wait = 30
			if v != "" {
				n, err := seconds(v)
				if err != nil {
					return nil, usagef("--wait=СЕК: число секунд от 1 до 600")
				}
				inv.Wait = n
			}
		}
		inv.Wire, inv.Args = name, ctl.WaitArgs{Wait: inv.Wait}
		return inv, noArgs()
	case "start":
		_, inv.NoWait = flags["--no-wait"]
		return inv, noArgs()
	case "server":
		inv.Wire, inv.Args = "server", ctl.NameArgs{Name: joined}
	case "check":
		if joined == "" {
			return nil, usagef("Укажите имя сервера: hyroutectl check ИМЯ")
		}
		inv.Wire, inv.Args = "check", ctl.NameArgs{Name: joined}
	case "ruleset":
		_, rc := flags["--reconnect"]
		if joined == "" {
			if rc {
				return nil, usagef("--reconnect — вместе с именем профиля: hyroutectl ruleset ИМЯ --reconnect")
			}
			inv.Wire, inv.Args = "rulesets", struct{}{}
			return inv, nil
		}
		inv.Wire, inv.Args = "ruleset", ctl.RulesetArgs{Name: joined, Reconnect: rc}
	case "explain":
		if len(rest) == 0 {
			return nil, usagef("Укажите сайт или IP: hyroutectl explain github.com")
		}
		if len(rest) > 1 {
			return nil, usagef("Лишний аргумент «%s»", rest[1])
		}
		_, udp := flags["--udp"]
		_, tcp := flags["--tcp"]
		if udp && tcp {
			return nil, usagef("--udp и --tcp вместе не указываются")
		}
		a := ctl.ExplainArgs{Target: rest[0], App: flags["--app"], UDP: udp}
		if v, ok := flags["--port"]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return nil, usagef("Порт — число от 1 до 65535")
			}
			a.Port = n
		}
		_, inv.Steps = flags["--steps"]
		a.Steps = inv.Steps
		inv.Target, inv.Port, inv.UDP = rest[0], a.Port, udp
		inv.Wire, inv.Args = "explain", a
	case "rules export":
		f := flags["--format"]
		if f != "" && f != "text" && f != "json" {
			return nil, usagef("--format: text или json")
		}
		if f == "" {
			f = "text"
		}
		inv.Out = flags["-o"]
		if _, ok := flags["-o"]; ok && inv.Out == "" {
			return nil, usagef("У параметра -o нет значения")
		}
		inv.Wire, inv.Args = "rules-export", ctl.RulesExportArgs{Format: f}
		return inv, noArgs()
	case "rules import":
		if len(rest) == 0 {
			return nil, usagef("Укажите файл: hyroutectl rules import rules.txt (или «-» для ввода)")
		}
		if len(rest) > 1 {
			return nil, usagef("Лишний аргумент «%s»", rest[1])
		}
		f := flags["--format"]
		if f != "" && f != "text" && f != "json" {
			return nil, usagef("--format: text или json")
		}
		if f == "" {
			f = "auto"
		}
		_, rep := flags["--replace"]
		_, dry := flags["--dry-run"]
		inv.File = rest[0]
		inv.Wire, inv.Args = "rules-import", ctl.RulesImportArgs{Format: f, Replace: rep, DryRun: dry}
	case "subs update":
		inv.Wire, inv.Args = "subs-update", ctl.NameArgs{Name: joined}
	case "networks":
		if len(rest) > 0 {
			return nil, usagef("networks: apply, on или off")
		}
		inv.Wire, inv.Args = "networks", struct{}{}
	case "networks apply":
		_, inv.Yes = flags["--yes"]
		inv.Wire, inv.Args = "networks-apply", ctl.NetworksApplyArgs{Yes: inv.Yes}
		return inv, noArgs()
	case "networks on", "networks off":
		inv.Enabled = name == "networks on"
		inv.Wire, inv.Args = "networks-set", ctl.NetworksSetArgs{Enabled: inv.Enabled}
		return inv, noArgs()
	case "stats":
		p := joined
		if p == "" {
			p = "today"
		}
		if p != "today" && p != "yesterday" && p != "7d" && p != "30d" && !periodRe.MatchString(p) {
			return nil, usagef("Период: today, yesterday, 7d, 30d или ГГГГ-ММ")
		}
		inv.Wire, inv.Args = "stats", ctl.StatsArgs{Period: p}
	case "logs":
		a := ctl.LogsArgs{Kind: joined, Lines: 50}
		if v, ok := flags["-n"]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 10000 {
				return nil, usagef("-n: число от 1 до 10000")
			}
			a.Lines = n
		}
		_, a.Follow = flags["--follow"]
		inv.Follow = a.Follow
		inv.Wire, inv.Args = "logs", a
	default:
		return nil, usagef("Неизвестная команда «%s»", cmd)
	}
	return inv, nil
}

// seconds reads 1–600.
func seconds(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 600 {
		return 0, fmt.Errorf("bad seconds %q", v)
	}
	return n, nil
}

// Mutating reports whether the invocation changes something (read-only
// mode refuses it; also used for the default timeouts).
func (inv *Invocation) timeoutDefault() time.Duration {
	switch inv.Wire {
	case "connect", "reconnect":
		return 180*time.Second + time.Duration(inv.Wait)*time.Second
	case "networks-apply":
		// A rule may connect or switch the rule profile.
		return 180 * time.Second
	case "check":
		return 90 * time.Second
	case "subs-update":
		if a, ok := inv.Args.(ctl.NameArgs); ok && a.Name != "" {
			return 120 * time.Second
		}
		// Each subscription of several (HyRoute reports every one done,
		// and the limit starts again).
		return 10 * time.Minute
	case "logs":
		if inv.Follow {
			return 0 // none
		}
	}
	if inv.Name == "start" {
		return 60 * time.Second
	}
	return 30 * time.Second
}

// flagOfField maps a request arg's JSON name back to its flag (unknown-arg).
var flagOfField = map[string]string{
	"wait": "--wait", "app": "--app", "port": "--port", "udp": "--udp", "steps": "--steps", "format": "--format",
	"replace": "--replace", "dryRun": "--dry-run", "lines": "-n", "follow": "--follow", "reconnect": "--reconnect", "yes": "--yes",
	"period": "stats ПЕРИОД", "enabled": "on|off", "name": "ИМЯ", "kind": "ЖУРНАЛ", "target": "АДРЕС", "content": "ФАЙЛ",
}
