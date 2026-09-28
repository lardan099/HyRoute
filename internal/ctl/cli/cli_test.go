package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/ctl"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

const self = "S-1-5-21-1-2-3-1001"

// fakeHy speaks the protocol over net.Pipe: hello (or first), then
// handle's frames for the request.
type fakeHy struct {
	mu      sync.Mutex
	first   *ctl.Frame
	handle  func(ctl.Request) []ctl.Frame
	reqs    []ctl.Request
	dialed  []string
	dialErr map[string]error // by pipe name
	run     map[string]ctl.RunState
	pipes   []string
	written map[string][]byte
	started bool
}

func (f *fakeHy) dial(name string, _ time.Duration) (net.Conn, uint32, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, name)
	err, ok := f.dialErr[name]
	f.mu.Unlock()
	if ok && err != nil {
		return nil, 0, err
	}
	if !ok && f.dialErr != nil {
		return nil, 0, ctl.ErrNotRunning
	}
	c, s := net.Pipe()
	go f.serve(s)
	return c, 42, nil
}

func (f *fakeHy) serve(s net.Conn) {
	defer s.Close()
	first := ctl.Frame{V: 1, OK: true, Hello: &ctl.Hello{App: "v1.3.0", Proto: 1, MinProto: 1, Mode: "full"}}
	if f.first != nil {
		first = *f.first
	}
	if ctl.WriteJSON(s, first, ctl.MaxResponse) != nil || first.Hello == nil {
		return
	}
	b, err := ctl.ReadFrame(s, ctl.MaxRequest)
	if err != nil {
		return
	}
	var req ctl.Request
	json.Unmarshal(b, &req)
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	frames := f.handle(req)
	if len(frames) == 0 {
		return // hung up without a final frame
	}
	for _, fr := range frames {
		if ctl.WriteJSON(s, fr, ctl.MaxResponse) != nil {
			return
		}
	}
	// Wait for the client to hang up.
	s.Read(make([]byte, 1))
}

func result(v any) []ctl.Frame {
	b, _ := json.Marshal(v)
	return []ctl.Frame{{V: 1, OK: true, Final: true, Result: b}}
}

func failFrames(code, msg string, lines ...ctl.ErrorLine) []ctl.Frame {
	return []ctl.Frame{{V: 1, Final: true, Error: &ctl.Error{Code: code, Message: msg, Lines: lines}}}
}

type rig struct {
	hy             *fakeHy
	d              *Deps
	stdout, stderr *bytes.Buffer
}

func newRig(handle func(ctl.Request) []ctl.Frame) *rig {
	hy := &fakeHy{handle: handle, run: map[string]ctl.RunState{}, written: map[string][]byte{}}
	r := &rig{hy: hy, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	r.d = &Deps{Stdin: strings.NewReader(""), Stdout: r.stdout, Stderr: r.stderr, Env: func(string) string { return "" },
		SelfSID: self, Version: "v1.3.0", Dial: hy.dial,
		Probe:     func(ev string) (ctl.RunState, error) { return hy.run[ev], nil },
		FindPipes: func() ([]string, error) { return hy.pipes, nil },
		ReadFile:  func(p string) ([]byte, error) { return os.ReadFile(p) },
		WriteFile: func(p string, b []byte) error { hy.written[p] = b; return nil },
		Launch:    func(io.Writer) error { hy.started = true; return nil },
		Now:       func() time.Time { return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) },
		Poll:      5 * time.Millisecond}
	return r
}

func (r *rig) run(args ...string) int { return Run(context.Background(), args, r.d) }

func TestParseArgs(t *testing.T) {
	ok := []struct {
		args []string
		wire string
		want any
	}{
		{[]string{"status"}, "status", struct{}{}},
		{[]string{"connect", "--wait"}, "connect", ctl.WaitArgs{Wait: 30}},
		{[]string{"--json", "connect", "--wait=60"}, "connect", ctl.WaitArgs{Wait: 60}},
		{[]string{"server", "DE", "1"}, "server", ctl.NameArgs{Name: "DE 1"}},
		{[]string{"server"}, "server", ctl.NameArgs{}},
		{[]string{"ruleset"}, "rulesets", struct{}{}},
		{[]string{"ruleset", "Работа", "--reconnect"}, "ruleset", ctl.RulesetArgs{Name: "Работа", Reconnect: true}},
		{[]string{"explain", "github.com", "--app", "chrome.exe", "--port=443", "--steps"}, "explain",
			ctl.ExplainArgs{Target: "github.com", App: "chrome.exe", Port: 443, Steps: true}},
		{[]string{"explain", "--udp", "1.1.1.1"}, "explain", ctl.ExplainArgs{Target: "1.1.1.1", UDP: true}},
		{[]string{"rules", "export", "--format", "json", "-o", "r.json"}, "rules-export", ctl.RulesExportArgs{Format: "json"}},
		{[]string{"rules", "import", "-", "--replace", "--dry-run"}, "rules-import", ctl.RulesImportArgs{Format: "auto", Replace: true, DryRun: true}},
		{[]string{"subs", "update"}, "subs-update", ctl.NameArgs{}},
		{[]string{"subs", "update", "Моя", "панель"}, "subs-update", ctl.NameArgs{Name: "Моя панель"}},
		{[]string{"networks", "on"}, "networks-set", ctl.NetworksSetArgs{Enabled: true}},
		{[]string{"networks", "apply"}, "networks-apply", ctl.NetworksApplyArgs{}},
		{[]string{"networks", "apply", "--yes"}, "networks-apply", ctl.NetworksApplyArgs{Yes: true}},
		{[]string{"networks", "off"}, "networks-set", ctl.NetworksSetArgs{}},
		{[]string{"networks"}, "networks", struct{}{}},
		{[]string{"stats", "2026-09"}, "stats", ctl.StatsArgs{Period: "2026-09"}},
		{[]string{"stats"}, "stats", ctl.StatsArgs{Period: "today"}},
		{[]string{"logs", "-n", "5000", "--follow", "DE", "1"}, "logs", ctl.LogsArgs{Kind: "DE 1", Lines: 5000, Follow: true}},
		{[]string{"server", "--", "-x"}, "server", ctl.NameArgs{Name: "-x"}},
	}
	for _, c := range ok {
		inv, err := Parse(c.args, "")
		if err != nil || inv.Wire != c.wire {
			t.Errorf("%v: %v %v", c.args, inv, err)
			continue
		}
		if a, b := jsonOf(inv.Args), jsonOf(c.want); a != b {
			t.Errorf("%v: args %s, want %s", c.args, a, b)
		}
	}
	bad := map[string][]string{
		"Неизвестный параметр --foo":                                                {"status", "--foo"},
		"Параметр --format есть только у rules export и rules import":               {"status", "--format", "json"},
		"Укажите имя сервера: hyroutectl check ИМЯ":                                 {"check"},
		"Укажите сайт или IP: hyroutectl explain github.com":                        {"explain"},
		"Укажите файл: hyroutectl rules import rules.txt (или «-» для ввода)":       {"rules", "import"},
		"Укажите rules export или rules import":                                     {"rules"},
		"Лишний аргумент «x»":                                                       {"status", "x"},
		"networks: apply, on или off":                                               {"networks", "up"},
		"Параметр --yes не подходит к команде «networks on»":                        {"networks", "on", "--yes"},
		"Порт — число от 1 до 65535":                                                {"explain", "a.com", "--port", "70000"},
		"-n: число от 1 до 10000":                                                   {"logs", "-n", "0"},
		"--wait=СЕК: число секунд от 1 до 600":                                      {"connect", "--wait=0"},
		"Лишний аргумент «60»":                                                      {"connect", "--wait", "60"},
		"--timeout: число секунд от 1 до 600":                                       {"status", "--timeout=601"},
		"Период: today, yesterday, 7d, 30d или ГГГГ-ММ":                             {"stats", "week"},
		"Неверный SID":                                                              {"status", "--user=bob"},
		"--udp и --tcp вместе не указываются":                                       {"explain", "a.com", "--udp", "--tcp"},
		"Параметр --steps не подходит к команде «status»":                           {"status", "--steps"},
		"--reconnect — вместе с именем профиля: hyroutectl ruleset ИМЯ --reconnect": {"ruleset", "--reconnect"},
		"Неизвестная команда «frobnicate»":                                          {"frobnicate"},
	}
	for want, args := range bad {
		_, err := Parse(args, "")
		var ue *UsageError
		if !errors.As(err, &ue) || ue.Msg != want {
			t.Errorf("%v: %v, want %q", args, err, want)
		}
	}
	// --timeout and --json anywhere; HYROUTE_PRIVATE.
	inv, _ := Parse([]string{"status", "--timeout", "5", "--json"}, "1")
	if inv.Timeout != 5*time.Second || !inv.JSON || !inv.Private {
		t.Fatalf("%+v", inv)
	}
}

func jsonOf(v any) string { b, _ := ctl.Marshal(v); return string(b) }

func TestHelp(t *testing.T) {
	want, _ := os.ReadFile(filepath.Join("testdata", "help.golden"))
	if got := HelpText(); got != string(want) {
		t.Fatalf("help differs from cli.md §1.2:\n%s", got)
	}
	r := newRig(nil)
	if r.run() != 0 || r.stdout.String() != string(want) {
		t.Fatal("no args must print the help")
	}
	r = newRig(nil)
	if r.run("rules", "--help") != 0 || !strings.Contains(r.stdout.String(), "rules export") || !strings.Contains(r.stdout.String(), "--dry-run только проверяет") ||
		strings.Contains(r.stdout.String(), "status") {
		t.Fatal(r.stdout.String())
	}
	r = newRig(nil)
	if r.run("status", "--bogus") != 2 || r.stderr.String() != "Неизвестный параметр --bogus. Справка: hyroutectl --help\n" {
		t.Fatalf("%q", r.stderr.String())
	}
}

func TestDecodeInput(t *testing.T) {
	text := "a.com -> vpn\r\n"
	le := []byte{0xff, 0xfe}
	be := []byte{0xfe, 0xff}
	for _, r := range text {
		le = append(le, byte(r), byte(r>>8))
		be = append(be, byte(r>>8), byte(r))
	}
	for name, in := range map[string][]byte{"utf8": []byte(text), "bom": append([]byte{0xef, 0xbb, 0xbf}, text...), "le": le, "be": be} {
		if s, err := DecodeInput(in); err != nil || s != text {
			t.Errorf("%s: %q %v", name, s, err)
		}
	}
	for want, in := range map[string][]byte{
		"Файл не в кодировке UTF-8 (сохраните его в UTF-8)":      {0xc3, 0x28},
		"В файле есть управляющие символы — это не текст правил": []byte("a\x00b"),
		"Файл больше 1 МБ": bytes.Repeat([]byte("a"), ctl.MaxImport+1),
	} {
		if _, err := DecodeInput(in); err == nil || err.Error() != want {
			t.Errorf("%q: %v", want, err)
		}
	}
	// "-" reads stdin.
	r := newRig(func(req ctl.Request) []ctl.Frame {
		var a ctl.RulesImportArgs
		json.Unmarshal(req.Args, &a)
		if a.Content != "x.com -> напрямую\n" {
			return failFrames("usage", "wrong content "+a.Content)
		}
		return result(ctl.RulesImportView{Summary: "Правил: 1", Rules: 1, Saved: true})
	})
	r.d.Stdin = strings.NewReader("x.com -> напрямую\n")
	if r.run("rules", "import", "-") != 0 || !strings.Contains(r.stdout.String(), "Сохранено: правил добавлено 1.") {
		t.Fatal(r.stdout.String(), r.stderr.String())
	}
}

func TestDiscover(t *testing.T) {
	own := ctl.PipeName(self)
	status := func(ctl.Request) []ctl.Frame { return result(ctl.StatusView{App: "v1", State: "disconnected"}) }
	type tc struct {
		dialErr map[string]error
		run     ctl.RunState
		pipes   []string
		admin   bool
		user    string
		exit    int
		msg     string
	}
	other, other2 := "S-1-5-21-9-9-9-1002", "S-1-5-21-9-9-9-1003"
	cases := map[string]tc{
		"own":          {dialErr: map[string]error{own: nil}, exit: 0},
		"none":         {dialErr: map[string]error{}, exit: 3, msg: "HyRoute не запущен. Запустить: hyroutectl start"},
		"settled":      {dialErr: map[string]error{}, run: ctl.RunSettled, exit: 4, msg: "не принимает команды"},
		"foreign":      {dialErr: map[string]error{}, run: ctl.RunForeign, exit: 4, msg: "другой программой"},
		"other":        {dialErr: map[string]error{}, pipes: []string{other}, exit: 4, msg: "другой учётной записью"},
		"other admin":  {dialErr: map[string]error{ctl.PipeName(other): nil}, pipes: []string{other}, admin: true, exit: 0},
		"two admin":    {dialErr: map[string]error{}, pipes: []string{other, other2, self}, admin: true, exit: 2, msg: other + ", " + other2},
		"--user":       {dialErr: map[string]error{ctl.PipeName(other): nil}, user: other, exit: 0},
		"--user gone":  {dialErr: map[string]error{}, pipes: []string{other2}, admin: true, user: other, exit: 3},
		"impostor":     {dialErr: map[string]error{own: ctl.ErrImpostor}, exit: 4, msg: "создан другой программой"},
		"busy":         {dialErr: map[string]error{own: ctl.ErrBusy}, exit: 1, msg: "занят"},
		"access":       {dialErr: map[string]error{own: ctl.ErrDenied}, exit: 4, msg: "отказал в доступе"},
		"starting out": {dialErr: map[string]error{}, run: ctl.RunStarting, exit: 5, msg: "не ответил за 1 с после запуска"},
	}
	for name, c := range cases {
		r := newRig(status)
		r.hy.dialErr, r.hy.pipes, r.d.Admin = c.dialErr, c.pipes, c.admin
		ev := ctl.RunEventName(self)
		if c.user != "" {
			ev = ctl.RunEventName(c.user)
		}
		r.hy.run[ev] = c.run
		args := []string{"status", "--timeout=1"}
		if c.user != "" {
			args = append(args, "--user="+c.user)
		}
		if got := r.run(args...); got != c.exit || !strings.Contains(r.stderr.String(), c.msg) {
			t.Errorf("%s: exit %d %q", name, got, r.stderr.String())
		}
	}

	// Starting: waits (once «запускается…»), then the command runs.
	r := newRig(status)
	r.hy.dialErr = map[string]error{own: ctl.ErrNotRunning}
	r.hy.run[ctl.RunEventName(self)] = ctl.RunStarting
	go func() {
		time.Sleep(30 * time.Millisecond)
		r.hy.mu.Lock()
		r.hy.dialErr[own] = nil
		r.hy.mu.Unlock()
	}()
	r.d.Now = time.Now
	if got := r.run("status"); got != 0 || strings.Count(r.stderr.String(), "HyRoute запускается…") != 1 {
		t.Fatal(got, r.stderr.String())
	}
}

func TestExitMapping(t *testing.T) {
	cases := []struct {
		first  *ctl.Frame
		frames []ctl.Frame
		args   []string
		exit   int
		msg    string
		sent   bool
	}{
		{frames: failFrames("read-only", "Команда недоступна: разрешён только просмотр. Включите «Полный доступ» в «Настройки» → «Командная строка» (интерфейс «Для опытных»)."), args: []string{"connect"}, exit: 4, msg: "только просмотр", sent: true},
		{frames: failFrames("unknown-command", "x"), args: []string{"stats"}, exit: 7, msg: "Эта версия HyRoute не поддерживает команду «stats»: обновите HyRoute.", sent: true},
		{frames: []ctl.Frame{{V: 1, Final: true, Error: &ctl.Error{Code: "unknown-arg", Field: "port"}}}, args: []string{"explain", "a.com", "--port", "443"}, exit: 7,
			msg: "Эта версия HyRoute не знает параметр --port команды «explain»: обновите HyRoute или уберите параметр.", sent: true},
		{frames: failFrames("failed", "Не подключено: HyRoute завершает работу"), args: []string{"connect"}, exit: 1, msg: "HyRoute завершает работу", sent: true},
		{frames: failFrames("usage", "Сервер «XX» не найден"), args: []string{"server", "XX"}, exit: 2, msg: "Сервер «XX» не найден\n", sent: true},
		{frames: nil, args: []string{"status"}, exit: 1, msg: "Связь с HyRoute прервалась", sent: true},
		{first: &ctl.Frame{V: 1, Final: true, Error: &ctl.Error{Code: "denied", Message: msgDenied}}, args: []string{"status"}, exit: 4, msg: "отказал в доступе"},
		{first: &ctl.Frame{V: 1, OK: true, Hello: &ctl.Hello{Proto: 2, MinProto: 2}}, args: []string{"status"}, exit: 7, msg: "hyroutectl старее HyRoute"},
		{first: &ctl.Frame{V: 1, OK: true, Hello: &ctl.Hello{Proto: 0}}, args: []string{"status"}, exit: 7, msg: "обновите HyRoute"},
		{first: &ctl.Frame{V: 1, OK: true, Hello: &ctl.Hello{Proto: 1}}, frames: result(ctl.StatusView{}), args: []string{"status"}, exit: 0, sent: true},
		{frames: failFrames("rules", "В файле ошибки, ничего не сохранено", ctl.ErrorLine{Line: 5, Text: "плохо"}), args: []string{"rules", "import", "-"}, exit: 6,
			msg: "В файле ошибки, ничего не сохранено:\n  строка 5: плохо\n", sent: true},
	}
	for i, c := range cases {
		frames := c.frames
		r := newRig(func(ctl.Request) []ctl.Frame { return frames })
		r.hy.first = c.first
		r.d.Stdin = strings.NewReader("a.com -> vpn")
		got := r.run(c.args...)
		if got != c.exit || !strings.Contains(r.stderr.String(), c.msg) || (len(r.hy.reqs) > 0) != c.sent {
			t.Errorf("%d %v: exit %d %q sent %d", i, c.args, got, r.stderr.String(), len(r.hy.reqs))
		}
	}
}

func TestConnectWording(t *testing.T) {
	cases := []struct {
		v    ctl.ConnectView
		args []string
		line string
		exit int
	}{
		{ctl.ConnectView{Already: true, Status: ctl.StatusView{State: "connecting"}}, []string{"connect"}, "Уже подключается…", 0},
		{ctl.ConnectView{Already: true, Status: ctl.StatusView{State: "tunnel-down"}}, []string{"connect"}, "Уже подключено.", 0},
		{ctl.ConnectView{Status: ctl.StatusView{State: "connected"}}, []string{"connect"}, "Подключено.", 0},
		{ctl.ConnectView{Status: ctl.StatusView{State: "connected"}}, []string{"reconnect"}, "Переподключено.", 0},
		{ctl.ConnectView{Status: ctl.StatusView{State: "starting"}}, []string{"connect"}, "Фильтры включены, серверы подключаются…", 0},
		{ctl.ConnectView{Status: ctl.StatusView{State: "tunnel-down", Message: "NL недоступен"}}, []string{"connect"}, "Подключено, но сервер недоступен.\nHyRoute v1 — сервер недоступен", 0},
		{ctl.ConnectView{Status: ctl.StatusView{State: "error", Message: "драйвер"}}, []string{"connect"}, "Не подключено: драйвер", 1},
		{ctl.ConnectView{Status: ctl.StatusView{State: "disconnected"}}, []string{"connect"}, "Не подключено: HyRoute отключился", 1},
		{ctl.ConnectView{WaitedOut: true, Status: ctl.StatusView{State: "connecting"}}, []string{"connect", "--wait"}, "Не дождались подключения за 30 с: серверы ещё подключаются", 5},
		{ctl.ConnectView{Already: true, Status: ctl.StatusView{State: "connected"}}, []string{"connect", "--wait=5"}, "Подключено.", 0},
	}
	for _, c := range cases {
		c.v.Status.App = "v1"
		r := newRig(func(ctl.Request) []ctl.Frame { return result(c.v) })
		if got := r.run(c.args...); got != c.exit || !strings.HasPrefix(r.stdout.String(), c.line) {
			t.Errorf("%+v: %d %q", c.v, got, r.stdout.String())
		}
		// --json: the same exit code.
		r = newRig(func(ctl.Request) []ctl.Frame { return result(c.v) })
		if got := r.run(append(c.args, "--json")...); got != c.exit {
			t.Errorf("--json %+v: %d", c.v, got)
		}
	}
}

func TestRequestSize(t *testing.T) {
	// A 1 MiB file of quotes and one of <>& and Cyrillic stay within
	// MaxRequest: no HTML or ASCII escaping in requests.
	for _, content := range []string{strings.Repeat(`"`, ctl.MaxImport), strings.Repeat("<>&я", ctl.MaxImport/5)} {
		b, err := ctl.EncodeRequest(ctl.Request{V: 1, Cmd: "rules-import", Args: json.RawMessage(jsonOf(ctl.RulesImportArgs{Content: content}))})
		if err != nil || len(b) > ctl.MaxRequest {
			t.Fatal(len(b), err)
		}
	}
	r := newRig(func(ctl.Request) []ctl.Frame { return result(ctl.RulesImportView{}) })
	r.d.MaxRequest = 100
	r.d.Stdin = strings.NewReader(strings.Repeat("a.com -> vpn\n", 20))
	if got := r.run("rules", "import", "-"); got != 2 || !strings.Contains(r.stderr.String(), "Файл слишком большой для отправки в HyRoute") ||
		len(r.hy.dialed) != 0 {
		t.Fatal(got, r.stderr.String(), r.hy.dialed)
	}
}

func TestJSONOutputASCII(t *testing.T) {
	check := func(name string, out []byte, ok bool) {
		t.Helper()
		for _, c := range out {
			if c >= 0x80 {
				t.Fatalf("%s: non-ASCII output %s", name, out)
			}
		}
		for _, l := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
			var v map[string]any
			if err := json.Unmarshal(l, &v); err != nil {
				t.Fatalf("%s: %s: %v", name, l, err)
			}
		}
		last := bytes.TrimSpace(out)
		last = last[bytes.LastIndexByte(last, '\n')+1:]
		var v map[string]any
		json.Unmarshal(last, &v)
		if v["ok"] != ok {
			t.Fatalf("%s: %s", name, last)
		}
	}
	r := newRig(func(ctl.Request) []ctl.Frame {
		return result(ctl.StatusView{App: "v1", State: "connected", Main: &ctl.TargetView{Name: "🇩🇪 Германия"}})
	})
	r.run("status", "--json")
	check("status", r.stdout.Bytes(), true)
	if !bytes.HasPrefix(r.stdout.Bytes(), []byte(`{"ok":true,"result":{`)) {
		t.Fatal(r.stdout.String())
	}
	r = newRig(func(ctl.Request) []ctl.Frame { return failFrames("usage", "Сервер «Ы» не найден") })
	if r.run("server", "Ы", "--json") != 2 || r.stderr.Len() != 0 {
		t.Fatal(r.stderr.String())
	}
	check("failure", r.stdout.Bytes(), false)
	r = newRig(nil)
	r.run("status", "--bogus", "--json")
	check("usage", r.stdout.Bytes(), false)
	r = newRig(func(ctl.Request) []ctl.Frame {
		page, _ := json.Marshal([]logEntry{{Seq: 1, Level: "info", Msg: "подключено"}, {Seq: 2, Level: "warn", Msg: "ой"}})
		return append([]ctl.Frame{{V: 1, OK: true, Event: page}}, result(struct{}{})...)
	})
	r.run("logs", "--json")
	check("logs", r.stdout.Bytes(), true)
	if n := bytes.Count(r.stdout.Bytes(), []byte(`{"event":`)); n != 2 {
		t.Fatal(r.stdout.String())
	}
}

func TestPrivateFlag(t *testing.T) {
	for _, c := range []struct {
		args []string
		env  string
	}{{[]string{"status", "--private"}, ""}, {[]string{"status"}, "1"}} {
		r := newRig(func(ctl.Request) []ctl.Frame { return result(ctl.StatusView{}) })
		env := c.env
		r.d.Env = func(string) string { return env }
		r.run(c.args...)
		if len(r.hy.reqs) != 1 || !r.hy.reqs[0].Private {
			t.Fatalf("%v: %+v", c.args, r.hy.reqs)
		}
	}
}

func TestExportAndVersion(t *testing.T) {
	r := newRig(func(ctl.Request) []ctl.Frame {
		return result(ctl.RulesExportView{Format: "text", Content: "a.com -> vpn\n* -> напрямую\n", Rules: 1})
	})
	if r.run("rules", "export", "-o", "out.txt", "--private") != 0 || string(r.hy.written["out.txt"]) != "a.com -> vpn\r\n* -> напрямую\r\n" ||
		r.stderr.String() != "Сохранено в out.txt (1 правило).\nС --private домены и адреса скрыты: такой файл не подойдёт для импорта.\n" ||
		r.stdout.Len() != 0 {
		t.Fatalf("%q %q", r.hy.written["out.txt"], r.stderr.String())
	}
	r = newRig(nil)
	r.hy.dialErr = map[string]error{}
	if r.run("version") != 3 || r.stdout.String() != "hyroutectl v1.3.0\nHyRoute не запущен\n" {
		t.Fatal(r.stdout.String())
	}
	r = newRig(func(ctl.Request) []ctl.Frame { return result(ctl.VersionView{App: "v1.3.0", Core: "v2.6.2", Proto: 1}) })
	if r.run("version") != 0 || r.stdout.String() != "hyroutectl v1.3.0\nHyRoute v1.3.0\nHysteria v2.6.2\n" {
		t.Fatal(r.stdout.String())
	}
}

func TestStart(t *testing.T) {
	own := ctl.PipeName(self)
	// Running: nothing launched.
	r := newRig(nil)
	if r.run("start") != 0 || r.hy.started || r.stdout.String() != "HyRoute уже запущен.\n" {
		t.Fatal(r.stdout.String())
	}
	// Not running: launched, then waits for the pipe.
	r = newRig(nil)
	r.hy.dialErr = map[string]error{own: ctl.ErrNotRunning}
	r.d.Launch = func(io.Writer) error {
		r.hy.started = true
		go func() {
			time.Sleep(20 * time.Millisecond)
			r.hy.mu.Lock()
			r.hy.dialErr[own] = nil
			r.hy.mu.Unlock()
		}()
		return nil
	}
	r.d.Now = time.Now
	if r.run("start") != 0 || !r.hy.started || r.stdout.String() != "HyRoute запущен.\n" {
		t.Fatal(r.stdout.String())
	}
	// --no-wait: launched, one result object with --json.
	r = newRig(nil)
	r.hy.dialErr = map[string]error{own: ctl.ErrNotRunning}
	var res struct {
		OK     bool
		Result struct{ Message string }
	}
	if r.run("start", "--no-wait", "--json") != 0 || !r.hy.started || strings.Count(r.stdout.String(), "\n") != 1 ||
		json.Unmarshal(r.stdout.Bytes(), &res) != nil || !res.OK || res.Result.Message != "Запуск HyRoute начат." {
		t.Fatal(r.stdout.String())
	}
	// Launched but the command line is off in it.
	r = newRig(nil)
	r.hy.dialErr = map[string]error{}
	r.d.Launch = func(io.Writer) error { r.hy.run[ctl.RunEventName(self)] = ctl.RunSettled; return nil }
	if r.run("start") != 0 || r.stdout.String() != "HyRoute запущен (командная строка в нём выключена).\n" {
		t.Fatal(r.stdout.String())
	}
	// UAC declined.
	r = newRig(nil)
	r.hy.dialErr = map[string]error{}
	r.d.Launch = func(io.Writer) error {
		return errors.New("Запуск отменён: права администратора не выданы.")
	}
	if r.run("start") != 1 || r.stderr.String() != "Запуск отменён: права администратора не выданы.\n" {
		t.Fatal(r.stderr.String())
	}
}

func TestInterrupted(t *testing.T) {
	block := make(chan struct{})
	r := newRig(func(ctl.Request) []ctl.Frame { <-block; return nil })
	defer close(block)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if got := Run(ctx, []string{"connect"}, r.d); got != 130 || !strings.Contains(r.stderr.String(), "Прервано.") {
		t.Fatal(got, r.stderr.String())
	}
}
