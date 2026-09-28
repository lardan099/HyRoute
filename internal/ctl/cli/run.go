package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/ctl"
)

// Deps is what Run needs from the system; cmd/hyroutectl passes the real
// ones, tests fakes.
type Deps struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Env            func(string) string
	SelfSID        string // the user running hyroutectl
	Admin          bool   // an elevated administrator
	Version        string // hyroutectl's own

	// Dial connects to a pipe (owner-checked); errors wrap ctl.ErrNotRunning,
	// ctl.ErrBusy, ctl.ErrDenied or ctl.ErrImpostor.
	Dial      func(name string, busy time.Duration) (net.Conn, uint32, error)
	Probe     func(event string) (ctl.RunState, error)
	FindPipes func() ([]string, error)
	ReadFile  func(path string) ([]byte, error)
	WriteFile func(path string, b []byte) error
	// Launch starts HyRoute (start): the autostart task, else HyRoute.exe
	// next to hyroutectl with a UAC prompt. It prints what it does.
	Launch func(stderr io.Writer) error
	// AllowForeground lets HyRoute bring its window up (show).
	AllowForeground func(pid uint32)

	Now        func() time.Time
	Poll       time.Duration // waiting for a starting HyRoute (500 ms)
	MaxRequest int           // tests lower it; 0 = ctl.MaxRequest
}

type client struct {
	d   *Deps
	inv *Invocation
}

func (c *client) timeout(def time.Duration) time.Duration {
	if c.inv.Timeout > 0 {
		return c.inv.Timeout
	}
	return def
}

// Run runs hyroutectl with argv (after the program name) and returns the
// exit code. Cancelling ctx is Ctrl+C.
func Run(ctx context.Context, argv []string, d *Deps) int {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Poll == 0 {
		d.Poll = 500 * time.Millisecond
	}
	// Human output never passes control characters to the console
	// (clean.go); --json is 7-bit with every control escaped.
	dd := *d
	d = &dd
	d.Stderr = cleanWriter{d.Stderr}
	env := ""
	if d.Env != nil {
		env = d.Env("HYROUTE_PRIVATE")
	}
	inv, err := Parse(argv, env)
	if err != nil {
		jsonOut := false
		for _, a := range argv {
			jsonOut = jsonOut || a == "--json"
		}
		c := &client{d: d, inv: &Invocation{JSON: jsonOut}}
		f := fail(ctl.CodeUsage, "%s", err.Error())
		f.local = true
		return c.report(f)
	}
	if !inv.JSON {
		d.Stdout = cleanWriter{d.Stdout}
	}
	if inv.Help != "" {
		fmt.Fprint(d.Stdout, inv.Help)
		return 0
	}
	c := &client{d: d, inv: inv}
	if inv.Name == "start" {
		return c.start(ctx)
	}
	return c.command(ctx)
}

// report prints a failure and returns its exit code.
func (c *client) report(f *failure) int {
	if f.code == ctl.CodeInterrupted {
		if c.inv.Follow {
			return 0
		}
		if !c.inv.JSON {
			fmt.Fprintln(c.d.Stderr, "Прервано. Команда, уже отправленная HyRoute, может выполниться до конца.")
		}
		return f.exit()
	}
	if c.inv.JSON {
		out := map[string]any{"ok": false, "code": f.code, "message": f.msg, "exit": f.exit()}
		if len(f.lines) > 0 {
			out["lines"] = f.lines
		}
		c.printJSON(out)
		return f.exit()
	}
	msg := f.msg
	if f.local {
		msg = strings.TrimSuffix(msg, ".") + ". Справка: hyroutectl --help"
	}
	var b strings.Builder
	if f.code == ctl.CodeRules && len(f.lines) > 0 {
		b.WriteString(strings.TrimSuffix(msg, ".") + ":\n")
		for _, l := range f.lines {
			b.WriteString(lineLabel(l, c.isJSONInput()) + "\n")
		}
	} else {
		b.WriteString(msg + "\n")
	}
	fmt.Fprint(c.d.Stderr, b.String())
	return f.exit()
}

func (c *client) printJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"code":"failed","message":"json","exit":1}`)
	}
	c.d.Stdout.Write(append(ctl.ASCIIJSON(b), '\n'))
}

// content is the rules file of rules import, read by hyroutectl itself.
func (c *client) content() (string, *failure) {
	var b []byte
	var err error
	if c.inv.File == "-" {
		b, err = readLimited(c.d.Stdin)
	} else {
		b, err = c.d.ReadFile(c.inv.File)
	}
	if err != nil {
		return "", fail(ctl.CodeUsage, "Не удалось прочитать %s: %v", c.inv.File, err)
	}
	s, err := DecodeInput(b)
	if err != nil {
		return "", fail(ctl.CodeUsage, "%s", err.Error())
	}
	return s, nil
}

func (c *client) isJSONInput() bool {
	a, ok := c.inv.Args.(ctl.RulesImportArgs)
	if !ok {
		return false
	}
	return a.Format == "json" || a.Format != "text" && strings.HasPrefix(strings.TrimLeft(a.Content, " \t\r\n"), "{")
}

// command runs a request against HyRoute and prints the outcome.
func (c *client) command(ctx context.Context) int {
	inv := c.inv
	if inv.Wire == "rules-import" {
		s, f := c.content()
		if f != nil {
			return c.report(f)
		}
		a := inv.Args.(ctl.RulesImportArgs)
		a.Content = s
		inv.Args = a
	}
	var entries []logEntry
	onEvent := func(raw json.RawMessage) error {
		var page []logEntry
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		if inv.JSON {
			for _, e := range page {
				c.printJSON(map[string]any{"event": e})
			}
			return nil
		}
		var b strings.Builder
		for _, e := range page {
			formatLog(&b, e)
		}
		fmt.Fprint(c.d.Stdout, b.String())
		entries = append(entries, page...)
		return nil
	}
	res, f := c.exchange(ctx, onEvent)
	if inv.Wire == "version" {
		return c.version(res, f)
	}
	if f != nil {
		return c.report(f)
	}
	return c.output(res)
}

// version prints hyroutectl's version even when HyRoute is not there.
func (c *client) version(res json.RawMessage, f *failure) int {
	var v ctl.VersionView
	if f == nil {
		json.Unmarshal(res, &v)
	}
	if c.inv.JSON {
		if f != nil {
			return c.report(f)
		}
		c.printJSON(map[string]any{"ok": true, "result": map[string]any{"ctl": c.d.Version, "app": v.App, "core": v.Core, "proto": v.Proto}})
		return 0
	}
	fmt.Fprintln(c.d.Stdout, "hyroutectl "+c.d.Version)
	if f != nil {
		if f.code == ctl.CodeNotRunning {
			fmt.Fprintln(c.d.Stdout, "HyRoute не запущен")
			return f.exit()
		}
		return c.report(f)
	}
	fmt.Fprintln(c.d.Stdout, "HyRoute "+v.App)
	if v.Core != "" {
		fmt.Fprintln(c.d.Stdout, "Hysteria "+v.Core)
	}
	return 0
}

// exchange connects, checks hello, sends the request and reads events
// until the final frame.
func (c *client) exchange(ctx context.Context, onEvent func(json.RawMessage) error) (json.RawMessage, *failure) {
	inv := c.inv
	args, err := ctl.Marshal(inv.Args)
	if err != nil {
		return nil, fail(ctl.CodeFailed, "%v", err)
	}
	body, err := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: inv.Wire, Args: args, Private: inv.Private})
	if err != nil {
		return nil, fail(ctl.CodeFailed, "%v", err)
	}
	max := c.d.MaxRequest
	if max == 0 {
		max = ctl.MaxRequest
	}
	if len(body) > max {
		return nil, fail(ctl.CodeTooBig, "Файл слишком большой для отправки в HyRoute")
	}
	conn, pid, f := c.connect(ctx)
	if f != nil {
		return nil, f
	}
	defer conn.Close()
	// Ctrl+C closes the connection: every read and write returns.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	limit := c.timeout(inv.timeoutDefault())
	if limit > 0 {
		conn.SetDeadline(time.Now().Add(limit))
	} else {
		// logs --follow: only the hello has to come in time.
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	readFail := func(err error) *failure {
		switch {
		case ctx.Err() != nil:
			return fail(ctl.CodeInterrupted, "")
		case errors.Is(err, os.ErrDeadlineExceeded):
			return fail(ctl.CodeTimeout, "HyRoute не ответил за %d с.", int(max64(limit, 30*time.Second)/time.Second))
		}
		return fail(ctl.CodeDropped, msgDropped)
	}
	fr, err := readFrame(conn)
	if err != nil {
		return nil, readFail(err)
	}
	if fr.Error != nil {
		return nil, serverFailure(fr.Error, inv)
	}
	h := fr.Hello
	if h == nil {
		return nil, fail(ctl.CodeDropped, msgDropped)
	}
	minProto := h.MinProto
	if minProto == 0 {
		minProto = h.Proto
	}
	switch {
	case ctl.Proto > h.Proto:
		return nil, fail(ctl.CodeProtoNew, "hyroutectl новее HyRoute (протокол %d и %d): обновите HyRoute.", ctl.Proto, h.Proto)
	case ctl.Proto < minProto:
		return nil, fail(ctl.CodeProtoOld, "hyroutectl старее HyRoute (протокол %d и %d): возьмите hyroutectl.exe из папки HyRoute.", ctl.Proto, minProto)
	}
	if inv.Wire == "show" && c.d.AllowForeground != nil {
		c.d.AllowForeground(pid)
	}
	if err := ctl.WriteFrame(conn, body, max); err != nil {
		// A server that refused the size answers before closing.
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if fr, err := readFrame(conn); err == nil && fr.Error != nil {
			return nil, serverFailure(fr.Error, inv)
		}
		return nil, readFail(err)
	}
	if limit == 0 {
		conn.SetDeadline(time.Time{})
	}
	for {
		fr, err := readFrame(conn)
		if err != nil {
			return nil, readFail(err)
		}
		if len(fr.Event) > 0 && !fr.Final {
			if err := onEvent(fr.Event); err != nil {
				return nil, fail(ctl.CodeFailed, "%v", err)
			}
			continue
		}
		if !fr.Final {
			continue
		}
		if fr.Error != nil {
			return nil, serverFailure(fr.Error, inv)
		}
		return fr.Result, nil
	}
}

func max64(a, b time.Duration) time.Duration {
	if a > 0 {
		return a
	}
	return b
}

func readFrame(conn net.Conn) (*ctl.Frame, error) {
	b, err := ctl.ReadFrame(conn, ctl.MaxResponse)
	if err != nil {
		return nil, err
	}
	var f ctl.Frame
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return &f, nil
}

// serverFailure turns HyRoute's error into the client's wording.
func serverFailure(e *ctl.Error, inv *Invocation) *failure {
	switch e.Code {
	case ctl.CodeUnknown:
		return fail(e.Code, "Эта версия HyRoute не поддерживает команду «%s»: обновите HyRoute.", inv.Name)
	case ctl.CodeUnknownArg:
		flag := flagOfField[e.Field]
		if flag == "" {
			flag = e.Field
		}
		return fail(e.Code, "Эта версия HyRoute не знает параметр %s команды «%s»: обновите HyRoute или уберите параметр.", flag, inv.Name)
	case ctl.CodeOff:
		return fail(e.Code, msgOff)
	}
	return &failure{code: e.Code, msg: e.Message, lines: e.Lines}
}

// output prints a successful result and returns the exit code.
func (c *client) output(res json.RawMessage) int {
	inv := c.inv
	d := c.d
	if inv.Wire == "rules-export" {
		return c.export(res)
	}
	if inv.JSON {
		if inv.Wire == "logs" {
			res = json.RawMessage("{}")
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(res))
		dec.UseNumber()
		dec.Decode(&v)
		c.printJSON(map[string]any{"ok": true, "result": v})
		return c.exitOf(res)
	}
	var b strings.Builder
	now := d.Now()
	code := 0
	switch inv.Wire {
	case "status":
		var st ctl.StatusView
		json.Unmarshal(res, &st)
		formatStatus(&b, st, now)
	case "connect", "reconnect":
		var v ctl.ConnectView
		json.Unmarshal(res, &v)
		line, ex := connectLine(v, inv.Wire == "reconnect", inv.Wait)
		code = ex
		b.WriteString(line + "\n")
		formatStatus(&b, v.Status, now)
	case "disconnect":
		var v ctl.DisconnectView
		json.Unmarshal(res, &v)
		if v.Already {
			b.WriteString("Уже отключено.\n")
		} else {
			b.WriteString("Отключено.\n")
		}
		if v.KillSwitchOpened {
			b.WriteString("Kill switch: интернет открыт.\n")
		}
	case "show":
		b.WriteString("Окно HyRoute открыто.\n")
	case "servers":
		var v []ctl.ServerView
		json.Unmarshal(res, &v)
		formatServers(&b, v)
	case "groups":
		var v ctl.GroupsView
		json.Unmarshal(res, &v)
		formatGroups(&b, v)
	case "server":
		var v ctl.TargetView
		json.Unmarshal(res, &v)
		name := inv.Args.(ctl.NameArgs).Name
		switch {
		case name == "" && v.ID == "":
			b.WriteString("Основной: не выбран\n")
		case name == "" && v.Kind == "group":
			b.WriteString("Основной: группа «" + v.Name + "»\n")
		case name == "":
			b.WriteString("Основной: " + v.Name + "\n")
		case v.Kind == "group":
			b.WriteString("Основная группа: " + v.Name + ". Новые соединения пойдут через неё, открытые остаются на прежнем.\n")
		default:
			b.WriteString("Основной сервер: " + v.Name + ". Новые соединения пойдут через него, открытые остаются на прежнем.\n")
		}
	case "check":
		var v ctl.CheckView
		json.Unmarshal(res, &v)
		formatCheck(&b, v)
	case "rulesets":
		var v ctl.RulesetsView
		json.Unmarshal(res, &v)
		formatRulesets(&b, v)
	case "ruleset":
		var v ctl.RulesetSwitchView
		json.Unmarshal(res, &v)
		switch {
		case v.Already:
			b.WriteString("Профиль правил «" + v.Ruleset.Name + "» уже включён.\n")
		default:
			b.WriteString("Профиль правил: " + v.Ruleset.Name + ".\n")
			if v.Note != "" {
				b.WriteString(v.Note + "\n")
			}
			rc := inv.Args.(ctl.RulesetArgs).Reconnect
			switch {
			case rc && v.ReconnectError != "":
				b.WriteString("Не переподключено: " + v.ReconnectError + "\n")
			case rc && v.Reconnected:
				b.WriteString("Переподключено.\n")
			case !rc && v.Connected:
				b.WriteString("Открытые соединения идут по-прежнему: hyroutectl reconnect — переподключить.\n")
			}
		}
	case "explain":
		var v ExplanationLite
		json.Unmarshal(res, &v)
		formatExplain(&b, v, inv)
	case "rules-import":
		var v ctl.RulesImportView
		json.Unmarshal(res, &v)
		formatImport(&b, v, inv.Args.(ctl.RulesImportArgs).DryRun)
	case "subs":
		var v []ctl.SubLine
		json.Unmarshal(res, &v)
		formatSubs(&b, v)
	case "subs-update":
		var v []ctl.SubUpdateView
		json.Unmarshal(res, &v)
		formatSubUpdates(&b, v)
	case "logs":
		if inv.Follow {
			fmt.Fprintln(d.Stderr, "HyRoute закрылся.")
		}
	case "networks", "networks-apply", "networks-set":
		var v NetModesLite
		json.Unmarshal(res, &v)
		switch inv.Wire {
		case "networks":
			formatNetworks(&b, v)
		case "networks-apply":
			formatNetworksApply(&b, v)
		default:
			formatNetworksSet(&b, v)
		}
	case "stats":
		var v ReportLite
		json.Unmarshal(res, &v)
		formatStats(&b, v)
	default:
		// A command without a formatter: its result as it came.
		b.Write(res)
		b.WriteString("\n")
	}
	fmt.Fprint(d.Stdout, b.String())
	if code != 0 {
		return code
	}
	return c.exitOf(res)
}

// exitOf is the exit code of a successful exchange whose result says the
// command did not work (the same with and without --json).
func (c *client) exitOf(res json.RawMessage) int {
	switch c.inv.Wire {
	case "connect", "reconnect":
		var v ctl.ConnectView
		json.Unmarshal(res, &v)
		_, code := connectLine(v, c.inv.Wire == "reconnect", c.inv.Wait)
		return code
	case "check":
		var v ctl.CheckView
		json.Unmarshal(res, &v)
		if !v.OK {
			return 1
		}
	case "subs-update":
		var v []ctl.SubUpdateView
		json.Unmarshal(res, &v)
		for _, u := range v {
			if !u.OK {
				return 1
			}
		}
	case "ruleset":
		var v ctl.RulesetSwitchView
		json.Unmarshal(res, &v)
		if v.ReconnectError != "" {
			return 1
		}
	case "networks-apply":
		// The rule's action failed (e.g. the connect).
		var v NetModesLite
		json.Unmarshal(res, &v)
		if v.State.Error != "" {
			return 1
		}
	}
	return 0
}

// export prints or saves the rules.
func (c *client) export(res json.RawMessage) int {
	var v ctl.RulesExportView
	json.Unmarshal(res, &v)
	inv, d := c.inv, c.d
	content := v.Content
	if v.Format == "text" {
		content = strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\n", "\r\n")
	}
	if inv.Out == "" {
		if inv.JSON {
			c.printJSON(map[string]any{"ok": true, "result": v})
		} else {
			fmt.Fprint(d.Stdout, content)
		}
	} else {
		if err := d.WriteFile(inv.Out, []byte(content)); err != nil {
			return c.report(fail(ctl.CodeFailed, "Не удалось записать %s: %v", inv.Out, err))
		}
		if inv.JSON {
			c.printJSON(map[string]any{"ok": true, "result": map[string]any{"format": v.Format, "rules": v.Rules, "path": inv.Out}})
		} else {
			fmt.Fprintf(d.Stderr, "Сохранено в %s (%d %s).\n", inv.Out, v.Rules, plural(v.Rules, "правило", "правила", "правил"))
		}
	}
	if inv.Private && !inv.JSON {
		fmt.Fprintln(d.Stderr, "С --private домены и адреса скрыты: такой файл не подойдёт для импорта.")
	}
	return 0
}

// start starts HyRoute unless it runs (cli.md §1.6).
func (c *client) start(ctx context.Context) int {
	d := c.d
	say := func(s string) {
		if c.inv.JSON {
			c.printJSON(map[string]any{"ok": true, "result": map[string]any{"message": s}})
		} else {
			fmt.Fprintln(d.Stdout, s)
		}
	}
	running := func() (up, settled bool) {
		if c.ping(ctx) {
			return true, true
		}
		st, _ := d.Probe(ctl.RunEventName(d.SelfSID))
		return st == ctl.RunStarting || st == ctl.RunSettled, st == ctl.RunSettled
	}
	up, settled := running()
	if !up {
		if err := d.Launch(d.Stderr); err != nil {
			return c.report(fail(ctl.CodeFailed, "%s", err.Error()))
		}
	} else if settled || c.inv.NoWait {
		say("HyRoute уже запущен.")
		return 0
	}
	if c.inv.NoWait {
		return 0
	}
	limit := c.timeout(60 * time.Second)
	deadline := time.Now().Add(limit)
	for {
		if c.ping(ctx) {
			say("HyRoute запущен.")
			return 0
		}
		if st, _ := d.Probe(ctl.RunEventName(d.SelfSID)); st == ctl.RunSettled {
			say("HyRoute запущен (командная строка в нём выключена).")
			return 0
		}
		if !time.Now().Before(deadline) {
			return c.report(fail(ctl.CodeStarting, "HyRoute не ответил за %d с после запуска.", int(limit/time.Second)))
		}
		select {
		case <-ctx.Done():
			return c.report(fail(ctl.CodeInterrupted, ""))
		case <-time.After(d.Poll):
		}
	}
}

// ping: the own pipe is there and owned by an administrator (the server
// answers the connection with hello and drops it when nothing follows).
func (c *client) ping(ctx context.Context) bool {
	conn, _, err := c.d.Dial(ctl.PipeName(c.d.SelfSID), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
