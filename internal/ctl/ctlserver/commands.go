package ctlserver

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/netmode"
)

// command is one entry of the command table.
type command struct {
	args     func() any          // a new args value to decode into
	mutating func(args any) bool // nil = never; refused in read-only mode
	run      func(r *request, args any) (any, *ctl.Error)
	// detail: the handler logs the command itself, with its arguments.
	detail bool
}

func always(any) bool { return true }

func noArgs() any { return &struct{}{} }

// commands is the command table.
func commands() map[string]command {
	return map[string]command{
		"version":    {args: noArgs, run: cmdVersion},
		"status":     {args: noArgs, run: cmdStatus},
		"connect":    {args: func() any { return &ctl.WaitArgs{} }, mutating: always, run: cmdConnect},
		"reconnect":  {args: func() any { return &ctl.WaitArgs{} }, mutating: always, run: cmdReconnect},
		"disconnect": {args: noArgs, mutating: always, run: cmdDisconnect},
		"show":       {args: noArgs, run: cmdShow},
		"servers":    {args: noArgs, run: cmdServers},
		"groups":     {args: noArgs, run: cmdGroups},
		"server": {args: func() any { return &ctl.NameArgs{} },
			mutating: func(a any) bool { return strings.TrimSpace(a.(*ctl.NameArgs).Name) != "" }, run: cmdServer, detail: true},
		"check":        {args: func() any { return &ctl.NameArgs{} }, mutating: always, run: cmdCheck},
		"rulesets":     {args: noArgs, run: cmdRulesets},
		"ruleset":      {args: func() any { return &ctl.RulesetArgs{} }, mutating: always, run: cmdRuleset, detail: true},
		"explain":      {args: func() any { return &ctl.ExplainArgs{} }, run: cmdExplain},
		"rules-export": {args: func() any { return &ctl.RulesExportArgs{} }, run: cmdRulesExport},
		"rules-import": {args: func() any { return &ctl.RulesImportArgs{} },
			mutating: func(a any) bool { return !a.(*ctl.RulesImportArgs).DryRun }, run: cmdRulesImport, detail: true},
		"subs":        {args: noArgs, run: cmdSubs},
		"subs-update": {args: func() any { return &ctl.NameArgs{} }, mutating: always, run: cmdSubsUpdate, detail: true},
		"logs":        {args: func() any { return &ctl.LogsArgs{} }, run: cmdLogs},
		// netmodes
		"networks":       {args: noArgs, run: cmdNetworks},
		"networks-apply": {args: func() any { return &ctl.NetworksApplyArgs{} }, mutating: always, run: cmdNetworksApply, detail: true},
		"networks-set":   {args: func() any { return &ctl.NetworksSetArgs{} }, mutating: always, run: cmdNetworksSet, detail: true},
		// stats
		"stats": {args: func() any { return &ctl.StatsArgs{} }, run: cmdStats},
	}
}

func failed(format string, a ...any) *ctl.Error {
	return &ctl.Error{Code: ctl.CodeFailed, Message: fmt.Sprintf(format, a...)}
}

func usage(format string, a ...any) *ctl.Error {
	return &ctl.Error{Code: ctl.CodeUsage, Message: fmt.Sprintf(format, a...)}
}

// capital starts a Go-made message with a capital letter.
func capital(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}

func cmdVersion(r *request, _ any) (any, *ctl.Error) {
	a, core := r.s.api.Version()
	return ctl.VersionView{App: a, Core: core, Proto: ctl.Proto}, nil
}

func cmdStatus(r *request, _ any) (any, *ctl.Error) {
	return r.status(r.s.api.Status()), nil
}

// status is the status DTO; with --private the network rule's name is
// masked too (netmodes' NetState.Private: often the Wi-Fi name).
func (r *request) status(st app.Status) ctl.StatusView {
	if r.private && st.Net != nil {
		n := st.Net.Private()
		st.Net = &n
	}
	return statusView(st, r.s.appVersion())
}

// online: a session exists (also one whose engine failed): «Переподключить»
// on Home reconnects it.
func online(st app.Status) bool {
	return st.State != "disconnected" && st.State != "error" || st.State == "error" && st.Stats != nil
}

func cmdConnect(r *request, a any) (any, *ctl.Error) {
	w := a.(*ctl.WaitArgs)
	if w.Wait < 0 || w.Wait > 600 {
		return nil, usage("--wait: от 1 до 600 секунд")
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	already, err := r.s.api.ConnectOrResume()
	if err != nil {
		return nil, failed("Не подключено: %v", err)
	}
	return r.waitConnected(already, w.Wait), nil
}

func cmdReconnect(r *request, a any) (any, *ctl.Error) {
	w := a.(*ctl.WaitArgs)
	if w.Wait < 0 || w.Wait > 600 {
		return nil, usage("--wait: от 1 до 600 секунд")
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	var err error
	if online(r.s.api.Status()) {
		err = r.s.api.Reconnect()
	} else {
		_, err = r.s.api.ConnectOrResume()
	}
	if err != nil {
		return nil, failed("Не подключено: %v", err)
	}
	return r.waitConnected(false, w.Wait), nil
}

// waitConnected polls the status until connected, the session is gone
// (error without a session, disconnected) or wait seconds passed.
func (r *request) waitConnected(already bool, wait int) ctl.ConnectView {
	st := r.s.api.Status()
	v := ctl.ConnectView{Already: already}
	if wait > 0 {
		deadline := time.Now().Add(time.Duration(wait) * time.Second)
	poll:
		for st.State != "connected" && !(st.State == "error" && st.Stats == nil) && st.State != "disconnected" {
			if !time.Now().Before(deadline) {
				v.WaitedOut = true
				break
			}
			select {
			case <-r.ctx.Done():
				break poll
			case <-r.s.quit:
				break poll
			case <-time.After(r.s.T.Wait):
			}
			st = r.s.api.Status()
		}
	}
	v.Status = r.status(st)
	return v
}

func cmdDisconnect(r *request, _ any) (any, *ctl.Error) {
	before := r.s.api.Status()
	if e := r.live(); e != nil {
		return nil, e
	}
	// Called even when off: it also releases a leftover block, as the
	// button does.
	r.s.api.Disconnect()
	after := r.s.api.Status()
	return ctl.DisconnectView{
		Already:          before.State == "disconnected" && before.KillSwitch != "blocking",
		KillSwitchOpened: before.KillSwitch != "" && after.KillSwitch != "blocking",
		Status:           r.status(after),
	}, nil
}

func cmdShow(r *request, _ any) (any, *ctl.Error) {
	if err := r.s.api.ShowWindow(); err != nil {
		return nil, failed("Окно HyRoute ещё не готово, повторите через секунду")
	}
	return struct{}{}, nil
}

func cmdServers(r *request, _ any) (any, *ctl.Error) {
	return serverViews(r.s.api.Profiles(), r.s.api.Status()), nil
}

func cmdGroups(r *request, _ any) (any, *ctl.Error) {
	info := r.s.api.Groups()
	if info.LoadError != "" {
		return nil, failed("%s", info.LoadError)
	}
	return groupsView(info), nil
}

func targetKind(id string) string {
	if groups.IsGroupID(id) {
		return "group"
	}
	return "server"
}

func cmdServer(r *request, a any) (any, *ctl.Error) {
	name := strings.TrimSpace(a.(*ctl.NameArgs).Name)
	api := r.s.api
	if name == "" {
		st := api.Status()
		if st.MainID == "" {
			return ctl.TargetView{}, nil
		}
		return ctl.TargetView{Kind: targetKind(st.MainID), ID: st.MainID, Name: st.Main}, nil
	}
	id, err := api.ResolveTarget(name)
	if err != nil {
		return nil, usage("%s", capital(err.Error()))
	}
	if id == "" {
		return nil, usage("Укажите сервер или группу, а не «основной»")
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	if err := api.SetMain(id); err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	n := api.TargetName(id)
	api.Log().Info("command line: server", "target", n)
	return ctl.TargetView{Kind: targetKind(id), ID: id, Name: n}, nil
}

// resolveServer resolves a server (not a group, not the main target).
func (r *request) resolveServer(name, group string) (string, *ctl.Error) {
	if strings.TrimSpace(name) == "" {
		return "", usage("Укажите имя сервера: hyroutectl check ИМЯ")
	}
	id, err := r.s.api.ResolveTarget(name)
	switch {
	case err != nil:
		return "", usage("%s", capital(err.Error()))
	case id == "":
		return "", usage("Укажите сервер, а не «основной»")
	case groups.IsGroupID(id):
		return "", usage("%s", group)
	}
	return id, nil
}

func cmdCheck(r *request, a any) (any, *ctl.Error) {
	id, e := r.resolveServer(a.(*ctl.NameArgs).Name, "Проверить можно сервер, а не группу")
	if e != nil {
		return nil, e
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	res, err := r.s.api.CheckProfile(id)
	if err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	return checkView(res), nil
}

func cmdRulesets(r *request, _ any) (any, *ctl.Error) {
	v := r.s.api.Rulesets()
	if v.Error != "" {
		return nil, failed("%s", capital(v.Error))
	}
	return rulesetsView(v), nil
}

func cmdRuleset(r *request, a any) (any, *ctl.Error) {
	args := a.(*ctl.RulesetArgs)
	api := r.s.api
	if strings.TrimSpace(args.Name) == "" {
		return nil, usage("Укажите профиль правил: hyroutectl ruleset ИМЯ")
	}
	id, err := api.ResolveRuleset(args.Name)
	if err != nil {
		return nil, usage("%s", capital(err.Error()))
	}
	v := api.Rulesets()
	if id == "" || id == v.Active {
		st := api.Status()
		return ctl.RulesetSwitchView{Already: true, Ruleset: ctl.RulesetBrief{ID: st.Ruleset.ID, Name: st.Ruleset.Name, Count: st.Ruleset.Count},
			Warnings: []string{}}, nil
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	res, err := api.SwitchRuleset(id, app.SourceCLI, app.SwitchOptions{Reconnect: args.Reconnect})
	if err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	api.Log().Info("command line: ruleset", "name", res.Ruleset.Name, "reconnect", args.Reconnect)
	out := ctl.RulesetSwitchView{Ruleset: ctl.RulesetBrief{ID: res.Ruleset.ID, Name: res.Ruleset.Name, Count: res.Ruleset.Count},
		Note: res.Note, Warnings: []string{}, Connected: res.Connected, Reconnected: res.Reconnected, ReconnectError: res.ReconnectError}
	for _, w := range res.Warnings {
		out.Warnings = append(out.Warnings, w.Text)
	}
	return out, nil
}

func cmdExplain(r *request, a any) (any, *ctl.Error) {
	args := a.(*ctl.ExplainArgs)
	if strings.TrimSpace(args.Target) == "" {
		return nil, usage("Укажите сайт или IP: hyroutectl explain github.com")
	}
	if args.Port < 0 || args.Port > 65535 {
		return nil, usage("Порт — число от 1 до 65535")
	}
	proto := "tcp"
	if args.UDP {
		proto = "udp"
	}
	// The explanation as the window gets it, the DNS line's server named.
	ex := r.s.api.Explain(app.ExplainQuery{App: args.App, Target: strings.TrimSpace(args.Target), Proto: proto, Port: args.Port})
	return explainView(ex, r.s.api.TargetName), nil
}

// rulesCount is the number of rules of a rules JSON export.
func rulesCount(b []byte) int {
	var env struct {
		Rules []json.RawMessage `json:"rules"`
	}
	json.Unmarshal(b, &env)
	return len(env.Rules)
}

func cmdRulesExport(r *request, a any) (any, *ctl.Error) {
	format := a.(*ctl.RulesExportArgs).Format
	switch format {
	case "json":
		b, err := r.s.api.RulesJSON()
		if err != nil {
			return nil, failed("%s", capital(err.Error()))
		}
		return ctl.RulesExportView{Format: "json", Content: string(b), Rules: rulesCount(b)}, nil
	case "", "text":
		// The count is only for «Сохранено … (N правил)»: a JSON failure
		// does not fail the text.
		v := ctl.RulesExportView{Format: "text", Content: r.s.api.RulesText()}
		if b, err := r.s.api.RulesJSON(); err == nil {
			v.Rules = rulesCount(b)
		}
		return v, nil
	}
	return nil, usage("--format: text или json")
}

// isJSON: the content is (to be read as) rules JSON.
func isJSON(content, format string) bool {
	return format == "json" || format != "text" && strings.HasPrefix(strings.TrimLeft(content, " \t\r\n"), "{")
}

func cmdRulesImport(r *request, a any) (any, *ctl.Error) {
	args := a.(*ctl.RulesImportArgs)
	if len(args.Content) > ctl.MaxImport {
		return nil, usage("Файл больше 1 МБ")
	}
	format := args.Format
	switch format {
	case "":
		format = "auto"
	case "auto", "text", "json":
	default:
		return nil, usage("--format: text или json")
	}
	api := r.s.api
	res := api.ParseRulesTextAs(args.Content, format, args.Replace)
	if e := rulesErrors(res); e != nil {
		return nil, e
	}
	if res.HasDefault && !args.Replace {
		return nil, &ctl.Error{Code: ctl.CodeRules, Message: "Строка «* -> …» меняет «Всё остальное», а без --replace правила только добавляются: уберите её или добавьте --replace"}
	}
	v := ctl.RulesImportView{Summary: res.Summary, Rules: len(res.Rules), Warnings: lines(res.Warnings), Replace: args.Replace,
		JSON: isJSON(args.Content, format)}
	if args.DryRun {
		return v, nil
	}
	if e := r.live(); e != nil {
		return nil, e
	}
	_, res, err := api.ApplyRulesTextAs(args.Content, format, args.Replace)
	if e := rulesErrors(res); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	api.Log().Info("command line: rules import", "rules", len(res.Rules), "replace", args.Replace)
	v.Saved, v.Summary, v.Rules, v.Warnings = true, res.Summary, len(res.Rules), lines(res.Warnings)
	v.Skipped, v.Enabled = res.Skipped, res.Enabled
	return v, nil
}

func rulesErrors(res app.RulesTextResult) *ctl.Error {
	if len(res.Errors) == 0 {
		return nil
	}
	return &ctl.Error{Code: ctl.CodeRules, Message: "В файле ошибки, ничего не сохранено", Lines: lines(res.Errors)}
}

func lines(ls []app.RuleLine) []ctl.ErrorLine {
	out := make([]ctl.ErrorLine, len(ls))
	for i, l := range ls {
		out[i] = ctl.ErrorLine{Line: l.Line, Text: l.Text}
	}
	return out
}

func cmdSubs(r *request, _ any) (any, *ctl.Error) {
	return subLines(r.s.api.Subscriptions()), nil
}

func cmdSubsUpdate(r *request, a any) (any, *ctl.Error) {
	name := strings.TrimSpace(a.(*ctl.NameArgs).Name)
	api := r.s.api
	subs := api.Subscriptions()
	var ids []string
	if name != "" {
		id, err := api.ResolveSubscription(name)
		if err != nil {
			return nil, usage("%s", capital(err.Error()))
		}
		ids = []string{id}
	} else {
		for _, s := range subs {
			if s.Enabled {
				ids = append(ids, s.ID)
			}
		}
	}
	nameOf := map[string]string{}
	for _, s := range subs {
		nameOf[s.ID] = s.Name
	}
	out := []ctl.SubUpdateView{}
	for i, id := range ids {
		if e := r.live(); e != nil {
			if i == 0 {
				return nil, e
			}
			// Remaining ones are reported, not sent: the client is gone.
			break
		}
		api.Log().Info("command line: subscription update", "name", nameOf[id])
		ms, err := api.UpdateSubscription(id)
		v := ctl.SubUpdateView{Name: nameOf[id], OK: err == nil, Added: ms.Added, Updated: ms.Updated, Removed: ms.Removed, MissingKept: ms.MissingKept}
		if err != nil {
			v.Error = err.Error()
		}
		out = append(out, v)
	}
	return out, nil
}

// logsPage is the most entries one event frame carries.
const logsPage = 500

func cmdLogs(r *request, a any) (any, *ctl.Error) {
	args := a.(*ctl.LogsArgs)
	api := r.s.api
	kind := strings.TrimSpace(args.Kind)
	switch kind {
	case "", "engine":
		kind = "engine"
	case "hysteria":
	default:
		// Only a resolved server ID: a journal is never made for an ID
		// from the client.
		id, e := r.resolveServer(kind, "Журнал есть у сервера, а не у группы")
		if e != nil {
			return nil, e
		}
		kind = "hysteria:" + id
	}
	n := args.Lines
	if n == 0 {
		n = 50
	}
	if n < 1 || n > 10000 {
		return nil, usage("-n: от 1 до 10000")
	}
	es := api.LogsTail(kind, n)
	if err := r.pages(es); err != nil {
		return nil, errGone
	}
	if !args.Follow {
		return struct{}{}, nil
	}
	var last uint64
	if len(es) > 0 {
		last = es[len(es)-1].Seq
	}
	for {
		select {
		case <-r.ctx.Done():
			return nil, errGone
		case <-r.s.quit:
			return struct{}{}, nil
		case <-time.After(r.s.T.Poll):
		}
		es := api.Logs(kind, last)
		if len(es) == 0 {
			continue
		}
		if last > 0 && es[0].Seq > last+1 {
			gap := logx.Entry{Time: time.Now(), Level: "warn", Msg: fmt.Sprintf("… пропущено %d строк журнала", es[0].Seq-last-1)}
			es = append([]logx.Entry{gap}, es...)
		}
		last = es[len(es)-1].Seq
		if err := r.pages(es); err != nil {
			return nil, errGone
		}
	}
}

// pages sends entries as event frames of at most logsPage entries.
func (r *request) pages(es []logx.Entry) error {
	for len(es) > 0 {
		n := min(len(es), logsPage)
		if err := r.emit(es[:n]); err != nil {
			return err
		}
		es = es[n:]
	}
	return nil
}

// ---- netmodes ----

// netView is what the networks commands return: the page's view, with
// --private the network and Wi-Fi names and the rule names masked
// (NetModesView.Private; the hosts and IPs then by the usual masking).
func (r *request) netView(v app.NetModesView) app.NetModesView {
	if r.private {
		return v.Private()
	}
	return v
}

func cmdNetworks(r *request, _ any) (any, *ctl.Error) {
	return r.netView(r.s.api.NetModes(true)), nil
}

// cmdNetworksApply is «Применить сейчас». A rule that disconnects (routing
// off, the kill switch block released) runs only with --yes, as the window
// asks first: the rule to confirm comes from the fresh read ApplyNetModes
// takes, and a second read that finds another disconnecting rule asks again.
func cmdNetworksApply(r *request, a any) (any, *ctl.Error) {
	yes := a.(*ctl.NetworksApplyArgs).Yes
	api := r.s.api
	if e := r.live(); e != nil {
		return nil, e
	}
	api.Log().Info("command line: networks apply", "yes", yes)
	v, err := api.ApplyNetModes("")
	if err == nil && v.Confirm && yes && v.Match != nil {
		v, err = api.ApplyNetModes(app.NetRuleKey(v.Match.RuleID, v.Match.Unknown))
	}
	if err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	if v.Confirm {
		name := netmode.UnknownName
		if v.Match != nil && !v.Match.Unknown {
			name = v.Match.Name
			if r.private {
				name = "***"
			}
		}
		if yes {
			return nil, failed("Сеть сменилась, пока правило применялось: правило «%s» отключит HyRoute. Повторите hyroutectl networks apply --yes", name)
		}
		return nil, failed("Правило «%s» отключит HyRoute: весь трафик пойдёт напрямую, kill switch снимет блокировку. Применить: hyroutectl networks apply --yes", name)
	}
	return r.netView(v), nil
}

// cmdNetworksSet is «Действовать по сети»: only the flag, never an action
// (enabling takes the current network as the baseline).
func cmdNetworksSet(r *request, a any) (any, *ctl.Error) {
	on := a.(*ctl.NetworksSetArgs).Enabled
	if e := r.live(); e != nil {
		return nil, e
	}
	r.s.api.Log().Info("command line: networks", "enabled", on)
	v, err := r.s.api.SetNetModesEnabled(on)
	if err != nil {
		return nil, failed("%s", capital(err.Error()))
	}
	return r.netView(v), nil
}

// ---- stats ----

func cmdStats(r *request, a any) (any, *ctl.Error) {
	p := a.(*ctl.StatsArgs).Period
	if p == "" {
		p = "today"
	}
	rep, err := r.s.api.Stats(p)
	if err != nil {
		// The only error: a period the client did not check (a future month).
		return nil, usage("Период: today, yesterday, 7d, 30d или ГГГГ-ММ не позже текущего месяца")
	}
	return rep, nil
}
