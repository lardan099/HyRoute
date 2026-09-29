package ctlserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/cli"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/stats"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Secrets planted in the fake HyRoute: no response may carry them.
const (
	secretPass  = "PASSWORD-planted-7"
	secretObfs  = "OBFS-planted-7"
	secretPin   = "PIN-planted-7"
	secretSub   = "https://panel.example/sub/TOKEN-planted-7"
	secretProxy = "PROXYPASS-planted-7"
	secretDNS   = "https://dns.example/QUERY-planted-7"
	secretProbe = "https://probe.example/PROBE-planted-7"
)

type fakeAPI struct {
	mu        sync.Mutex
	mode      string
	status    app.Status
	statusSeq []app.Status // consumed by Status() one by one, the last repeats
	calls     []string
	journal   *logx.Journal
	panicCmd  bool
	blockStat chan struct{}
	netOn     bool // «Действовать по сети»
}

func newFake() *fakeAPI {
	f := &fakeAPI{mode: "full", journal: logx.NewJournal(10000)}
	f.status = app.Status{State: "connected", Main: "DE", MainID: "a1b2c3d4e5f6", KillSwitch: "armed",
		Tunnels:  []tunnels.Status{{ID: "a1b2c3d4e5f6", Name: "DE", State: "connected", SOCKS: "127.0.0.1:1080", ServerIPs: []string{"203.0.113.9"}, Sent: 10, Recv: 20}},
		Warnings: []app.RuleWarning{{Text: "правило «X»: сервер удалён"}}, Stats: &session.Stats{Passed: 5},
		MainGroup: &app.GroupBrief{ID: "grp-1", Name: "Auto"}, Ruleset: app.RulesetRef{ID: "r1", Name: "Дом", Count: 2},
		SubAlerts: []app.SubAlert{{ID: "s", Name: "Панель", Level: "low", Text: "мало"}},
		Net:       &app.NetState{Rule: "HomeWiFi", RuleID: "n1", Text: "Сеть сменилась: правило «HomeWiFi»", Override: true},
		DNS:       &app.DNSStatus{ByRules: true, Health: []app.DNSHealth{{Via: "tunnel", Profile: "a1b2c3d4e5f6", Upstream: "Cloudflare", Kind: "timeout"}}}}
	return f
}

func (f *fakeAPI) call(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeAPI) called(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == s {
			return true
		}
	}
	return false
}

func (f *fakeAPI) Version() (string, string) { return "v1.3.0", "v2.6.2" }
func (f *fakeAPI) Status() app.Status {
	if f.blockStat != nil {
		<-f.blockStat
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statusSeq) > 0 {
		st := f.statusSeq[0]
		if len(f.statusSeq) > 1 {
			f.statusSeq = f.statusSeq[1:]
		}
		return st
	}
	return f.status
}
func (f *fakeAPI) ConnectOrResume() (bool, error) { f.call("ConnectOrResume"); return false, nil }
func (f *fakeAPI) Reconnect() error               { f.call("Reconnect"); return nil }
func (f *fakeAPI) Disconnect() {
	f.call("Disconnect")
	f.mu.Lock()
	f.status.State, f.status.KillSwitch = "disconnected", ""
	f.mu.Unlock()
}
func (f *fakeAPI) ShowWindow() error { f.call("ShowWindow"); return nil }
func (f *fakeAPI) Profiles() []app.ProfileSummary {
	return []app.ProfileSummary{{ID: "a1b2c3d4e5f6", Name: "DE", Server: "de.example.com:443", Host: "de.example.com", Obfs: secretObfs, Main: true, SourceName: "Панель"}}
}
func (f *fakeAPI) ResolveTarget(text string) (string, error) {
	switch text {
	case "DE":
		return "a1b2c3d4e5f6", nil
	case "Auto":
		return "grp-000000000001", nil
	case "vpn":
		return "", nil
	}
	return "", fmt.Errorf("сервер «%s» не найден", text)
}
func (f *fakeAPI) TargetName(id string) string {
	if id == "grp-000000000001" {
		return "Auto"
	}
	return "DE"
}
func (f *fakeAPI) SetMain(id string) error { f.call("SetMain:" + id); return nil }
func (f *fakeAPI) CheckProfile(id string) (app.CheckResult, error) {
	f.call("CheckProfile")
	return app.CheckResult{Profile: id, OK: true, Steps: []app.CheckStep{{Name: "TCP", OK: true}}}, nil
}
func (f *fakeAPI) Explain(q app.ExplainQuery) app.Explanation {
	if f.panicCmd {
		panic("boom")
	}
	return app.Explanation{Explanation: rules.Explanation{Winner: rules.Step{Index: -1, Action: rules.Direct}}, Port: q.Port}
}
func (f *fakeAPI) RulesText() string { return "a.com -> vpn\n" }
func (f *fakeAPI) RulesJSON() ([]byte, error) {
	return []byte(`{"hyroute":"rules","version":1,"rules":[{"name":"a"}],"targets":{}}`), nil
}
func (f *fakeAPI) ParseRulesTextAs(content, format string, replace bool) app.RulesTextResult {
	if strings.Contains(content, "bad") {
		return app.RulesTextResult{Errors: []app.RuleLine{{Line: 2, Text: "плохо"}}}
	}
	return app.RulesTextResult{Rules: []rules.Rule{{Name: "a"}}, Summary: "Правил: 1", Warnings: []app.RuleLine{}}
}
func (f *fakeAPI) ApplyRulesTextAs(content, format string, replace bool) (app.SaveResult, app.RulesTextResult, error) {
	f.call("ApplyRulesTextAs")
	return app.SaveResult{}, f.ParseRulesTextAs(content, format, replace), nil
}
func (f *fakeAPI) Subscriptions() []app.SubView {
	v := app.SubView{URLMasked: "https://panel.example/…", Profiles: 3}
	v.ID, v.Name, v.Enabled, v.URL = "s1", "Панель", true, secretSub
	return []app.SubView{v}
}
func (f *fakeAPI) ResolveSubscription(q string) (string, error) {
	if q == "Панель" {
		return "s1", nil
	}
	return "", errors.New("не найдено: подписка «" + q + "»")
}
func (f *fakeAPI) UpdateSubscription(id string) (app.MergeStats, error) {
	f.call("UpdateSubscription")
	return app.MergeStats{Added: 2}, nil
}
func (f *fakeAPI) Logs(kind string, after uint64) []logx.Entry { return f.journal.Since(after, 2000) }
func (f *fakeAPI) LogsTail(kind string, n int) []logx.Entry    { return f.journal.Tail(n) }
func (f *fakeAPI) Sanitizer() func(string) string              { return strings.ToUpper }
func (f *fakeAPI) Mode() string                                { f.mu.Lock(); defer f.mu.Unlock(); return f.mode }
func (f *fakeAPI) Log() *slog.Logger                           { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (f *fakeAPI) Groups() app.GroupsInfo {
	g := app.GroupView{Group: groups.Group{ID: "grp-000000000001", Name: "Auto", Strategy: groups.Latency, Members: []string{"a1b2c3d4e5f6"}},
		Active: "a1b2c3d4e5f6", Running: true, Views: []app.MemberView{{ID: "a1b2c3d4e5f6", Name: "DE", LatencyMs: 40}}}
	return app.GroupsInfo{Groups: []app.GroupView{g}, Probe: groups.Probe{URL: secretProbe}}
}
func (f *fakeAPI) Rulesets() app.RulesetsView {
	return app.RulesetsView{Active: "r1", Saved: true, List: []app.RulesetView{{ID: "r1", Name: "Дом", Active: true}, {ID: "r2", Name: "Работа"}}}
}
func (f *fakeAPI) ResolveRuleset(q string) (string, error) {
	switch q {
	case "Дом":
		return "r1", nil
	case "Работа":
		return "r2", nil
	}
	return "", errors.New("Профиль правил «" + q + "» не найден")
}
func (f *fakeAPI) SwitchRuleset(id string, src app.Source, o app.SwitchOptions) (app.SwitchResult, error) {
	f.call(fmt.Sprintf("SwitchRuleset:%s:%s:%v", id, src, o.Reconnect))
	return app.SwitchResult{Ruleset: app.RulesetRef{ID: id, Name: "Работа", Count: 2}, Note: "Профиль правил «Работа» включён.", Connected: true,
		Warnings: []app.RuleWarning{{Text: "w"}}}, nil
}

// netView: one rule «HomeWiFi» (its SSID) that disconnects, the network
// it matches now.
func (f *fakeAPI) netView() app.NetModesView {
	f.mu.Lock()
	on := f.netOn
	f.mu.Unlock()
	return app.NetModesView{
		Config: netmode.Config{Version: 1, Enabled: on, Rules: []netmode.Rule{{ID: "n1", Name: "HomeWiFi",
			Match: netmode.Match{SSIDs: []string{"HomeWiFi"}}, Action: netmode.Action{Connect: netmode.Disconnect}}},
			Unknown: netmode.Action{Connect: netmode.Connect}},
		Current: netmode.Snapshot{Active: &netmode.Network{ID: "{0F1E2D3C-0000-0000-0000-000000000001}", Name: "HomeWiFi", Category: netmode.Private,
			Adapter: netmode.WiFi, AdapterName: "Беспроводная сеть 2", SSID: "HomeWiFi", Identified: true}, Others: []netmode.Network{}},
		Match: &app.NetMatchView{RuleID: "n1", Name: "HomeWiFi", Action: netmode.Action{Connect: netmode.Disconnect}},
		State: app.NetState{Rule: "HomeWiFi", RuleID: "n1", Text: "Сеть сменилась: правило «HomeWiFi»"}, Available: true,
		Rulesets: []app.NetRuleset{}, RuleErrors: map[string]string{},
	}
}
func (f *fakeAPI) NetModes(refresh bool) app.NetModesView {
	f.call(fmt.Sprintf("NetModes:%v", refresh))
	return f.netView()
}

// ApplyNetModes: the rule disconnects, so only its key acts.
func (f *fakeAPI) ApplyNetModes(confirm string) (app.NetModesView, error) {
	f.call("ApplyNetModes:" + confirm)
	v := f.netView()
	if !v.Config.Enabled {
		return app.NetModesView{}, errors.New("Правила сетей выключены")
	}
	if confirm != "n1" {
		v.Confirm = true
	}
	return v, nil
}
func (f *fakeAPI) SetNetModesEnabled(on bool) (app.NetModesView, error) {
	f.call(fmt.Sprintf("SetNetModesEnabled:%v", on))
	f.mu.Lock()
	f.netOn = on
	f.mu.Unlock()
	return f.netView(), nil
}
func (f *fakeAPI) Stats(period string) (stats.Report, error) {
	f.call("Stats:" + period)
	if period == "2099-01" {
		return stats.Report{}, errors.New("неизвестный период статистики")
	}
	return stats.Report{Period: period, From: "2026-09-28", To: "2026-09-28", Total: stats.Counters{TC: 3, TU: 100, TD: 200},
		Days: []stats.DayTotal{}, Apps: []stats.Row{},
		Servers: []stats.Row{}, Groups: []stats.Row{}, Months: []string{"2026-09"}}, nil
}

// pipeListener hands out net.Pipe server ends with a chosen identity.
type pipeListener struct {
	ch     chan net.Conn
	allow  bool
	closed chan struct{}
	once   sync.Once
}

func newPipeListener(allow bool) *pipeListener {
	return &pipeListener{ch: make(chan net.Conn), allow: allow, closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, ctl.Identity, bool, error) {
	select {
	case c := <-l.ch:
		return c, ctl.Identity{User: "S-1-5-21-1", IntegrityRID: ctl.MediumRID}, l.allow, nil
	case <-l.closed:
		return nil, ctl.Identity{}, false, ctl.ErrClosed
	}
}

func (l *pipeListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

func (l *pipeListener) dial() net.Conn {
	c, s := net.Pipe()
	l.ch <- s
	return c
}

func serve(t *testing.T, api API, allow bool) (*Server, *pipeListener) {
	t.Helper()
	s := New(api)
	s.T = Timeouts{Request: time.Second, Write: time.Second, Linger: 200 * time.Millisecond, Poll: 10 * time.Millisecond,
		Wait: 5 * time.Millisecond, Close: time.Second}
	l := newPipeListener(allow)
	go s.Serve(l)
	t.Cleanup(s.Close)
	return s, l
}

func readFrame(t *testing.T, c net.Conn) ctl.Frame {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := ctl.ReadFrame(c, ctl.MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	var f ctl.Frame
	json.Unmarshal(b, &f)
	return f
}

// doReq sends one request and returns the final frame (events in evs).
func doReq(t *testing.T, l *pipeListener, cmd string, args any, private bool) (ctl.Frame, []json.RawMessage) {
	t.Helper()
	c := l.dial()
	defer c.Close()
	if h := readFrame(t, c); h.Hello == nil {
		return h, nil
	}
	var raw json.RawMessage
	if args != nil {
		raw, _ = json.Marshal(args)
	}
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: cmd, Args: raw, Private: private})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	var evs []json.RawMessage
	for {
		f := readFrame(t, c)
		if f.Final {
			return f, evs
		}
		evs = append(evs, f.Event)
	}
}

func TestHelloAndDenied(t *testing.T) {
	f := newFake()
	f.mode = "read"
	_, l := serve(t, f, true)
	c := l.dial()
	if h := readFrame(t, c); h.Hello == nil || h.Hello.Mode != "read" || h.Hello.Proto != ctl.Proto || h.Hello.MinProto != ctl.MinProto {
		t.Fatalf("%+v", h)
	}
	c.Close()
	_, l2 := serve(t, newFake(), false)
	c = l2.dial()
	if h := readFrame(t, c); h.Error == nil || h.Error.Code != ctl.CodeDenied || !h.Final {
		t.Fatalf("%+v", h)
	}
	if _, err := ctl.ReadFrame(c, 100); err != io.EOF {
		t.Fatal(err)
	}
}

func TestDispatchAll(t *testing.T) {
	f := newFake()
	_, l := serve(t, f, true)
	fr, _ := doReq(t, l, "status", nil, false)
	var st ctl.StatusView
	json.Unmarshal(fr.Result, &st)
	if st.State != "connected" || st.App != "v1.3.0" || st.KillSwitch != "armed" || len(st.Tunnels) != 1 || st.Warnings[0] != "правило «X»: сервер удалён" ||
		st.Ruleset.Name != "Дом" || len(st.MainGroup) == 0 || len(st.SubAlerts) == 0 || len(st.Stats) == 0 || st.Main.Kind != "server" ||
		!strings.Contains(string(st.Net), `"rule":"HomeWiFi"`) || !strings.Contains(string(st.DNS), `"upstream":"Cloudflare"`) {
		t.Fatalf("%+v", st)
	}
	if strings.Contains(string(fr.Result), "1080") || strings.Contains(string(fr.Result), "203.0.113.9") {
		t.Fatal("SOCKS or server IPs in status:", string(fr.Result))
	}
	for _, c := range []struct {
		cmd  string
		args any
		want string
	}{
		{"version", nil, `"core":"v2.6.2"`},
		{"servers", nil, `"address":"de.example.com:443"`},
		{"groups", nil, `"activeName":"DE"`},
		{"server", ctl.NameArgs{}, `"id":"a1b2c3d4e5f6"`},
		{"server", ctl.NameArgs{Name: "Auto"}, `"kind":"group"`},
		{"check", ctl.NameArgs{Name: "DE"}, `"ok":true`},
		{"rulesets", nil, `"name":"Работа"`},
		{"ruleset", ctl.RulesetArgs{Name: "Работа", Reconnect: true}, `"note":"Профиль правил «Работа» включён."`},
		{"ruleset", ctl.RulesetArgs{Name: "Дом"}, `"already":true`},
		{"explain", ctl.ExplainArgs{Target: "a.com", Port: 443}, `"port":443`},
		{"rules-export", ctl.RulesExportArgs{Format: "json"}, `"rules":1`},
		{"rules-export", nil, `"content":"a.com -> vpn\n"`},
		{"rules-import", ctl.RulesImportArgs{Content: "a.com -> vpn"}, `"saved":true`},
		{"subs", nil, `"name":"Панель"`},
		{"subs-update", ctl.NameArgs{}, `"added":2`},
		{"connect", ctl.WaitArgs{}, `"status":`},
		{"reconnect", nil, `"status":`},
		{"show", nil, `{}`},
		{"disconnect", nil, `"killSwitchOpened":true`},
		{"networks", nil, `"ssid":"HomeWiFi"`},
		{"networks-set", ctl.NetworksSetArgs{Enabled: true}, `"enabled":true`},
		{"networks-apply", ctl.NetworksApplyArgs{Yes: true}, `"text":"Сеть сменилась: правило «HomeWiFi»"`},
		{"stats", ctl.StatsArgs{Period: "7d"}, `"period":"7d"`},
		{"stats", nil, `"period":"today"`},
	} {
		fr, _ := doReq(t, l, c.cmd, c.args, false)
		if !fr.OK || !strings.Contains(string(fr.Result), c.want) {
			t.Errorf("%s: %+v %s", c.cmd, fr.Error, fr.Result)
		}
	}
	if !f.called("SwitchRuleset:r2:cli:true") || !f.called("SetMain:grp-000000000001") || !f.called("Reconnect") ||
		!f.called("NetModes:true") || !f.called("SetNetModesEnabled:true") || !f.called("ApplyNetModes:n1") {
		t.Fatal(f.calls)
	}
	// Errors.
	for _, c := range []struct {
		cmd  string
		args any
		code string
	}{
		{"server", ctl.NameArgs{Name: "vpn"}, ctl.CodeUsage},
		{"server", ctl.NameArgs{Name: "XX"}, ctl.CodeUsage},
		{"check", ctl.NameArgs{Name: "Auto"}, ctl.CodeUsage},
		{"logs", ctl.LogsArgs{Kind: "Auto"}, ctl.CodeUsage},
		{"explain", ctl.ExplainArgs{}, ctl.CodeUsage},
		{"rules-import", ctl.RulesImportArgs{Content: "bad"}, ctl.CodeRules},
		{"rules-import", ctl.RulesImportArgs{Content: strings.Repeat("a", ctl.MaxImport+1)}, ctl.CodeUsage},
		{"subs-update", ctl.NameArgs{Name: "Нет"}, ctl.CodeUsage},
		{"ruleset", ctl.RulesetArgs{Name: "Нет"}, ctl.CodeUsage},
		{"stats", ctl.StatsArgs{Period: "2099-01"}, ctl.CodeUsage},
	} {
		fr, _ := doReq(t, l, c.cmd, c.args, false)
		if fr.Error == nil || fr.Error.Code != c.code {
			t.Errorf("%s %+v: %+v", c.cmd, c.args, fr.Error)
		}
	}
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	fr, _ = doReq(t, l, "rules-import", ctl.RulesImportArgs{Content: "bad"}, false)
	if len(fr.Error.Lines) != 1 || fr.Error.Lines[0].Line != 2 {
		t.Fatalf("%+v", fr.Error)
	}
	if f.called("ApplyRulesTextAs") {
		t.Fatal("rules with errors were saved")
	}
}

func TestReadOnlyMode(t *testing.T) {
	f := newFake()
	f.mode = "read"
	_, l := serve(t, f, true)
	refused := []struct {
		cmd  string
		args any
	}{
		{"connect", nil}, {"reconnect", nil}, {"disconnect", nil}, {"server", ctl.NameArgs{Name: "DE"}}, {"check", ctl.NameArgs{Name: "DE"}},
		{"ruleset", ctl.RulesetArgs{Name: "Работа"}}, {"rules-import", ctl.RulesImportArgs{Content: "a.com -> vpn"}}, {"subs-update", nil},
		{"networks-apply", nil}, {"networks-set", ctl.NetworksSetArgs{Enabled: true}},
	}
	for _, c := range refused {
		if fr, _ := doReq(t, l, c.cmd, c.args, false); fr.Error == nil || fr.Error.Code != ctl.CodeReadOnly || ctl.ExitCode(fr.Error.Code) != 4 {
			t.Errorf("%s: %+v", c.cmd, fr)
		}
	}
	allowed := []struct {
		cmd  string
		args any
	}{
		{"status", nil}, {"servers", nil}, {"groups", nil}, {"server", nil}, {"rulesets", nil}, {"explain", ctl.ExplainArgs{Target: "a"}},
		{"rules-export", nil}, {"rules-import", ctl.RulesImportArgs{Content: "a.com -> vpn", DryRun: true}}, {"subs", nil}, {"logs", nil}, {"version", nil},
		{"networks", nil}, {"stats", ctl.StatsArgs{Period: "30d"}},
	}
	for _, c := range allowed {
		if fr, _ := doReq(t, l, c.cmd, c.args, false); !fr.OK {
			t.Errorf("%s: %+v", c.cmd, fr.Error)
		}
	}
	for _, c := range f.calls {
		if c != "NetModes:true" && c != "Stats:30d" {
			t.Fatal("a refused command ran:", f.calls)
		}
	}
}

func TestStrictArgs(t *testing.T) {
	_, l := serve(t, newFake(), true)
	if fr, _ := doReq(t, l, "explain", map[string]any{"target": "a", "future": 1}, false); fr.Error == nil || fr.Error.Code != ctl.CodeUnknownArg || fr.Error.Field != "future" {
		t.Fatalf("%+v", fr.Error)
	}
	if fr, _ := doReq(t, l, "explain", map[string]any{"target": 5}, false); fr.Error == nil || fr.Error.Code != ctl.CodeUsage {
		t.Fatalf("%+v", fr.Error)
	}
	if fr, _ := doReq(t, l, "status", map[string]any{"x": 1}, false); fr.Error == nil || fr.Error.Code != ctl.CodeUnknownArg {
		t.Fatalf("%+v", fr.Error)
	}
	if fr, _ := doReq(t, l, "frobnicate", nil, false); fr.Error == nil || fr.Error.Code != ctl.CodeUnknown {
		t.Fatalf("%+v", fr.Error)
	}
	for _, v := range []int{ctl.Proto + 1, ctl.MinProto - 1} {
		c := l.dial()
		readFrame(t, c)
		body, _ := json.Marshal(ctl.Request{V: v, Cmd: "status"})
		ctl.WriteFrame(c, body, ctl.MaxRequest)
		if fr := readFrame(t, c); fr.Error == nil || fr.Error.Code != ctl.CodeVersion {
			t.Fatalf("v=%d: %+v", v, fr)
		}
		c.Close()
	}
	// An oversize frame length: answered, the body never read.
	c := l.dial()
	readFrame(t, c)
	n := uint32(ctl.MaxRequest + 1)
	c.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	if fr := readFrame(t, c); fr.Error == nil || fr.Error.Message != "Запрос больше 4 МБ" {
		t.Fatalf("%+v", fr)
	}
	c.Close()
}

func TestModeOff(t *testing.T) {
	f := newFake()
	f.mode = "off"
	_, l := serve(t, f, true)
	c := l.dial()
	if fr := readFrame(t, c); fr.Hello != nil || fr.Error == nil || fr.Error.Code != ctl.CodeOff || !fr.Final {
		t.Fatalf("%+v", fr)
	}
	c.Close()
	// Off between hello and the request: refused, not run.
	f.mode = "full"
	c = l.dial()
	readFrame(t, c)
	f.mu.Lock()
	f.mode = "off"
	f.mu.Unlock()
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: "connect"})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	if fr := readFrame(t, c); fr.Error == nil || fr.Error.Code != ctl.CodeOff {
		t.Fatalf("%+v", fr)
	}
	c.Close()
	if f.called("ConnectOrResume") {
		t.Fatal("ran while off")
	}
}

func TestPrivateMasks(t *testing.T) {
	f := newFake()
	f.netOn = true
	_, l := serve(t, f, true)
	fr, _ := doReq(t, l, "servers", nil, true)
	var v []map[string]any
	json.Unmarshal(fr.Result, &v)
	if v[0]["address"] != "DE.EXAMPLE.COM:443" || v[0]["main"] != true || v[0]["name"] != "DE" {
		t.Fatalf("%v", v)
	}
	if _, ok := v[0]["ADDRESS"]; ok {
		t.Fatal("keys masked")
	}
	raw, _ := Private([]byte(`{"a":["x",{"b":"y"}],"n":12345678901234567890,"f":1.5}`), strings.ToUpper)
	if string(raw) != `{"a":["X",{"b":"Y"}],"f":1.5,"n":12345678901234567890}` {
		t.Fatal(string(raw))
	}
	// Network, Wi-Fi and rule names (often the Wi-Fi name) become «***»,
	// in networks and in the status' network line; the NLM ID stays.
	fr, _ = doReq(t, l, "networks", nil, true)
	if strings.Contains(string(fr.Result), "HomeWiFi") || strings.Contains(string(fr.Result), "Беспроводная") ||
		!strings.Contains(string(fr.Result), `"ssid":"***"`) || !strings.Contains(string(fr.Result), `"name":"***"`) {
		t.Fatalf("networks --private: %s", fr.Result)
	}
	fr, _ = doReq(t, l, "status", nil, true)
	if strings.Contains(string(fr.Result), "HomeWiFi") || !strings.Contains(string(fr.Result), `"rule":"***"`) {
		t.Fatalf("status --private: %s", fr.Result)
	}
	fr, _ = doReq(t, l, "networks", nil, false)
	if !strings.Contains(string(fr.Result), `"ssid":"HomeWiFi"`) {
		t.Fatalf("networks: %s", fr.Result)
	}
	// A confirm names the rule: masked as well.
	fr, _ = doReq(t, l, "networks-apply", nil, true)
	if fr.Error == nil || strings.Contains(fr.Error.Message, "HomeWiFi") || !strings.Contains(fr.Error.Message, "«***»") {
		t.Fatalf("%+v", fr.Error)
	}

	// Error texts quote names and hosts too.
	fr, _ = doReq(t, l, "server", ctl.NameArgs{Name: "secret.example"}, true)
	if fr.Error == nil || !strings.Contains(fr.Error.Message, "SECRET.EXAMPLE") {
		t.Fatalf("%+v", fr.Error)
	}
	fr, _ = doReq(t, l, "rules-import", ctl.RulesImportArgs{Content: "bad", Format: "text"}, true)
	if fr.Error == nil || len(fr.Error.Lines) != 1 || fr.Error.Lines[0].Text != "ПЛОХО" || fr.Error.Lines[0].Line != 2 {
		t.Fatalf("%+v", fr.Error)
	}
	fr, _ = doReq(t, l, "server", ctl.NameArgs{Name: "secret.example"}, false)
	if fr.Error == nil || !strings.Contains(fr.Error.Message, "secret.example") {
		t.Fatalf("%+v", fr.Error)
	}
}

func TestNoSecrets(t *testing.T) {
	f := newFake()
	_, l := serve(t, f, true)
	for _, cmd := range []string{"status", "servers", "groups", "subs", "rulesets", "version", "rules-export", "logs", "networks", "stats"} {
		fr, _ := doReq(t, l, cmd, nil, false)
		b, _ := json.Marshal(fr)
		for _, s := range []string{secretPass, secretObfs, secretPin, secretSub, "TOKEN-planted", secretProxy, secretDNS, secretProbe} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s leaks %s: %s", cmd, s, b)
			}
		}
	}
}

func TestClientGoneSkipsMutation(t *testing.T) {
	f := newFake()
	f.blockStat = make(chan struct{})
	_, l := serve(t, f, true)
	c := l.dial()
	readFrame(t, c)
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: "disconnect"})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	c.Close()
	time.Sleep(50 * time.Millisecond)
	close(f.blockStat)
	time.Sleep(100 * time.Millisecond)
	if f.called("Disconnect") {
		t.Fatal("a mutating call ran for a client that hung up")
	}
}

func TestConnectWait(t *testing.T) {
	f := newFake()
	f.statusSeq = []app.Status{{State: "connecting"}, {State: "connecting"}, {State: "connected"}}
	_, l := serve(t, f, true)
	fr, _ := doReq(t, l, "connect", ctl.WaitArgs{Wait: 5}, false)
	var v ctl.ConnectView
	json.Unmarshal(fr.Result, &v)
	if v.WaitedOut || v.Status.State != "connected" {
		t.Fatalf("%+v", v)
	}
	f.statusSeq = []app.Status{{State: "connecting"}}
	start := time.Now()
	fr, _ = doReq(t, l, "connect", ctl.WaitArgs{Wait: 1}, false)
	json.Unmarshal(fr.Result, &v)
	if !v.WaitedOut || time.Since(start) < time.Second {
		t.Fatalf("%+v", v)
	}
	for _, end := range []app.Status{{State: "error"}, {State: "disconnected"}} {
		f.statusSeq = []app.Status{{State: "connecting"}, end}
		start = time.Now()
		fr, _ = doReq(t, l, "connect", ctl.WaitArgs{Wait: 5}, false)
		json.Unmarshal(fr.Result, &v)
		if v.WaitedOut || v.Status.State != end.State || time.Since(start) > 2*time.Second {
			t.Fatalf("%+v", v)
		}
	}
}

func TestLogsFollow(t *testing.T) {
	f := newFake()
	for i := 0; i < 10000; i++ {
		f.journal.Add(time.Now(), "info", fmt.Sprint(i))
	}
	s, l := serve(t, f, true)
	_, evs := doReq(t, l, "logs", ctl.LogsArgs{Lines: 5000}, false)
	var got []logx.Entry
	for _, e := range evs {
		var page []logx.Entry
		json.Unmarshal(e, &page)
		if len(page) > logsPage {
			t.Fatal("page too big", len(page))
		}
		got = append(got, page...)
	}
	if len(got) != 5000 || got[0].Msg != "5000" || got[4999].Msg != "9999" {
		t.Fatal(len(got), got[0].Msg)
	}

	// Follow: new entries arrive; a gap is marked.
	s.T.Poll = 200 * time.Millisecond
	c := l.dial()
	readFrame(t, c)
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: "logs", Args: json.RawMessage(`{"lines":1,"follow":true}`)})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	readFrame(t, c) // the tail
	for i := 0; i < 3000; i++ {
		f.journal.Add(time.Now(), "info", fmt.Sprint("n", i))
	}
	var page []logx.Entry
	for len(page) == 0 || page[0].Seq != 0 && len(page) < 2 {
		json.Unmarshal(readFrame(t, c).Event, &page)
		if len(page) > 0 && page[0].Seq == 0 {
			break
		}
	}
	if !strings.Contains(page[0].Msg, "пропущено 1000 строк журнала") {
		t.Fatalf("%+v", page[0])
	}
	c.Close()
}

func TestFollowWriteDeadline(t *testing.T) {
	f := newFake()
	s, l := serve(t, f, true)
	s.T.Write = 200 * time.Millisecond
	c := l.dial()
	readFrame(t, c)
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: "logs", Args: json.RawMessage(`{"follow":true}`)})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	f.journal.Add(time.Now(), "info", "x") // an event nobody reads
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a follow stream nobody reads was not ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.Close()
}

func TestFinalLinger(t *testing.T) {
	_, l := serve(t, newFake(), true)
	c := l.dial()
	readFrame(t, c)
	body, _ := ctl.EncodeRequest(ctl.Request{V: ctl.Proto, Cmd: "version"})
	ctl.WriteFrame(c, body, ctl.MaxRequest)
	readFrame(t, c)
	// Not hanging up: the server closes after the linger.
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF || time.Since(start) < 150*time.Millisecond {
		t.Fatal(err, time.Since(start))
	}
}

func TestPanicRecovered(t *testing.T) {
	f := newFake()
	f.panicCmd = true
	_, l := serve(t, f, true)
	if fr, _ := doReq(t, l, "explain", ctl.ExplainArgs{Target: "a"}, false); fr.Error == nil || fr.Error.Code != ctl.CodeFailed {
		t.Fatalf("%+v", fr)
	}
	if fr, _ := doReq(t, l, "status", nil, false); !fr.OK {
		t.Fatal("not served after a panic")
	}
}

func TestSlowClient(t *testing.T) {
	s, l := serve(t, newFake(), true)
	s.T.Request = 100 * time.Millisecond
	c := l.dial()
	readFrame(t, c)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
}

func TestConcurrentCommands(t *testing.T) {
	_, l := serve(t, newFake(), true)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, cmd := range []string{"status", "servers", "groups", "subs", "rulesets"} {
				if fr, _ := doReq(t, l, cmd, nil, i%2 == 0); !fr.OK {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatal(bad.Load())
	}
}

// nonZero fails when a field of v named in fields is its zero value.
func nonZero(t *testing.T, what string, v any) {
	t.Helper()
	rv := reflect.ValueOf(v)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("%s.%s is empty after decoding the real type: a JSON tag changed?", what, rv.Type().Field(i).Name)
		}
	}
}

// TestLiteContract pins hyroutectl's lite views to the real app types.
func TestLiteContract(t *testing.T) {
	step := rules.Step{Index: 2, Name: "GitHub", Enabled: true, Matched: true, Winner: true, Reason: "сайт", Action: rules.Tunnel, Profile: "a"}
	dns := app.DNSExplain{Route: "tunnel", Profile: "a1b2c3d4e5f6", Upstream: "Cloudflare", Rule: "GitHub", Cond: "proto", Proto: "udp", NoIPv6: true}
	sys := dns
	dns.System = &sys
	ex := app.Explanation{Explanation: rules.Explanation{Steps: []rules.Step{step}, Winner: step, Notes: []string{"n"}},
		ProfileName: "DE", Group: true, Via: "NL", Port: 443, DNS: &dns}
	var exl cli.ExplanationLite
	json.Unmarshal(rawJSON(explainView(ex, func(string) string { return "DE" })), &exl)
	nonZero(t, "ExplanationLite", exl)
	nonZero(t, "StepLite", exl.Winner)
	nonZero(t, "DNSExplainLite", *exl.DNS)
	if exl.DNS.System.ProfileName != "DE" || exl.DNS.System.System != nil {
		t.Fatalf("%+v", exl.DNS.System)
	}

	ds := app.DNSStatus{ByRules: true, Health: []app.DNSHealth{{Via: "tunnel", Profile: "a", Upstream: "Quad9", Kind: "tls"}}, PauseLeft: 30, NotApplied: true}
	var dsl cli.DNSStatusLite
	json.Unmarshal(rawJSON(ds), &dsl)
	nonZero(t, "DNSStatusLite", dsl)
	nonZero(t, "DNSHealthLite", dsl.Health[0])

	ns := app.NetState{Rule: "Дом", RuleID: "n1", Unknown: true, NoNet: true, Pending: true, Text: "t", Error: "e", Override: true, Restored: true,
		Off: true, OffBy: "Офис"}
	var nsl cli.NetStateLite
	json.Unmarshal(rawJSON(ns), &nsl)
	nonZero(t, "NetStateLite", nsl)

	off := false
	nv := app.NetModesView{
		Config: netmode.Config{Enabled: true, Rules: []netmode.Rule{{ID: "n1", Name: "Дом", Enabled: &off,
			Action: netmode.Action{Connect: netmode.Disconnect, Ruleset: "r1"}}}, Unknown: netmode.Action{Connect: netmode.Connect, Ruleset: "r2"}},
		Current: netmode.Snapshot{Active: &netmode.Network{Name: "n", Category: netmode.Public, Adapter: netmode.WiFi, SSID: "s"}, Err: "e"},
		Match:   &app.NetMatchView{Name: "Дом", Unknown: true, Action: netmode.Action{Connect: netmode.Connect, Ruleset: "r1"}},
		State:   ns, Unavailable: "u", LoadError: "l", Rulesets: []app.NetRuleset{{ID: "r1", Name: "Работа"}},
	}
	var nvl cli.NetModesLite
	json.Unmarshal(rawJSON(nv), &nvl)
	nonZero(t, "NetModesLite", nvl)
	nonZero(t, "NetConfigLite", nvl.Config)
	nonZero(t, "NetRuleLite", nvl.Config.Rules[0])
	nonZero(t, "NetActionLite", nvl.Config.Rules[0].NetActionLite)
	nonZero(t, "NetActionLite (unknown)", nvl.Config.Unknown)
	nonZero(t, "NetSnapshotLite", nvl.Current)
	nonZero(t, "NetworkLite", *nvl.Current.Active)
	nonZero(t, "NetMatchLite", *nvl.Match)
	nonZero(t, "NetRulesetLite", nvl.Rulesets[0])

	c := stats.Counters{TC: 1, TU: 2, TD: 3, DC: 4, DU: 5, BC: 6, F: 7, FO: 8}
	row := stats.Row{Key: "k", Name: "n", Counters: c, Drops: 1, Gone: true}
	rep := stats.Report{Period: "7d", From: "2026-09-22", To: "2026-09-28", Total: c, Events: stats.Events{Drops: 1, EngineFails: 2},
		Apps: []stats.Row{row}, Servers: []stats.Row{row}, Groups: []stats.Row{row}, Since: "2026-07-01",
		Mode: "no-sites", StoreError: "e", ModeUnread: true}
	var rl cli.ReportLite
	json.Unmarshal(rawJSON(rep), &rl)
	nonZero(t, "ReportLite", rl)
	nonZero(t, "StatCountersLite", rl.Total)
	nonZero(t, "StatEventsLite", rl.Events)
	nonZero(t, "StatRowLite", rl.Apps[0])

	gb := app.GroupBrief{ID: "grp-1", Name: "Auto", Strategy: groups.Latency, Active: "a", ActiveName: "DE", Up: 1, Total: 2, Rejected: 3}
	var gbl cli.GroupBriefLite
	json.Unmarshal(rawJSON(gb), &gbl)
	nonZero(t, "GroupBriefLite", gbl)

	sa := app.SubAlert{ID: "s", Name: "Панель", Level: "low", Text: "мало", Key: "k"}
	var sal cli.SubAlertLite
	json.Unmarshal(rawJSON(sa), &sal)
	nonZero(t, "SubAlertLite", sal)
}

func rawJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// A network rule that disconnects (and so releases the kill switch block)
// runs only with --yes, as the window asks first.
func TestNetworksApplyConfirm(t *testing.T) {
	f := newFake()
	f.netOn = true
	_, l := serve(t, f, true)
	fr, _ := doReq(t, l, "networks-apply", ctl.NetworksApplyArgs{}, false)
	if fr.Error == nil || fr.Error.Code != ctl.CodeFailed || !strings.Contains(fr.Error.Message, "Правило «HomeWiFi» отключит HyRoute") ||
		!strings.Contains(fr.Error.Message, "hyroutectl networks apply --yes") {
		t.Fatalf("%+v", fr.Error)
	}
	if f.called("ApplyNetModes:n1") || !f.called("ApplyNetModes:") {
		t.Fatal("ran without --yes:", f.calls)
	}
	fr, _ = doReq(t, l, "networks-apply", ctl.NetworksApplyArgs{Yes: true}, false)
	if !fr.OK || !f.called("ApplyNetModes:n1") {
		t.Fatalf("%+v %v", fr.Error, f.calls)
	}
	// Off: the controller's refusal.
	doReq(t, l, "networks-set", ctl.NetworksSetArgs{}, false)
	fr, _ = doReq(t, l, "networks-apply", ctl.NetworksApplyArgs{Yes: true}, false)
	if fr.Error == nil || fr.Error.Message != "Правила сетей выключены" {
		t.Fatalf("%+v", fr.Error)
	}
}
