// Package ctlserver serves hyroutectl's requests inside HyRoute: one
// request per connection, dispatched to the same controller calls the
// window makes (the CLI does nothing the UI cannot do).
package ctlserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/stats"
)

// API is what the commands need from HyRoute; ctl_windows.go implements it
// over the GUI and the controller. Methods mirror bound GUI methods.
type API interface {
	Version() (app, core string)
	Status() app.Status
	ConnectOrResume() (already bool, err error)
	Reconnect() error
	Disconnect()
	ShowWindow() error // an error before the window exists
	Profiles() []app.ProfileSummary
	ResolveTarget(text string) (string, error) // "" = main
	TargetName(id string) string
	SetMain(id string) error
	CheckProfile(id string) (app.CheckResult, error)
	Explain(q app.ExplainQuery) app.Explanation
	RulesText() string
	RulesJSON() ([]byte, error)
	ParseRulesTextAs(content, format string, replace bool) app.RulesTextResult
	ApplyRulesTextAs(content, format string, replace bool) (app.SaveResult, app.RulesTextResult, error)
	Subscriptions() []app.SubView
	ResolveSubscription(q string) (string, error)
	UpdateSubscription(id string) (app.MergeStats, error)
	Logs(kind string, after uint64) []logx.Entry
	LogsTail(kind string, n int) []logx.Entry
	Sanitizer() func(string) string // one c.mu hold per request
	Mode() string                   // "full" | "read" | "off" (listener being stopped, or prefs broken)
	Log() *slog.Logger

	// Features consumed by the command line.
	Groups() app.GroupsInfo
	Rulesets() app.RulesetsView
	ResolveRuleset(q string) (string, error)
	SwitchRuleset(id string, src app.Source, o app.SwitchOptions) (app.SwitchResult, error)
	// netmodes: the page «Сети» (refresh: a fresh read of the network),
	// «Применить сейчас» (confirmDisconnect: the NetRuleKey of the
	// disconnecting rule the user confirmed) and «Действовать по сети».
	NetModes(refresh bool) app.NetModesView
	ApplyNetModes(confirmDisconnect string) (app.NetModesView, error)
	SetNetModesEnabled(on bool) (app.NetModesView, error)
	// stats: the report of a period (today, yesterday, 7d, 30d, YYYY-MM).
	Stats(period string) (stats.Report, error)
}

// Listener is what Serve accepts from (ctl.Listener; tests feed net.Pipe
// conns with a chosen identity).
type Listener interface {
	Accept() (net.Conn, ctl.Identity, bool, error)
	Close() error
}

// Timeouts (tests shorten them).
type Timeouts struct {
	Request time.Duration // the request must arrive within this
	Write   time.Duration // every frame, including each logs event
	Linger  time.Duration // after the final frame, until the client hangs up
	Poll    time.Duration // logs --follow
	Wait    time.Duration // connect --wait status polls
	Close   time.Duration // Close waits this long for handlers
}

var defaultTimeouts = Timeouts{Request: 10 * time.Second, Write: 30 * time.Second, Linger: 2 * time.Second,
	Poll: 500 * time.Millisecond, Wait: 250 * time.Millisecond, Close: 2 * time.Second}

// Server dispatches requests. It holds no lock across API calls: the
// controller's own locks order the commands like concurrent UI clicks.
type Server struct {
	api  API
	cmds map[string]command
	T    Timeouts

	mu     sync.Mutex // guards conns and ln
	conns  map[net.Conn]struct{}
	ln     Listener
	wg     sync.WaitGroup
	closed atomic.Bool
	quit   chan struct{}
}

func New(api API) *Server {
	return &Server{api: api, cmds: commands(), T: defaultTimeouts, conns: map[net.Conn]struct{}{}, quit: make(chan struct{})}
}

// Serve accepts until l or the server is closed.
func (s *Server) Serve(l Listener) error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		l.Close()
		return nil
	}
	s.ln = l
	s.mu.Unlock()
	for {
		c, id, allowed, err := l.Accept()
		if err != nil {
			if s.closed.Load() || errors.Is(err, ctl.ErrClosed) {
				return nil
			}
			s.api.Log().Warn("command line: accept failed", "err", err)
			select {
			case <-s.quit:
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		if !s.track(c) {
			c.Close()
			return nil
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.handle(c, id, allowed)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

// Close closes the listener and every open connection, and waits up to
// T.Close for the handlers (one blocked in a controller call finishes it).
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed.Swap(true) {
		s.mu.Unlock()
		return
	}
	close(s.quit)
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(s.T.Close):
	}
}

// request is one request being served.
type request struct {
	s       *Server
	conn    net.Conn
	ctx     context.Context
	private bool
	mask    func(string) string // private: the sanitizer, read once
}

// emit sends a logs page (not final) with the write deadline.
func (r *request) emit(v any) error {
	raw, err := r.encode(v)
	if err != nil {
		return err
	}
	return r.s.write(r.conn, ctl.Frame{V: ctl.Proto, OK: true, Event: raw})
}

// encode marshals a result or event, masked with --private.
func (r *request) encode(v any) (json.RawMessage, error) {
	raw, err := ctl.Marshal(v)
	if err != nil || !r.private {
		return raw, err
	}
	return Private(raw, r.mask)
}

func (s *Server) write(c net.Conn, f ctl.Frame) error {
	c.SetWriteDeadline(time.Now().Add(s.T.Write))
	return ctl.WriteJSON(c, f, ctl.MaxResponse)
}

func (s *Server) fail(c net.Conn, e *ctl.Error) error {
	return s.write(c, ctl.Frame{V: ctl.Proto, Final: true, Error: e})
}

var errGone = &ctl.Error{Code: ctl.CodeDropped, Message: "client gone"}

// handle serves one connection.
func (s *Server) handle(c net.Conn, id ctl.Identity, allowed bool) {
	log := s.api.Log()
	if !allowed {
		log.Debug("command line: client refused", "pid", id.PID)
		s.fail(c, &ctl.Error{Code: ctl.CodeDenied, Message: "HyRoute отказал в доступе: команды принимаются только от программ пользователя, запустившего HyRoute."})
		return
	}
	mode := s.api.Mode()
	if mode == "off" {
		s.fail(c, offError)
		return
	}
	if err := s.write(c, ctl.Frame{V: ctl.Proto, OK: true, Hello: &ctl.Hello{App: s.appVersion(), Proto: ctl.Proto, MinProto: ctl.MinProto, Mode: mode}}); err != nil {
		return
	}
	c.SetReadDeadline(time.Now().Add(s.T.Request))
	body, err := ctl.ReadFrame(c, ctl.MaxRequest)
	if err != nil {
		var tb *ctl.ErrFrameTooBig
		if errors.As(err, &tb) && tb.N > 0 {
			// Answered before closing; the body is never read.
			s.fail(c, &ctl.Error{Code: ctl.CodeUsage, Message: "Запрос больше 4 МБ"})
		}
		return
	}
	var req ctl.Request
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Cmd == "" {
		s.fail(c, &ctl.Error{Code: ctl.CodeUsage, Message: "Неверный запрос"})
		return
	}
	if req.V > ctl.Proto || req.V < ctl.MinProto {
		s.fail(c, &ctl.Error{Code: ctl.CodeVersion, Message: fmt.Sprintf("hyroutectl говорит на протоколе %d, HyRoute — на %d–%d", req.V, ctl.MinProto, ctl.Proto)})
		return
	}
	cmd, ok := s.cmds[req.Cmd]
	if !ok {
		s.fail(c, &ctl.Error{Code: ctl.CodeUnknown, Message: fmt.Sprintf("Эта версия HyRoute не поддерживает команду «%s»: обновите HyRoute.", req.Cmd)})
		return
	}
	args, aerr := decodeArgs(cmd, req.Args)
	if aerr != nil {
		s.fail(c, aerr)
		return
	}
	switch s.api.Mode() { // re-read: the user may have changed it meanwhile
	case "off":
		s.fail(c, offError)
		return
	case "read":
		if cmd.mutating != nil && cmd.mutating(args) {
			s.fail(c, &ctl.Error{Code: ctl.CodeReadOnly, Message: "Команда недоступна: разрешён только просмотр. Включите «Полный доступ» в «Настройки» → «Командная строка» (интерфейс «Для опытных»)."})
			return
		}
	}

	// The client sends nothing more: any return of Read means it is gone.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gone := make(chan struct{})
	c.SetReadDeadline(time.Time{})
	go func() {
		var b [1]byte
		c.Read(b[:])
		cancel()
		close(gone)
	}()
	r := &request{s: s, conn: c, ctx: ctx, private: req.Private}
	if req.Private {
		r.mask = s.api.Sanitizer()
	}
	if cmd.mutating != nil && cmd.mutating(args) {
		if !cmd.detail {
			log.Info("command line: " + req.Cmd)
		}
	} else {
		log.Debug("command line: " + req.Cmd)
	}
	res, cerr := s.run(r, cmd, args, req.Cmd)
	if cerr == errGone {
		log.Debug("command line: client gone, not run", "cmd", req.Cmd)
		return
	}
	var f ctl.Frame
	if cerr != nil {
		f = ctl.Frame{V: ctl.Proto, Final: true, Error: r.maskError(cerr)}
	} else {
		raw, err := r.encode(res)
		if err != nil {
			f = ctl.Frame{V: ctl.Proto, Final: true, Error: &ctl.Error{Code: ctl.CodeFailed, Message: "Внутренняя ошибка HyRoute: " + err.Error()}}
		} else {
			f = ctl.Frame{V: ctl.Proto, OK: true, Final: true, Result: raw}
		}
	}
	if s.write(c, f) != nil {
		return
	}
	// Linger: the final frame's tail stays in the pipe until the client
	// has read it (it hangs up right after); no DisconnectNamedPipe.
	select {
	case <-gone:
	case <-time.After(s.T.Linger):
	case <-s.quit:
	}
}

// maskError masks an error's texts under --private: they quote servers,
// hosts and domains too. A copy: shared errors stay as they are.
func (r *request) maskError(e *ctl.Error) *ctl.Error {
	if r.mask == nil {
		return e
	}
	m := *e
	m.Message = r.mask(e.Message)
	if len(e.Lines) > 0 {
		m.Lines = make([]ctl.ErrorLine, len(e.Lines))
		for i, l := range e.Lines {
			l.Text = r.mask(l.Text)
			m.Lines[i] = l
		}
	}
	return &m
}

// run calls the handler, recovering a panic.
func (s *Server) run(r *request, cmd command, args any, name string) (res any, cerr *ctl.Error) {
	defer func() {
		if p := recover(); p != nil {
			s.api.Log().Error("command line: handler panic", "cmd", name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			res, cerr = nil, &ctl.Error{Code: ctl.CodeFailed, Message: "Внутренняя ошибка HyRoute: команда не выполнена"}
		}
	}()
	return cmd.run(r, args)
}

func (s *Server) appVersion() string {
	a, _ := s.api.Version()
	return a
}

var offError = &ctl.Error{Code: ctl.CodeOff, Message: "Командная строка выключена в «Настройки» → «Командная строка» (интерфейс «Для опытных»)"}

// decodeArgs decodes a request's args strictly into the command's type:
// an unknown field is unknown-arg (a newer hyroutectl's option), anything
// else wrong is usage.
func decodeArgs(cmd command, raw json.RawMessage) (any, *ctl.Error) {
	v := cmd.args()
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if f, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			f = strings.Trim(f, `"`)
			return nil, &ctl.Error{Code: ctl.CodeUnknownArg, Field: f, Message: fmt.Sprintf("Эта версия HyRoute не знает параметр «%s»: обновите HyRoute или уберите параметр.", f)}
		}
		return nil, &ctl.Error{Code: ctl.CodeUsage, Message: "Неверные параметры команды"}
	}
	if dec.More() {
		return nil, &ctl.Error{Code: ctl.CodeUsage, Message: "Неверные параметры команды"}
	}
	return v, nil
}

// live is checked before every mutating call: a client that hung up does
// not get it run.
func (r *request) live() *ctl.Error {
	if r.ctx.Err() != nil {
		return errGone
	}
	return nil
}
