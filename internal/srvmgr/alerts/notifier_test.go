package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// Canaries: a password the controller knows and a server's address.
const (
	canaryPass = "canary-alert-ssh-pass-77"
	canaryHost = "198.51.100.77"
)

type env struct {
	t     *testing.T
	db    *sqlite.DB
	keys  *secrets.Keyring
	red   *redact.Redactor
	bus   *events.Bus
	n     *Notifier
	logs  *bytes.Buffer
	lmu   *sync.Mutex
	clock atomic.Int64 // unix seconds of the fake time
	srv   model.Server
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	e := &env{t: t, db: db, keys: keys, red: redact.New(), logs: &bytes.Buffer{}, lmu: &sync.Mutex{}}
	e.red.Add(canaryPass)
	e.clock.Store(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).Unix())
	now := func() time.Time { return time.Unix(e.clock.Load(), 0) }
	log := slog.New(e.red.Handler(slog.NewTextHandler(lockedWriter{e.lmu, e.logs}, nil)))
	e.bus = &events.Bus{Store: db, Redact: e.red, Now: now}
	e.n = &Notifier{Store: db, Keys: keys, Redact: e.red, Log: log, Now: now, Glue: 50 * time.Millisecond, Retry: []time.Duration{50 * time.Millisecond},
		Timeout: 2 * time.Second, QuietPoll: 20 * time.Millisecond}
	e.bus.Subscribe(e.n.Notify)
	e.srv = model.Server{Name: "Alpha", Host: canaryHost, SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword}
	if err := db.CreateServer(ctx, &e.srv, nil); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) start() {
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	e.n.Start(ctx)
}

// channel stores a channel with its sealed secret.
func (e *env) channel(c model.AlertChannel, secret string) model.AlertChannel {
	e.t.Helper()
	c.Enabled = true
	if err := Check(&c, secret); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.CreateAlertChannel(context.Background(), &c, func(id int64) ([]byte, error) {
		if secret == "" {
			return nil, nil
		}
		return e.keys.Seal([]byte(secret), model.AlertSecretContext(id))
	}); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// raise opens an event whose raw text has the canaries in it.
func (e *env) raise(key string, kind model.EventKind) {
	e.t.Helper()
	err := e.bus.Raise(context.Background(), model.Event{Kind: kind, Key: key, Severity: model.SeverityCritical, Subject: model.SubjectServer, SubjectID: e.srv.ID,
		Text: "Сервер «Alpha» недоступен: dial tcp " + canaryHost + ":22 (password " + canaryPass + ")."})
	if err != nil {
		e.t.Fatal(err)
	}
}

// hook is a webhook receiver on 127.0.0.1.
type hook struct {
	mu     sync.Mutex
	bodies [][]byte
	heads  []http.Header
	status []int // answers in turn, then 200
	got    chan struct{}
	block  chan struct{} // set: requests hang until it is closed
}

func newHook(t *testing.T) (*hook, *httptest.Server) {
	h := &hook{got: make(chan struct{}, 100)}
	s := httptest.NewServer(h)
	t.Cleanup(func() {
		h.mu.Lock()
		if h.block != nil {
			close(h.block)
			h.block = nil
		}
		h.mu.Unlock()
		s.Close()
	})
	return h, s
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.bodies, h.heads = append(h.bodies, b), append(h.heads, r.Header.Clone())
	code := http.StatusOK
	if len(h.status) > 0 {
		code, h.status = h.status[0], h.status[1:]
	}
	block := h.block
	h.mu.Unlock()
	h.got <- struct{}{}
	if block != nil {
		select {
		case <-block:
		case <-r.Context().Done():
		}
		return
	}
	w.WriteHeader(code)
}

func (h *hook) wait(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-h.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("the webhook got %d of %d requests", len(h.all()), n)
		}
	}
}

func (h *hook) all() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.bodies...)
}

func (e *env) webhook(url string, kinds ...model.EventKind) model.AlertChannel {
	return e.channel(model.AlertChannel{Name: "hook", Kind: model.ChannelWebhook, Settings: json.RawMessage(`{"url":"` + url + `"}`), Events: kinds}, fakeHookey)
}

// The webhook gets one signed message for the events of a window, with
// no secret or address in it; a channel gets only the kinds it wants.
func TestWebhookGlueAndSign(t *testing.T) {
	e := newEnv(t)
	h, s := newHook(t)
	e.webhook(s.URL)
	other, so := newHook(t)
	e.webhook(so.URL, model.EventDisk)
	e.start()
	for i := range 5 {
		e.raise("server:"+strconv.Itoa(i), model.EventServer)
	}
	e.bus.Resolve(context.Background(), "server:0", "Сервер «Alpha» снова работает.")
	h.wait(t, 1)
	time.Sleep(150 * time.Millisecond)
	bodies := h.all()
	if len(bodies) != 1 {
		t.Fatalf("%d requests, want one for the window", len(bodies))
	}
	var body WebhookBody
	if err := json.Unmarshal(bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	if body.Source != "hyroute-server" || len(body.Events) != 6 || body.Events[0].State != "open" || body.Events[5].State != "closed" || body.Events[5].ClosedAt == nil ||
		!strings.Contains(body.Text, "5 событий") || !strings.Contains(body.Text, "Было и прошло") {
		t.Fatalf("body %s", bodies[0])
	}
	for _, bad := range []string{canaryHost, canaryPass, fakeHookey} {
		if bytes.Contains(bodies[0], []byte(bad)) {
			t.Fatalf("%q in the webhook body", bad)
		}
	}
	h.mu.Lock()
	head := h.heads[0]
	h.mu.Unlock()
	ts, _ := strconv.ParseInt(head.Get(HeaderTimestamp), 10, 64)
	if ts != e.clock.Load() || head.Get(HeaderSignature) != Sign(fakeHookey, ts, bodies[0]) || !strings.HasPrefix(head.Get(HeaderSignature), "sha256=") {
		t.Fatalf("signature %q at %q", head.Get(HeaderSignature), head.Get(HeaderTimestamp))
	}
	if Sign("another-key-0123456789", ts, bodies[0]) == head.Get(HeaderSignature) || Sign(fakeHookey, ts+1, bodies[0]) == head.Get(HeaderSignature) {
		t.Fatal("the signature does not depend on the key and the time")
	}
	if n := len(other.all()); n != 0 {
		t.Fatalf("the disk-only channel got %d messages", n)
	}
}

// During quiet hours nothing goes; when they end, all of it goes glued.
func TestQuietHours(t *testing.T) {
	e := newEnv(t)
	h, s := newHook(t)
	c := e.webhook(s.URL)
	c.Quiet = model.QuietHours{From: "23:00", To: "08:00", Zone: "UTC"}
	if err := e.db.UpdateAlertChannel(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.Store(time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC).Unix())
	e.start()
	e.raise("server:1", model.EventServer)
	time.Sleep(100 * time.Millisecond)
	e.raise("server:2", model.EventServer)
	time.Sleep(200 * time.Millisecond)
	if n := len(h.all()); n != 0 {
		t.Fatalf("%d messages during quiet hours", n)
	}
	e.clock.Store(time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC).Unix())
	h.wait(t, 1)
	var body WebhookBody
	json.Unmarshal(h.all()[0], &body)
	if len(body.Events) != 2 {
		t.Fatalf("after quiet hours: %+v", body)
	}
}

// A failed send is retried after the pause, with what came meanwhile.
func TestRetry(t *testing.T) {
	e := newEnv(t)
	h, s := newHook(t)
	h.status = []int{http.StatusInternalServerError}
	e.webhook(s.URL)
	e.start()
	e.raise("server:1", model.EventServer)
	h.wait(t, 1)
	e.raise("server:2", model.EventServer)
	h.wait(t, 1)
	bodies := h.all()
	var body WebhookBody
	json.Unmarshal(bodies[1], &body)
	if len(bodies) != 2 || len(body.Events) != 2 {
		t.Fatalf("%d requests, the retry has %d events", len(bodies), len(body.Events))
	}
	e.lmu.Lock()
	logged := e.logs.String()
	e.lmu.Unlock()
	if !strings.Contains(logged, "will retry") || strings.Contains(logged, fakeHookey) {
		t.Fatalf("log %s", logged)
	}
}

// A channel that does not answer holds up nobody: raising events stays
// quick, the queue is bounded, and what did not fit is counted.
func TestHungChannel(t *testing.T) {
	e := newEnv(t)
	h, s := newHook(t)
	h.block = make(chan struct{})
	e.webhook(s.URL)
	e.n.Queue, e.n.Timeout = 10, 300*time.Millisecond
	e.start()
	e.raise("server:0", model.EventServer)
	h.wait(t, 1) // the first send hangs
	start := time.Now()
	for i := 1; i <= 40; i++ {
		e.raise("server:"+strconv.Itoa(i), model.EventServer)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("raising 40 events took %v with a hung channel", took)
	}
	// The timeout ends the hung send; the retry carries the queue.
	h.wait(t, 1)
	var body WebhookBody
	json.Unmarshal(h.all()[1], &body)
	if len(body.Events) != 10 || body.Dropped != 31 || !strings.Contains(body.Text, "не отправлено") {
		t.Fatalf("retry: %d events, %d dropped", len(body.Events), body.Dropped)
	}
}

// Telegram: the bot token goes only into the Bot API path; it is in no
// log line and no error.
func TestTelegram(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var paths []string
	var texts []map[string]any
	fail := atomic.Bool{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		paths, texts = append(paths, r.URL.Path), append(texts, m)
		mu.Unlock()
		if fail.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(api.Close)
	c := e.channel(model.AlertChannel{Name: "Админы", Kind: model.ChannelTelegram, Settings: json.RawMessage(`{"chatId":"-1001","apiBase":"` + api.URL + `"}`)}, fakeToken)
	e.start()
	if err := e.n.Test(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	e.raise("server:1", model.EventServer)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(paths)
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d requests", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if paths[0] != "/bot"+fakeToken+"/sendMessage" || texts[0]["chat_id"] != "-1001" || !strings.Contains(texts[0]["text"].(string), "Проверка канала «Админы»") {
		t.Fatalf("test %s %v", paths[0], texts[0])
	}
	sent := texts[1]["text"].(string)
	mu.Unlock()
	if !strings.Contains(sent, "Сервер «Alpha» недоступен") || strings.Contains(sent, canaryHost) || strings.Contains(sent, canaryPass) {
		t.Fatalf("text %q", sent)
	}
	fail.Store(true)
	err := e.n.Test(context.Background(), c.ID)
	if err == nil || strings.Contains(err.Error(), fakeToken) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("failed test: %v", err)
	}
	// A dead Bot API: the error of the request names its URL, token and
	// all — it is dropped.
	api.Close()
	err = e.n.Test(context.Background(), c.ID)
	if err == nil || strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), strings.SplitN(fakeToken, ":", 2)[1]) {
		t.Fatalf("dead API: %v", err)
	}
	e.lmu.Lock()
	defer e.lmu.Unlock()
	if strings.Contains(e.logs.String(), strings.SplitN(fakeToken, ":", 2)[1]) {
		t.Fatalf("the token is in the log: %s", e.logs.String())
	}
}

// Reload follows the admin: a disabled or deleted channel stops getting
// messages, a new one starts.
func TestReload(t *testing.T) {
	e := newEnv(t)
	h, s := newHook(t)
	c := e.webhook(s.URL)
	e.start()
	c.Enabled = false
	e.db.UpdateAlertChannel(context.Background(), c, nil)
	if err := e.n.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.raise("server:1", model.EventServer)
	time.Sleep(200 * time.Millisecond)
	if n := len(h.all()); n != 0 {
		t.Fatalf("a disabled channel got %d messages", n)
	}
	c.Enabled = true
	e.db.UpdateAlertChannel(context.Background(), c, nil)
	e.n.Reload(context.Background())
	e.raise("server:2", model.EventServer)
	h.wait(t, 1)
}
