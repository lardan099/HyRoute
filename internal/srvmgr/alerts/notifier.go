package alerts

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// Store is what the notifier reads.
type Store interface {
	ListAlertChannels(ctx context.Context) ([]model.AlertChannel, error)
	AlertChannelByID(ctx context.Context, id int64) (model.AlertChannel, error)
	AlertChannelSecret(ctx context.Context, id int64) ([]byte, error)
}

// Defaults of the Notifier.
const (
	DefaultGlue      = 30 * time.Second
	DefaultTimeout   = 15 * time.Second
	DefaultQueue     = 200
	DefaultQuietPoll = time.Minute
)

// DefaultRetry are the pauses before each new attempt of a failed send:
// about two hours in all, longer than most outages of a network (the
// controller's own included: its «no network» event goes out once the
// network is back).
var DefaultRetry = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour}

// Notifier sends the notices of the event bus through every enabled
// channel that wants their kind. Notify only queues: a channel that does
// not answer holds up nobody but its own queue.
type Notifier struct {
	Store Store
	Keys  *secrets.Keyring
	// Redact is the controller's redactor: channel secrets are added to
	// it, so no log line shows them.
	Redact *redact.Redactor
	Log    *slog.Logger
	Now    func() time.Time
	// Glue: notices that come within it go out as one message.
	Glue time.Duration
	// Retry are the pauses before the attempts after a failed send.
	Retry []time.Duration
	// Timeout bounds one send.
	Timeout time.Duration
	// Queue bounds the notices waiting per channel: past it the oldest
	// are dropped (and counted in the next message).
	Queue int
	// QuietPoll: how often held messages look whether the quiet hours
	// are over.
	QuietPoll time.Duration
	// HTTP sends to Telegram and webhooks (nil: a client of its own that
	// does not follow redirects); TLS is the base of SMTP's TLS settings.
	HTTP *http.Client
	TLS  *tls.Config

	mu      sync.Mutex
	ctx     context.Context
	workers map[int64]*worker
}

// worker sends through one channel.
type worker struct {
	n    *Notifier
	stop context.CancelFunc
	wake chan struct{}

	mu      sync.Mutex
	ch      model.AlertChannel
	send    Sender
	queue   []events.Notice
	dropped int
}

func (n *Notifier) now() time.Time {
	if n.Now == nil {
		return time.Now()
	}
	return n.Now()
}

func (n *Notifier) log() *slog.Logger {
	if n.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return n.Log
}

func (n *Notifier) glue() time.Duration {
	if n.Glue <= 0 {
		return DefaultGlue
	}
	return n.Glue
}

func (n *Notifier) timeout() time.Duration {
	if n.Timeout <= 0 {
		return DefaultTimeout
	}
	return n.Timeout
}

func (n *Notifier) queueSize() int {
	if n.Queue <= 0 {
		return DefaultQueue
	}
	return n.Queue
}

func (n *Notifier) retry() []time.Duration {
	if n.Retry == nil {
		return DefaultRetry
	}
	return n.Retry
}

func (n *Notifier) quietPoll() time.Duration {
	if n.QuietPoll <= 0 {
		return DefaultQuietPoll
	}
	return n.QuietPoll
}

var defaultHTTP = &http.Client{
	// A redirect would take the signed request elsewhere: an answer.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (n *Notifier) options() senderOptions {
	h := n.HTTP
	if h == nil {
		h = defaultHTTP
	}
	return senderOptions{http: h, tls: n.TLS}
}

// Start loads the enabled channels and starts their workers; they stop
// when ctx ends.
func (n *Notifier) Start(ctx context.Context) {
	n.mu.Lock()
	n.ctx = ctx
	n.mu.Unlock()
	if err := n.Reload(ctx); err != nil && ctx.Err() == nil {
		n.log().Warn("alerts: channels not loaded", "err", err)
	}
	context.AfterFunc(ctx, func() {
		n.mu.Lock()
		for _, w := range n.workers {
			w.stop()
		}
		n.workers = nil
		n.mu.Unlock()
	})
}

// Reload reads the channels again (after the admin changed them): new
// and changed channels get their settings and secret, removed and
// disabled ones stop (with what they had queued).
func (n *Notifier) Reload(ctx context.Context) error {
	list, err := n.Store.ListAlertChannels(ctx)
	if err != nil {
		return err
	}
	type ready struct {
		ch   model.AlertChannel
		send Sender
	}
	var next []ready
	for _, c := range list {
		if !c.Enabled {
			continue
		}
		s, err := n.sender(ctx, c)
		if err != nil {
			n.log().Warn("alerts: channel not ready", "channel", c.Name, "err", err)
			continue
		}
		next = append(next, ready{c, s})
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ctx == nil || n.ctx.Err() != nil {
		return nil // not started, or stopped
	}
	keep := map[int64]bool{}
	if n.workers == nil {
		n.workers = map[int64]*worker{}
	}
	for _, r := range next {
		keep[r.ch.ID] = true
		if w, ok := n.workers[r.ch.ID]; ok {
			w.mu.Lock()
			w.ch, w.send = r.ch, r.send
			w.mu.Unlock()
			continue
		}
		wctx, stop := context.WithCancel(n.ctx)
		w := &worker{n: n, stop: stop, wake: make(chan struct{}, 1), ch: r.ch, send: r.send}
		n.workers[r.ch.ID] = w
		go w.run(wctx)
	}
	for id, w := range n.workers {
		if !keep[id] {
			w.stop()
			delete(n.workers, id)
		}
	}
	return nil
}

// sender opens the channel's secret and builds its sender.
func (n *Notifier) sender(ctx context.Context, c model.AlertChannel) (Sender, error) {
	secret, err := n.secret(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	return newSender(c, secret, n.options())
}

func (n *Notifier) secret(ctx context.Context, id int64) (string, error) {
	sealed, err := n.Store.AlertChannelSecret(ctx, id)
	if err != nil || len(sealed) == 0 {
		return "", err
	}
	if n.Keys == nil {
		return "", errors.New("no master key")
	}
	b, err := n.Keys.Open(sealed, model.AlertSecretContext(id))
	if err != nil {
		return "", err
	}
	if n.Redact != nil {
		n.Redact.Add(string(b))
	}
	return string(b), nil
}

// Notify queues a notice for every channel that wants its kind. It
// never blocks: it is the bus's subscriber.
func (n *Notifier) Notify(x events.Notice) {
	n.mu.Lock()
	ws := make([]*worker, 0, len(n.workers))
	for _, w := range n.workers {
		ws = append(ws, w)
	}
	n.mu.Unlock()
	for _, w := range ws {
		w.push(x)
	}
}

func (w *worker) push(x events.Notice) {
	w.mu.Lock()
	if !w.ch.Wants(x.Event.Kind) {
		w.mu.Unlock()
		return
	}
	w.queue = append(w.queue, x)
	if over := len(w.queue) - w.n.queueSize(); over > 0 {
		w.queue = w.queue[over:]
		w.dropped += over
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// take empties the queue.
func (w *worker) take() ([]events.Notice, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	q, d := w.queue, w.dropped
	w.queue, w.dropped = nil, 0
	return q, d
}

func (w *worker) channel() (model.AlertChannel, Sender) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch, w.send
}

// sleep waits d or until ctx ends (false).
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (w *worker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		}
		// What comes within the window joins the message.
		if !sleep(ctx, w.n.glue()) {
			return
		}
		for {
			ch, _ := w.channel()
			if quiet(ch.Quiet, w.n.now()) {
				// Held: notices gather until the quiet hours end.
				if !sleep(ctx, w.n.quietPoll()) {
					return
				}
				continue
			}
			batch, dropped := w.take()
			if len(batch) == 0 && dropped == 0 {
				break
			}
			if !w.deliver(ctx, batch, dropped) {
				return
			}
		}
	}
}

// deliver sends the notices as one message, again after each pause of
// Retry while it fails; notices that come meanwhile join it. false: ctx
// ended.
func (w *worker) deliver(ctx context.Context, batch []events.Notice, dropped int) bool {
	retry := w.n.retry()
	for attempt := 0; ; attempt++ {
		ch, send := w.channel()
		m := render(batch, dropped, w.n.now())
		sctx, cancel := context.WithTimeout(ctx, w.n.timeout())
		err := send.Send(sctx, m)
		cancel()
		if err == nil {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		if attempt >= len(retry) {
			w.n.log().Warn("alerts: message not sent, given up", "channel", ch.Name, "events", len(batch), "err", w.n.Redact.String(err.Error()))
			return true
		}
		w.n.log().Warn("alerts: message not sent, will retry", "channel", ch.Name, "in", retry[attempt], "err", w.n.Redact.String(err.Error()))
		if !sleep(ctx, retry[attempt]) {
			return false
		}
		more, d := w.take()
		batch, dropped = append(batch, more...), dropped+d
		if over := len(batch) - w.n.queueSize(); over > 0 {
			batch, dropped = batch[over:], dropped+over
		}
	}
}

// Test sends a test message through a channel now (also a disabled
// one), within the timeout. The error says why it did not go, without
// the channel's secret.
func (n *Notifier) Test(ctx context.Context, id int64) error {
	c, err := n.Store.AlertChannelByID(ctx, id)
	if err != nil {
		return err
	}
	secret, err := n.secret(ctx, c.ID)
	if err != nil {
		return err
	}
	s, err := newSender(c, secret, n.options())
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	if err := s.Send(sctx, testMessage(c, n.now())); err != nil {
		red := redact.New()
		red.Add(secret)
		return errors.New(red.String(n.Redact.String(err.Error())))
	}
	return nil
}
