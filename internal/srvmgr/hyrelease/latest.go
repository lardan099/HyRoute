package hyrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Latest is the newest Hysteria release: the tag Releases + "/latest"
// redirects to (app/vX.Y.Z), checked the way a deploy checks a version:
// the release's hashes.txt has the Linux build of the common machine
// (amd64). A version HyRoute pins needs no hashes.txt.
func (r *Resolver) Latest(ctx context.Context) (string, error) {
	url := r.LatestURL
	if url == "" {
		url = Releases + "/latest"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	c := *r.client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось узнать последний релиз Hysteria: %w", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tag := path.Base(loc)
	if resp.StatusCode/100 != 3 || !strings.Contains(loc, "/releases/tag/app/") || CheckVersion(tag) != nil {
		return "", fmt.Errorf("не удалось узнать последний релиз Hysteria: ответ %s", resp.Status)
	}
	if _, err := r.Resolve(ctx, tag, "amd64"); err != nil {
		return "", err
	}
	return tag, nil
}

// Older reports v < than for version tags ("v2.6.0" < "v2.12.3");
// anything that is not a version tag is not older.
func Older(v, than string) bool {
	a, okA := parts(v)
	b, okB := parts(than)
	return okA && okB && slices.Compare(a, b) < 0
}

func parts(v string) ([]int, bool) {
	if CheckVersion(v) != nil {
		return nil, false
	}
	f := strings.Split(v[1:], ".")
	out := make([]int, len(f))
	for i, p := range f {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// Release is the newest Hysteria release the controller knows of.
type Release struct {
	// Version is the tag ("": none found yet).
	Version string `json:"version"`
	// CheckedAt is when it was found; TriedAt the last lookup, which
	// failed with Error when it is later.
	CheckedAt time.Time `json:"checkedAt"`
	TriedAt   time.Time `json:"triedAt"`
	Error     string    `json:"error,omitempty"`
}

// Target is the version servers are brought to: the newest release when
// it is known and newer than DefaultVersion, DefaultVersion otherwise.
func (r Release) Target() string {
	if Older(DefaultVersion, r.Version) {
		return r.Version
	}
	return DefaultVersion
}

// Settings keeps what Watch found across restarts (the settings table).
type Settings interface {
	Setting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string, at time.Time) error
}

// DefaultCheckInterval is how often Watch looks for a new release.
const DefaultCheckInterval = 24 * time.Hour

// settingKey is where Watch keeps the release it found.
const settingKey = "hysteria_release"

// Watch looks for the newest Hysteria release once per Interval (P4-07):
// the overview offers it, and «Требует внимания» calls the Hysteria of a
// server old against it. A failed lookup is tried again after Tick.
type Watch struct {
	// Find looks the release up (Resolver.Latest; tests inject theirs).
	Find     func(ctx context.Context) (string, error)
	Settings Settings // nil: kept in memory only
	Interval time.Duration
	Tick     time.Duration // how often to look whether it is time; an hour if 0
	// Delay is the wait before the first look after a start (a minute if
	// 0): a controller restarting in a loop, or started for a moment,
	// does not ask GitHub every time.
	Delay time.Duration
	Now   func() time.Time
	Log   *slog.Logger

	mu     sync.Mutex
	cur    Release
	loaded bool
}

func (w *Watch) now() time.Time {
	if w.Now == nil {
		return time.Now()
	}
	return w.Now()
}

func (w *Watch) log() *slog.Logger {
	if w.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return w.Log
}

func (w *Watch) interval() time.Duration {
	if w.Interval <= 0 {
		return DefaultCheckInterval
	}
	return w.Interval
}

func (w *Watch) tick() time.Duration {
	if w.Tick <= 0 {
		return time.Hour
	}
	return w.Tick
}

// Latest is what the watch knows now (nil watch: nothing).
func (w *Watch) Latest() Release {
	if w == nil {
		return Release{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// load reads what an earlier process found, once.
func (w *Watch) load(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.loaded || w.Settings == nil {
		w.loaded = true
		return
	}
	w.loaded = true
	v, err := w.Settings.Setting(ctx, settingKey)
	if err != nil {
		return // none yet
	}
	var r Release
	if json.Unmarshal([]byte(v), &r) == nil && (r.Version == "" || CheckVersion(r.Version) == nil) {
		w.cur = r
	}
}

// Due reports whether it is time to look: Interval since the last find,
// and Tick since the last try.
func (w *Watch) Due() bool {
	r, now := w.Latest(), w.now()
	return now.Sub(r.CheckedAt) >= w.interval() && now.Sub(r.TriedAt) >= w.tick()
}

// Run looks whenever it is due, from Delay after the start until ctx
// ends.
func (w *Watch) Run(ctx context.Context) {
	w.load(ctx)
	delay := w.Delay
	if delay <= 0 {
		delay = time.Minute
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	t := time.NewTicker(w.tick())
	defer t.Stop()
	for {
		if w.Due() {
			w.Check(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check looks the release up now. A failure keeps the version found
// before.
func (w *Watch) Check(ctx context.Context) Release {
	w.load(ctx)
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	v, err := w.Find(cctx)
	cancel()
	if err == nil && CheckVersion(v) != nil {
		err = errors.New("неверная версия " + strconv.Quote(v))
	}
	if ctx.Err() != nil {
		return w.Latest() // stopping: not a try
	}
	now := w.now()
	w.mu.Lock()
	r := w.cur
	r.TriedAt = now
	if err != nil {
		r.Error = err.Error()
	} else {
		if v != r.Version {
			w.log().Info("hysteria release found", "version", v)
		}
		r.Version, r.CheckedAt, r.Error = v, now, ""
	}
	w.cur = r
	w.mu.Unlock()
	if err != nil {
		w.log().Warn("hysteria release: lookup failed", "err", err)
	}
	if w.Settings != nil {
		b, _ := json.Marshal(r)
		if serr := w.Settings.SetSetting(context.WithoutCancel(ctx), settingKey, string(b), now); serr != nil {
			w.log().Warn("hysteria release: not saved", "err", serr)
		}
	}
	return r
}
