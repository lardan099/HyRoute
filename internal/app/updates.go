package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/update"
)

// Updater wires the release checks into the controller.
type Updater struct {
	// Repo is HyRoute's GitHub repository ("owner/name"); empty disables
	// self-update.
	Repo string
	// Dir is the protected staging directory for HyRoute packages.
	Dir    string
	Core   *core.Manager
	Client *release.Client

	mu    sync.Mutex
	state UpdatesState
	app   *update.Available
	core  *core.Update
	// coreSess is the session that ran when the core changed: its
	// profiles keep the old core until a reconnect replaces it.
	coreSess Session
}

// UpdatesState is shown in the UI.
type UpdatesState struct {
	Current  string    `json:"current"`
	Dev      bool      `json:"dev"` // build without a release tag
	Repo     string    `json:"repo"`
	Checked  time.Time `json:"checked"`
	Checking bool      `json:"checking"`

	App         *update.Available `json:"app"`
	AppError    string            `json:"appError"`
	AppStage    string            `json:"appStage"` // "" | downloading | ready
	AppProgress float64           `json:"appProgress"`
	AppSkipped  bool              `json:"appSkipped"` // user chose "Позже" for this version

	Core            core.Info    `json:"core"`
	CoreUpdate      *core.Update `json:"coreUpdate"`
	CoreError       string       `json:"coreError"`
	CoreBusy        bool         `json:"coreBusy"`
	CoreProgress    float64      `json:"coreProgress"`
	CoreNeedsReconn bool         `json:"coreNeedsReconnect"`

	staging string
}

// IsDev reports builds that are not a release (no "vX.Y.Z" tag).
func IsDev(v string) bool {
	p, err := release.Parse(v)
	return err != nil || strings.Contains(p.Pre, "dev") || strings.Contains(p.Pre, "-g")
}

func (c *Controller) Updates() UpdatesState {
	u := c.Updater
	if u == nil {
		return UpdatesState{Current: c.Version, Dev: IsDev(c.Version)}
	}
	u.mu.Lock()
	st := u.state
	coreSess := u.coreSess
	u.mu.Unlock()
	if st.CoreNeedsReconn {
		// After a reconnect or a disconnect no profile runs the old core.
		c.mu.Lock()
		st.CoreNeedsReconn = c.sess != nil && c.sess == coreSess
		c.mu.Unlock()
		if !st.CoreNeedsReconn {
			u.set(func(s *UpdatesState) {
				if u.coreSess == coreSess {
					s.CoreNeedsReconn, u.coreSess = false, nil
				}
			})
		}
	}
	st.Current, st.Dev, st.Repo = c.Version, IsDev(c.Version), u.Repo
	if u.Core != nil {
		st.Core = u.Core.Info()
	}
	if st.App != nil {
		st.AppSkipped = c.Prefs().SkipVersion == st.App.Version
	}
	return st
}

func (u *Updater) set(f func(*UpdatesState)) {
	u.mu.Lock()
	f(&u.state)
	u.mu.Unlock()
}

// CheckUpdates looks for a newer HyRoute and a newer Hysteria core.
func (c *Controller) CheckUpdates() UpdatesState {
	u := c.Updater
	if u == nil {
		return c.Updates()
	}
	u.set(func(s *UpdatesState) { s.Checking = true })
	c.changed()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if u.Repo == "" {
			u.set(func(s *UpdatesState) {
				s.AppError = "в этой сборке не задан репозиторий обновлений"
			})
			return
		}
		a, ok, err := update.Check(ctx, u.Client, u.Repo, c.Version, c.channel())
		u.set(func(s *UpdatesState) {
			s.AppError = ""
			if err != nil {
				s.AppError = err.Error()
			}
			if ok {
				if s.App == nil || s.App.Version != a.Version {
					s.AppStage, s.AppProgress = "", 0
				}
				s.App = &a
			} else if err == nil {
				s.App, s.AppStage = nil, ""
			}
		})
		if ok {
			c.Log.Info("HyRoute update available", "current", c.Version, "new", a.Version)
		}
	}()
	go func() {
		defer wg.Done()
		if u.Core == nil {
			return
		}
		cu, ok, err := u.Core.Check(ctx)
		u.set(func(s *UpdatesState) {
			s.CoreError = ""
			if err != nil {
				s.CoreError = err.Error()
			}
			if ok {
				s.CoreUpdate = &cu
			} else if err == nil {
				s.CoreUpdate = nil
			}
		})
		if ok {
			c.Log.Info("Hysteria core update available", "new", cu.Version)
		}
	}()
	wg.Wait()
	u.set(func(s *UpdatesState) { s.Checking, s.Checked = false, time.Now() })
	c.changed()
	return c.Updates()
}

func (c *Controller) channel() string {
	if ch := c.Prefs().UpdateChannel; ch != "" {
		return ch
	}
	return "stable"
}

// InstallCore downloads and activates the offered Hysteria core. Running
// profiles keep their process; new starts use the new core.
func (c *Controller) InstallCore() error {
	u := c.Updater
	if u == nil || u.Core == nil {
		return errors.New("обновление ядра недоступно")
	}
	u.mu.Lock()
	cu := u.state.CoreUpdate
	if cu == nil || u.state.CoreBusy {
		u.mu.Unlock()
		return errors.New("нет доступного обновления ядра")
	}
	u.state.CoreBusy, u.state.CoreProgress, u.state.CoreError = true, 0, ""
	u.mu.Unlock()
	c.changed()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	err := u.Core.Install(ctx, *cu, func(done, total int64) {
		if total > 0 {
			u.set(func(s *UpdatesState) { s.CoreProgress = float64(done) / float64(total) })
		}
	})
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	u.set(func(s *UpdatesState) {
		s.CoreBusy = false
		if err != nil {
			s.CoreError = err.Error()
			return
		}
		s.CoreUpdate, s.CoreNeedsReconn, u.coreSess = nil, sess != nil, sess
	})
	if err != nil {
		c.Log.Error("Hysteria core update failed, the current core stays", "err", err)
	} else {
		c.Log.Info("Hysteria core updated: profiles use it from their next start", "version", cu.Version)
		c.refreshKillSwitchApps()
	}
	c.changed()
	return err
}

// RollbackCore returns to the previous Hysteria core.
func (c *Controller) RollbackCore() error {
	u := c.Updater
	if u == nil || u.Core == nil {
		return errors.New("обновление ядра недоступно")
	}
	if err := u.Core.Rollback(); err != nil {
		return err
	}
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	u.set(func(s *UpdatesState) { s.CoreNeedsReconn, u.coreSess = sess != nil, sess })
	c.Log.Info("Hysteria core rolled back", "version", u.Core.Info().Version)
	c.refreshKillSwitchApps()
	c.changed()
	return nil
}

// refreshKillSwitchApps: the block lets HyRoute's programs through, and a
// core update or rollback moves hysteria.exe. An installed block (armed or
// blocking) lets the new core through now, not only after the next Arm:
// a server check or a new profile starts it at once.
func (c *Controller) refreshKillSwitchApps() {
	ks, ok := c.KillSwitch.(interface{ RefreshApps() error })
	if !ok {
		return
	}
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	if !c.ks.blocks {
		return
	}
	if err := ks.RefreshApps(); err != nil {
		c.Log.Error("kill switch: the new Hysteria core is not let through while the internet is closed", "err", err)
	}
}

// DownloadAppUpdate downloads and verifies the offered HyRoute package.
func (c *Controller) DownloadAppUpdate() error {
	u := c.Updater
	if u == nil {
		return errors.New("обновление недоступно")
	}
	u.mu.Lock()
	a := u.state.App
	if a == nil || u.state.AppStage == "downloading" {
		u.mu.Unlock()
		return errors.New("нет доступного обновления")
	}
	u.state.AppStage, u.state.AppProgress, u.state.AppError = "downloading", 0, ""
	u.mu.Unlock()
	c.changed()
	if err := core.ProtectDir(u.Dir); err != nil {
		u.set(func(s *UpdatesState) { s.AppStage, s.AppError = "", err.Error() })
		c.changed()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	dir, err := update.Stage(ctx, u.Client, *a, u.Dir, func(done, total int64) {
		if total > 0 {
			u.set(func(s *UpdatesState) { s.AppProgress = float64(done) / float64(total) })
		}
	})
	u.set(func(s *UpdatesState) {
		if err != nil {
			s.AppStage, s.AppError = "", err.Error()
			return
		}
		s.AppStage, s.staging = "ready", dir
	})
	if err != nil {
		c.Log.Error("HyRoute update download failed", "err", err)
	} else {
		c.Log.Info("HyRoute update downloaded and verified", "version", a.Version)
	}
	c.changed()
	return err
}

// ReadyUpdate returns the verified staging directory and its version.
func (c *Controller) ReadyUpdate() (dir, version string, err error) {
	u := c.Updater
	if u == nil {
		return "", "", errors.New("обновление недоступно")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state.AppStage != "ready" || u.state.App == nil {
		return "", "", errors.New("обновление ещё не скачано")
	}
	if _, err := update.Verify(u.state.staging); err != nil {
		u.state.AppStage = ""
		return "", "", fmt.Errorf("скачанное обновление повреждено: %w", err)
	}
	return u.state.staging, u.state.App.Version, nil
}

// SkipAppVersion is "Позже": no startup prompt for this version.
func (c *Controller) SkipAppVersion(v string) error {
	p := c.Prefs()
	p.SkipVersion = v
	return c.SavePrefs(p)
}

// RunUpdateChecks checks at start (after a delay) and every 12 hours when
// automatic checks are on. Development builds only check on request.
func (c *Controller) RunUpdateChecks(ctx context.Context) {
	auto := func() bool {
		m := c.Prefs().UpdateCheck
		return m == "auto" || (m == "" && !IsDev(c.Version))
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}
	if auto() {
		c.CheckUpdates()
	}
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if auto() {
				c.CheckUpdates()
			}
		}
	}
}
