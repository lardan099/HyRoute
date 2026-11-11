package app

import (
	"fmt"
	"sync/atomic"

	"github.com/lardan099/hyroute/internal/zapret"
)

// What the tray menu shows besides the state and the rule profiles: the
// main server, to change it without the window, and the DPI bypass, to
// turn it off and on. Light reads, as RulesetsBrief: the tray asks on
// every change of the state.

// ServersBrief is the servers and groups for the tray: c.mu only.
type ServersBrief struct {
	// Main is the main server or group ("" = none chosen).
	Main string
	List []ServerBriefItem
}

type ServerBriefItem struct {
	ID string
	// Name as the lists show it: a server named like another one with
	// where it comes from.
	Name    string
	Group   bool
	Missing bool // gone from its subscription: not to be chosen
}

// ServersBrief lists the servers, then the groups, for the tray.
func (c *Controller) ServersBrief() ServersBrief {
	c.mu.Lock()
	b := ServersBrief{Main: c.mainTargetLocked()}
	for _, p := range c.profiles.List {
		b.List = append(b.List, ServerBriefItem{ID: p.ID, Missing: p.Missing})
	}
	if c.groupsBroken == nil {
		for _, g := range c.groupsFile.Groups {
			b.List = append(b.List, ServerBriefItem{ID: g.ID, Group: true})
		}
	}
	c.mu.Unlock()
	for i := range b.List {
		b.List[i].Name = c.profileName(b.List[i].ID)
	}
	return b
}

// ZapretBrief is the DPI bypass for the tray.
type ZapretBrief struct {
	// Shown: there is something to switch (services are chosen, the
	// settings loaded, the bypass can run here).
	Shown   bool
	Enabled bool
	// Targets: the services chosen, as the page names them.
	Targets []string
}

// zapretBriefState is the Controller's part for ZapretBrief.
type zapretBriefState struct {
	// zapretBrief is the last answer: an apply or a pick holds zapretMu
	// for long, and the tray must not wait for it. zapretBriefWait: a
	// goroutine waits for zapretMu to tell the tray to ask again.
	zapretBrief     atomic.Pointer[ZapretBrief]
	zapretBriefWait atomic.Bool
}

// ZapretBrief never waits for an apply or a pick under way: it answers
// with what it saw last (nothing shown before the first read). The change
// that holds zapretMu reports itself before it lets go (SaveZapret calls
// changed with the lock held), so the answer may be the one from before
// it: once the lock is free the controller reports a change again, and
// the tray asks anew.
func (c *Controller) ZapretBrief() ZapretBrief {
	if !c.zapretMu.TryLock() {
		if c.zapretBriefWait.CompareAndSwap(false, true) {
			go func() {
				c.zapretMu.Lock()
				c.zapretBriefWait.Store(false)
				c.zapretMu.Unlock()
				c.changed()
			}()
		}
		if b := c.zapretBrief.Load(); b != nil {
			return *b
		}
		return ZapretBrief{}
	}
	defer c.zapretMu.Unlock()
	b := ZapretBrief{Enabled: c.zapretCfg.Enabled}
	for _, t := range zapret.Targets {
		for _, have := range c.zapretCfg.Targets {
			if have == t {
				b.Targets = append(b.Targets, zapret.TargetName(t))
			}
		}
	}
	b.Shown = c.ZapretPrepare != nil && c.zapretErr == nil && len(b.Targets) > 0
	c.zapretBrief.Store(&b)
	return b
}

// SetZapretEnabled turns the DPI bypass on or off with its settings as
// they are (the tray's switch; the page saves the whole of them).
func (c *Controller) SetZapretEnabled(on bool) error {
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	if c.zapretErr != nil {
		return fmt.Errorf("zapret.json не загружен, изменения не сохраняются: %v", c.zapretErr)
	}
	if c.zapretCfg.Enabled == on {
		return nil
	}
	next := c.zapretCfg
	next.Enabled = on
	if err := c.Store.SaveZapret(next); err != nil {
		return err
	}
	c.zapretCfg = next
	c.Log.Info("zapret: switched from the tray", "on", on)
	c.zapretApplyLocked()
	c.changed()
	return nil
}
