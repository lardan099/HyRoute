package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

type ProfileSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Host     string `json:"host"`
	Obfs     string `json:"obfs"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`
	Pinned   bool   `json:"pinned"`
	// Main: rules without an explicit profile use this one.
	Main bool `json:"main"`
	// Source: "" (manual) or "sub:<id>"; SourceName is the subscription.
	Source     string `json:"source"`
	SourceName string `json:"sourceName"`
	Missing    bool   `json:"missing"`
	// UsedBy lists the rules that send traffic here ("по умолчанию" for
	// the default route).
	UsedBy []string `json:"usedBy"`
}

func (c *Controller) summaryLocked(p *hysteria.Profile) ProfileSummary {
	s := ProfileSummary{ID: p.ID, Name: p.Name, Server: hysteria.ServerString(p.Host, p.Ports), Host: p.Host,
		Obfs: p.Obfs.Type, SNI: p.TLS.SNI, Insecure: p.TLS.Insecure, Pinned: p.TLS.PinSHA256 != "",
		Main: p.ID == c.profiles.Active, Source: p.Source, Missing: p.Missing, UsedBy: c.usedByLocked(p.ID)}
	s.SourceName = c.sourceNameLocked(p.Source)
	return s
}

// usedByLocked lists enabled rules (and the default route) that tunnel
// through profile id, resolving "" to the main profile.
func (c *Controller) usedByLocked(id string) []string {
	out := []string{}
	resolve := func(p string) string {
		if p == "" {
			return c.profiles.Active
		}
		return p
	}
	for i, r := range c.settings.Rules {
		if r.Enabled != nil && !*r.Enabled || r.Action != rules.Tunnel {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("правило %d", i+1)
		}
		if resolve(r.Profile) == id {
			out = append(out, name)
		} else if fallbackHas(r.Fallback, id, resolve) {
			out = append(out, name+" (запасной)")
		}
	}
	if c.settings.DefaultAction == rules.Tunnel {
		if resolve(c.settings.DefaultProfile) == id {
			out = append(out, "по умолчанию")
		} else if fallbackHas(c.settings.DefaultFallback, id, resolve) {
			out = append(out, "по умолчанию (запасной)")
		}
	}
	return out
}

func fallbackHas(fb []string, id string, resolve func(string) string) bool {
	for _, f := range fb {
		if resolve(f) == id {
			return true
		}
	}
	return false
}

// explicitRefsLocked lists Tunnel rules, turned off ones too, that name
// profile id explicitly. A direct or block route never uses its server or
// fallbacks, so a stale one left there pins nothing.
func (c *Controller) explicitRefsLocked(id string) []string {
	var out []string
	same := func(f string) string { return f }
	for i, r := range c.settings.Rules {
		if r.Action != rules.Tunnel {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("правило %d", i+1)
		}
		if r.Profile == id {
			out = append(out, name)
		} else if fallbackHas(r.Fallback, id, same) {
			out = append(out, name+" (запасной сервер)")
		}
	}
	if c.settings.DefaultAction != rules.Tunnel {
		return out
	}
	if c.settings.DefaultProfile == id {
		out = append(out, "маршрут по умолчанию")
	} else if fallbackHas(c.settings.DefaultFallback, id, same) {
		out = append(out, "маршрут по умолчанию (запасной сервер)")
	}
	return out
}

func (c *Controller) Profiles() []ProfileSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []ProfileSummary{}
	for i := range c.profiles.List {
		out = append(out, c.summaryLocked(&c.profiles.List[i]))
	}
	return out
}

// Profile returns the full profile, secrets included (for the editor).
func (c *Controller) Profile(id string) (hysteria.Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.profiles.Find(id); p != nil {
		return *p, nil
	}
	return hysteria.Profile{}, fmt.Errorf("профиль %s не найден", id)
}

type ImportResult struct {
	Added    []ProfileSummary `json:"added"`
	Warnings []string         `json:"warnings"`
	Errors   []string         `json:"errors"`
}

// ImportURIs adds every hysteria2:// / hy2:// link found in text (one per
// line or separated by spaces). The first imported profile becomes the
// main one when there is none.
func (c *Controller) ImportURIs(text string) (ImportResult, error) {
	res := ImportResult{Added: []ProfileSummary{}, Warnings: []string{}, Errors: []string{}}
	parsed := ParseLinks(text)
	res.Warnings, res.Errors = parsed.Warnings, parsed.Errors
	if len(parsed.Profiles) == 0 && len(res.Errors) == 0 {
		return res, errors.New("не найдено ни одной ссылки hysteria2:// или hy2://")
	}
	added := parsed.Profiles
	for i := range added {
		added[i].ID = newID()
	}
	c.mu.Lock()
	next := cloneProfiles(c.profiles)
	next.List = append(next.List, added...)
	if next.Active == "" && len(added) > 0 {
		next.Active = added[0].ID
	}
	err := c.saveProfilesLocked(next)
	if err == nil {
		for i := range added {
			res.Added = append(res.Added, c.summaryLocked(&added[i]))
		}
	}
	c.mu.Unlock()
	c.changed()
	return res, err
}

// saveProfilesLocked stores next, makes it current and re-applies routing
// (a profile edit restarts only that profile's Hysteria).
func (c *Controller) saveProfilesLocked(next *store.Profiles) error {
	if c.profilesBroken != nil {
		return fmt.Errorf("profiles.json не загружен, изменения не сохраняются, чтобы не потерять данные: %v", c.profilesBroken)
	}
	if err := c.Store.SaveProfiles(next); err != nil {
		return err
	}
	c.profiles = next
	c.updateNamesLocked()
	c.applyRoutingLocked()
	return nil
}

// SaveProfile creates (empty ID) or replaces a profile.
func (c *Controller) SaveProfile(p hysteria.Profile) (ProfileSummary, error) {
	p.Host = strings.Trim(strings.TrimSpace(p.Host), "[]")
	p.Ports = strings.TrimSpace(p.Ports)
	if p.Ports == "" {
		p.Ports = "443"
	}
	if err := p.Validate(); err != nil {
		return ProfileSummary{}, err
	}
	if p.Name == "" {
		p.Name = p.Host
	}
	c.mu.Lock()
	next := cloneProfiles(c.profiles)
	if p.ID == "" {
		p.ID = newID()
		p.Source, p.Missing = "", false
		next.List = append(next.List, p)
	} else if old := next.Find(p.ID); old != nil {
		// The editor does not own the bookkeeping fields.
		p.Source, p.Missing = old.Source, old.Missing
		*old = p
	} else {
		c.mu.Unlock()
		return ProfileSummary{}, fmt.Errorf("профиль %s не найден", p.ID)
	}
	if next.Active == "" {
		next.Active = p.ID
	}
	err := c.saveProfilesLocked(next)
	sum := c.summaryLocked(&p)
	c.mu.Unlock()
	c.changed()
	return sum, err
}

// DeleteProfile refuses while a rule or a local proxy names the profile:
// it would otherwise silently refuse its traffic.
func (c *Controller) DeleteProfile(id string) error {
	c.mu.Lock()
	if refs := c.explicitRefsLocked(id); len(refs) > 0 {
		c.mu.Unlock()
		return fmt.Errorf("профиль используется: %s. Выберите в этих правилах другой профиль", strings.Join(refs, ", "))
	}
	if refs := c.proxyRefsLocked(id); len(refs) > 0 {
		c.mu.Unlock()
		return fmt.Errorf("профиль используется: %s. Выберите в этих прокси другой сервер", strings.Join(refs, ", "))
	}
	next := cloneProfiles(c.profiles)
	for i := range next.List {
		if next.List[i].ID == id {
			next.List = append(next.List[:i], next.List[i+1:]...)
			break
		}
	}
	if next.Active == id {
		next.Active = ""
		if len(next.List) > 0 {
			next.Active = next.List[0].ID
		}
	}
	err := c.saveProfilesLocked(next)
	c.mu.Unlock()
	c.changed()
	return err
}

// SetMain selects the profile used by Tunnel rules without an explicit
// profile. It applies at once: new flows of those rules use it.
func (c *Controller) SetMain(id string) error {
	c.mu.Lock()
	if c.profiles.Find(id) == nil {
		c.mu.Unlock()
		return fmt.Errorf("профиль %s не найден", id)
	}
	next := cloneProfiles(c.profiles)
	next.Active = id
	err := c.saveProfilesLocked(next)
	c.mu.Unlock()
	if err == nil {
		c.Log.Info("main profile changed: rules without an explicit profile use it for new connections")
	}
	c.changed()
	return err
}

// MoveProfile reorders the list.
func (c *Controller) MoveProfile(id string, to int) error {
	c.mu.Lock()
	next := cloneProfiles(c.profiles)
	from := -1
	for i := range next.List {
		if next.List[i].ID == id {
			from = i
		}
	}
	if from < 0 || to < 0 || to >= len(next.List) {
		c.mu.Unlock()
		return errors.New("bad move")
	}
	p := next.List[from]
	next.List = append(next.List[:from], next.List[from+1:]...)
	next.List = append(next.List[:to], append([]hysteria.Profile{p}, next.List[to:]...)...)
	err := c.saveProfilesLocked(next)
	c.mu.Unlock()
	c.changed()
	return err
}

// ExportURI returns the share link (secrets included).
func (c *Controller) ExportURI(id string) (string, error) {
	p, err := c.Profile(id)
	if err != nil {
		return "", err
	}
	return p.URI(), nil
}

func cloneProfiles(p *store.Profiles) *store.Profiles {
	return &store.Profiles{Active: p.Active, List: append([]hysteria.Profile(nil), p.List...)}
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
