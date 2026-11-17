package app

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

// MigrateBrowserRules gives old domain rules a Chrome condition before
// the first connection after upgrade. Rules and profiles use the normal
// paired save. The preference is written only after that save succeeds.
func (c *Controller) MigrateBrowserRules() (int, error) {
	c.prefsMu.Lock()
	var post func()
	defer func() {
		c.prefsMu.Unlock()
		if post != nil {
			post()
		}
	}()
	prefs := c.Prefs()
	if prefs.BrowserRulesMigrated {
		return 0, nil
	}
	browser := "chrome.exe"
	if runtime.GOOS == "darwin" {
		browser = "google chrome"
	}
	c.saveMu.Lock()
	count, post, err := c.scopeSavedBrowserRules(browser)
	c.saveMu.Unlock()
	if err != nil {
		return 0, err
	}
	prefs.BrowserRulesMigrated = true
	return count, c.savePrefs(prefs)
}

// scopeSavedBrowserRules runs under saveMu and prefsMu, before startup
// hooks can connect. A backup of all rules makes the change reversible.
func (c *Controller) scopeSavedBrowserRules(browser string) (int, func(), error) {
	c.mu.Lock()
	blocked := c.settingsBroken
	if blocked == nil {
		blocked = c.rulesetsBroken
	}
	if blocked == nil {
		blocked = c.prefsBroken
	}
	st := *c.settings
	st.Config = store.CloneConfig(st.Config)
	profiles := c.rulesets.Clone()
	c.mu.Unlock()
	if blocked != nil {
		return 0, nil, blocked
	}

	count := scopeBrowserDestinationRules(&st.Config, browser)
	if profiles != nil {
		for i := range profiles.List {
			profile := &profiles.List[i]
			if profile.ID != profiles.Active && !profile.Newer() && checkRules(profile.Config) == nil {
				count += scopeBrowserDestinationRules(&profile.Config, browser)
			}
		}
	}
	if count == 0 {
		return 0, nil, nil
	}

	old, err := c.Store.ReadRaw(store.BrowserRulesBackup)
	if err != nil {
		return 0, nil, err
	}
	if !old.Exists {
		b, err := c.ExportBackup(BackupExportOptions{Sections: []string{"rules"}})
		if err != nil {
			return 0, nil, fmt.Errorf("резервная копия правил: %w", err)
		}
		if err := c.Store.WriteRaw(store.BrowserRulesBackup, store.RawFile{Exists: true, Data: b}); err != nil {
			return 0, nil, fmt.Errorf("резервная копия правил: %w", err)
		}
	}
	_, post, err := c.commitSettingsLocked(st, profiles)
	if err != nil {
		return 0, nil, err
	}
	return count, post, nil
}

func scopeBrowserDestinationRules(cfg *rules.Config, browser string) int {
	count := 0
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if len(r.AllApps()) != 0 || isZapretRule(*r) {
			continue
		}
		for _, domain := range r.AllDomains() {
			if rules.IsAddressItem(domain) {
				continue
			}
			if isBrowserRule(*r) {
				name := strings.TrimSuffix(r.Name, browserHostsSuffix) + browserAppSuffix(browser)
				if browserHostsRule(*r) {
					name += browserHostsSuffix
				}
				r.Name = name
			}
			r.Apps = browserAppMatches(browser)
			count++
			break
		}
	}
	return count
}
