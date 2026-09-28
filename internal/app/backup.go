package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// Backup and restore (*.hyroute). The files on disk cannot be copied to
// another computer or Windows account: the secrets in them are sealed
// with DPAPI for this user. A backup carries them sealed with a password
// instead.
//
//	full   servers (with passwords), subscriptions (with links), rules and
//	       routing options, local proxies, preferences; always encrypted
//	rules  rules and routing options only: nothing secret, not encrypted
//
// Traffic statistics, logs, subscription history and downloaded databases
// are not included.

const (
	backupFormat  = "hyroute-backup"
	backupVersion = 1
	backupKDF     = "pbkdf2-sha256"
	// backupMinPassword: the shortest password a full backup takes.
	backupMinPassword = 8
	// backupMaxSize: a larger file is not a backup.
	backupMaxSize = 32 << 20
)

// backupIter is the PBKDF2 iteration count of new backups (tests lower it).
var backupIter = 600_000

type backupFile struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	Kind    string    `json:"kind"` // full | rules
	Created time.Time `json:"created"`
	App     string    `json:"app,omitempty"`
	// Sealed holds the payload of an encrypted backup, Data a plain one.
	Sealed *backupSeal     `json:"sealed,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type backupSeal struct {
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Box   []byte `json:"box"` // AES-256-GCM
}

type backupPayload struct {
	Settings      json.RawMessage `json:"settings"`
	Profiles      *store.Profiles `json:"profiles,omitempty"`
	Subscriptions []backupSub     `json:"subscriptions,omitempty"`
	Proxies       []backupProxy   `json:"proxies,omitempty"`
	Prefs         *store.Prefs    `json:"prefs,omitempty"`
}

// store.Subscription and store.LocalProxy keep their secret out of JSON.
type backupSub struct {
	store.Subscription
	URL string `json:"url"`
}

type backupProxy struct {
	store.LocalProxy
	Password string `json:"password,omitempty"`
}

// Backup builds a backup: full with a password, else rules only.
func (c *Controller) Backup(full bool, password string) ([]byte, error) {
	if full && utf8.RuneCountInString(password) < backupMinPassword {
		return nil, fmt.Errorf("пароль копии — не короче %d символов: в ней пароли серверов и ссылки подписок", backupMinPassword)
	}
	c.mu.Lock()
	if full && (c.profilesBroken != nil || c.subsBroken != nil || c.proxiesBroken != nil) {
		c.mu.Unlock()
		return nil, errors.New("часть настроек не загрузилась (см. сообщение на главной): полная копия была бы неполной")
	}
	if c.settingsBroken != nil {
		c.mu.Unlock()
		return nil, errors.New("settings.json не загрузился: в копию попали бы правила по умолчанию, а не ваши")
	}
	st, err := json.Marshal(c.settings)
	var p backupPayload
	p.Settings = st
	if full {
		p.Profiles = &store.Profiles{Active: c.profiles.Active, List: slices.Clone(c.profiles.List)}
		for _, s := range c.subs {
			p.Subscriptions = append(p.Subscriptions, backupSub{Subscription: s, URL: s.URL})
		}
		for _, x := range c.proxies {
			p.Proxies = append(p.Proxies, backupProxy{LocalProxy: x, Password: x.Password})
		}
		prefs := c.prefs
		prefs.SkipVersion = "" // this computer's choice
		p.Prefs = &prefs
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	f := backupFile{Format: backupFormat, Version: backupVersion, Kind: "rules", Created: time.Now().UTC(), App: c.Version}
	if !full {
		f.Data = data
		return json.MarshalIndent(f, "", "  ")
	}
	f.Kind = "full"
	seal := &backupSeal{KDF: backupKDF, Iter: backupIter, Salt: make([]byte, 16)}
	rand.Read(seal.Salt)
	gcm, err := backupCipher(password, seal)
	if err != nil {
		return nil, err
	}
	seal.Nonce = make([]byte, gcm.NonceSize())
	rand.Read(seal.Nonce)
	seal.Box = gcm.Seal(nil, seal.Nonce, data, backupAAD(f))
	f.Sealed = seal
	return json.MarshalIndent(f, "", "  ")
}

func backupCipher(password string, s *backupSeal) (cipher.AEAD, error) {
	if s.KDF != backupKDF || s.Iter < 1000 || s.Iter > 10_000_000 || len(s.Salt) < 8 {
		return nil, errors.New("копия зашифрована неизвестным способом: возможно, её сделала более новая версия HyRoute")
	}
	key, err := pbkdf2.Key(sha256.New, password, s.Salt, s.Iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// backupAAD binds the header to the sealed payload.
func backupAAD(f backupFile) []byte {
	return fmt.Appendf(nil, "%s/%d/%s", f.Format, f.Version, f.Kind)
}

// BackupInfo describes a backup before it is restored.
type BackupInfo struct {
	Kind      string    `json:"kind"` // full | rules
	Created   time.Time `json:"created"`
	App       string    `json:"app"`
	Encrypted bool      `json:"encrypted"`
	// Rules is the number of rules (known before the password only for a
	// rules backup, -1 otherwise).
	Rules int `json:"rules"`
}

func parseBackup(b []byte) (backupFile, error) {
	var f backupFile
	if len(b) > backupMaxSize {
		return f, errors.New("это не копия HyRoute: файл слишком большой")
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if err := json.Unmarshal(b, &f); err != nil || f.Format != backupFormat {
		return f, errors.New("это не копия HyRoute")
	}
	if f.Version > backupVersion {
		return f, errors.New("копию сделала более новая версия HyRoute: обновите HyRoute и попробуйте снова")
	}
	switch {
	case f.Kind == "full" && f.Sealed != nil:
	case f.Kind == "rules" && (f.Data != nil || f.Sealed != nil):
	default:
		return f, errors.New("копия повреждена")
	}
	return f, nil
}

// InspectBackup reads a backup's header.
func (c *Controller) InspectBackup(b []byte) (BackupInfo, error) {
	f, err := parseBackup(b)
	if err != nil {
		return BackupInfo{}, err
	}
	info := BackupInfo{Kind: f.Kind, Created: f.Created, App: f.App, Encrypted: f.Sealed != nil, Rules: -1}
	if f.Sealed == nil {
		if p, err := openBackup(f, ""); err == nil {
			var st settings.Settings
			if json.Unmarshal(p.Settings, &st) == nil {
				info.Rules = len(st.Rules)
			}
		}
	}
	return info, nil
}

func openBackup(f backupFile, password string) (backupPayload, error) {
	var p backupPayload
	data := []byte(f.Data)
	if f.Sealed != nil {
		if password == "" {
			return p, errors.New("введите пароль копии")
		}
		gcm, err := backupCipher(password, f.Sealed)
		if err != nil {
			return p, err
		}
		if len(f.Sealed.Nonce) != gcm.NonceSize() {
			return p, errors.New("копия повреждена")
		}
		data, err = gcm.Open(nil, f.Sealed.Nonce, f.Sealed.Box, backupAAD(f))
		if err != nil {
			return p, errors.New("неверный пароль или копия повреждена")
		}
	}
	if err := json.Unmarshal(data, &p); err != nil || p.Settings == nil {
		return p, errors.New("копия повреждена")
	}
	if f.Kind == "full" && p.Profiles == nil {
		return p, errors.New("копия повреждена: в ней нет серверов")
	}
	return p, nil
}

// RestoreResult says what a restore did.
type RestoreResult struct {
	Kind          string `json:"kind"`
	Rules         int    `json:"rules"`
	Profiles      int    `json:"profiles"`
	Subscriptions int    `json:"subscriptions"`
	Proxies       int    `json:"proxies"`
	// Remapped: rules (and «всё остальное») whose server is not among the
	// servers here: they now go through the main server.
	Remapped int `json:"remapped"`
}

// RestoreBackup replaces the current state with the backup's: everything
// for a full one, the rules and routing options for a rules one. HyRoute
// must be disconnected.
func (c *Controller) RestoreBackup(b []byte, password string) (RestoreResult, error) {
	var res RestoreResult
	f, err := parseBackup(b)
	if err != nil {
		return res, err
	}
	p, err := openBackup(f, password)
	if err != nil {
		return res, err
	}
	st, _, err := settings.Parse(p.Settings)
	if err != nil {
		return res, fmt.Errorf("правила в копии не читаются: %v", err)
	}
	res.Kind = f.Kind
	c.mu.Lock()
	ksWas := c.settings.KillSwitchOn()
	c.mu.Unlock()
	res, written, geoChanged, err := c.restore(f, p, st, res)
	if !written {
		return res, err
	}
	// As a settings save does (commitWith's post), with no lock held.
	c.mu.Lock()
	ksNow := c.settings.KillSwitchOn()
	c.mu.Unlock()
	if ksNow != ksWas {
		c.applyKillSwitch()
	}
	if geoChanged {
		c.pokeGeo()
	}
	if c.OnSettings != nil {
		c.OnSettings(c.settingsRev.Load())
	}
	c.changed()
	c.Log.Info("backup restored", "kind", f.Kind, "rules", res.Rules, "profiles", res.Profiles, "subscriptions", res.Subscriptions)
	return res, err
}

// restore writes the backup's files and loads them. written: something
// on disk changed (also when it failed half way).
func (c *Controller) restore(f backupFile, p backupPayload, st *settings.Settings, res RestoreResult) (_ RestoreResult, written, geoChanged bool, _ error) {
	full := f.Kind == "full"
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	busy := c.sess != nil || c.starting
	known := map[string]bool{}
	list := c.profiles.List
	if full {
		list = p.Profiles.List
	}
	for _, pr := range list {
		known[pr.ID] = true
	}
	oldSubs := slices.Clone(c.subs)
	oldGeo := c.prefs.GeoSource + "\n" + c.prefs.GeoSiteURL + "\n" + c.prefs.GeoIPURL
	skip := c.prefs.SkipVersion
	c.mu.Unlock()
	if busy {
		return res, false, false, errors.New("сначала отключите VPN: восстановление заменит серверы и правила, которыми он сейчас пользуется")
	}

	if full {
		if err := checkRestoredProfiles(p.Profiles.List); err != nil {
			return res, false, false, err
		}
	}
	res.Remapped = remapProfiles(&st.Config, known)

	if full {
		profiles := &store.Profiles{Active: p.Profiles.Active, List: p.Profiles.List}
		if profiles.List == nil {
			profiles.List = []hysteria.Profile{}
		}
		if profiles.Find(profiles.Active) == nil {
			profiles.Active = ""
			if len(profiles.List) > 0 {
				profiles.Active = profiles.List[0].ID
			}
		}
		subs := make([]store.Subscription, 0, len(p.Subscriptions))
		for _, s := range p.Subscriptions {
			s.Subscription.URL = s.URL
			s.HasPrevious = false // its history stays on the old computer
			subs = append(subs, s.Subscription)
		}
		proxies := make([]store.LocalProxy, 0, len(p.Proxies))
		for _, x := range p.Proxies {
			x.LocalProxy.Password = x.Password
			proxies = append(proxies, x.LocalProxy)
		}
		if err := c.Store.SaveProfiles(profiles); err != nil {
			return res, false, false, err
		}
		if err := c.Store.SaveSubscriptions(subs); err != nil {
			return c.reloadAfter(res, err)
		}
		for _, s := range oldSubs {
			c.Store.DeleteSnapshots(s.ID)
		}
		if err := c.Store.SaveProxies(proxies); err != nil {
			return c.reloadAfter(res, err)
		}
		if p.Prefs != nil {
			prefs := *p.Prefs
			prefs.SkipVersion = skip
			if err := c.Store.SavePrefs(prefs); err != nil {
				return c.reloadAfter(res, err)
			}
		}
		res.Profiles, res.Subscriptions, res.Proxies = len(profiles.List), len(subs), len(proxies)
	}
	if _, err := c.Store.SaveSettings(st); err != nil {
		if full {
			return c.reloadAfter(res, err)
		}
		return res, false, false, err
	}
	res.Rules = len(st.Rules)
	loadErr := c.Load()
	c.mu.Lock()
	newGeo := c.prefs.GeoSource + "\n" + c.prefs.GeoSiteURL + "\n" + c.prefs.GeoIPURL
	c.mu.Unlock()
	return res, true, newGeo != oldGeo, loadErr
}

// reloadAfter: a full restore failed after some files were written; what
// is on disk now is loaded, so memory and disk agree.
func (c *Controller) reloadAfter(res RestoreResult, err error) (RestoreResult, bool, bool, error) {
	c.Load()
	return res, true, false, fmt.Errorf("восстановление прервалось: %v. Часть настроек уже заменена копией — повторите восстановление", err)
}

func checkRestoredProfiles(list []hysteria.Profile) error {
	seen := map[string]bool{}
	for _, p := range list {
		if p.ID == "" || seen[p.ID] {
			return errors.New("копия повреждена: у серверов повторяются ID")
		}
		seen[p.ID] = true
	}
	return nil
}

// remapProfiles points rules at servers that are not here to the main one
// ("") and drops such fallbacks; it returns how many routes changed.
func remapProfiles(cfg *rules.Config, known map[string]bool) int {
	n := 0
	fix := func(profile *string, fb *[]string) {
		changed := false
		if *profile != "" && !known[*profile] {
			*profile, changed = "", true
		}
		keep := (*fb)[:0]
		for _, id := range *fb {
			if id == "" || known[id] {
				keep = append(keep, id)
			} else {
				changed = true
			}
		}
		*fb = keep
		if changed {
			n++
		}
	}
	for i := range cfg.Rules {
		fix(&cfg.Rules[i].Profile, &cfg.Rules[i].Fallback)
	}
	fix(&cfg.DefaultProfile, &cfg.DefaultFallback)
	return n
}
