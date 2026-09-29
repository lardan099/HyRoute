package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/store"
)

// «Резервная копия» (backup.md): the whole configuration in one
// .hyroute-backup file (internal/backup), restored section by section after
// a preview and a plan the user confirms (backup_plan.go), written with a
// byte-exact rollback (backup_commit.go) and an undo of the last restore
// (restore-undo.sealed). The API works on bytes: only the GUI shows dialogs
// and touches the user's file (store.WriteUserFile / ReadUserFile).
// HyRoute 1.2.0's .hyroute files are read too, never written.

// ---- Go↔TS contract ----

type BackupAppearance struct {
	Theme  string `json:"theme"`  // system|light|dark|midnight
	Accent string `json:"accent"` // blue|violet|teal|orange|pink|rainbow
}

// BackupSectionInfo is a row of the export dialog.
type BackupSectionInfo struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Empty     bool   `json:"empty"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Default   bool   `json:"default"`
}

type BackupExportOptions struct {
	Sections   []string          `json:"sections"`
	Password   string            `json:"password"` // "" = without secrets
	Appearance *BackupAppearance `json:"appearance"`
}

type BackupItem struct {
	Text      string `json:"text"`
	Sensitive bool   `json:"sensitive"` // masked as «***» in Privacy mode
}

type BackupSectionPreview struct {
	Key     string       `json:"key"`
	Title   string       `json:"title"`
	Detail  string       `json:"detail"`
	Items   []BackupItem `json:"items"` // ≤ 50
	More    int          `json:"more"`  // items not listed
	Modes   []string     `json:"modes"` // ["replace","add"] or ["replace"]
	Default bool         `json:"default"`
	Error   string       `json:"error,omitempty"`  // not importable
	Broken  string       `json:"broken,omitempty"` // current file failed to load (text for the note)
}

type BackupPreview struct {
	Token    string                 `json:"token"`
	FileName string                 `json:"fileName"`
	App      string                 `json:"app"`
	Created  time.Time              `json:"created"`
	Secrets  bool                   `json:"secrets"`
	Newer    bool                   `json:"newer"`
	Legacy   bool                   `json:"legacy"` // a HyRoute 1.2.0 .hyroute file
	Sections []BackupSectionPreview `json:"sections"`
	Unknown  []string               `json:"unknown"`
}

type BackupOpened struct {
	Token     string         `json:"token"` // "" = cancelled (GUI)
	FileName  string         `json:"fileName"`
	Encrypted bool           `json:"encrypted"`
	Preview   *BackupPreview `json:"preview"` // set when not encrypted
}

type BackupChoice struct {
	Sections map[string]string `json:"sections"` // key → "replace" | "add"
}

// BackupPart is a piece of a plan text; S marks what Privacy mode replaces
// with «***» (SSIDs, Windows network names, file paths) — hide() alone
// does not know them.
type BackupPart struct {
	T string `json:"t"`
	S bool   `json:"s,omitempty"`
}

// BackupMsg is a plan line or warning: Text is the plain full text (tests,
// no logging), Parts the same text split for masking.
type BackupMsg struct {
	Key   string       `json:"key"` // section key, "" = general
	Text  string       `json:"text"`
	Parts []BackupPart `json:"parts"`
}

type BackupPlan struct {
	Lines    []BackupMsg `json:"lines"`
	Warnings []BackupMsg `json:"warnings"`
	Error    string      `json:"error,omitempty"` // selection cannot be applied
	// Digest (planDigest) is what ApplyBackup requires: the plan the user
	// saw is the plan applied.
	Digest string `json:"digest"`
}

type BackupApplyResult struct {
	Restored       []string          `json:"restored"` // titles
	Warnings       []BackupMsg       `json:"warnings"`
	Appearance     *BackupAppearance `json:"appearance"`
	NeedsReconnect bool              `json:"needsReconnect"`
	Undo           bool              `json:"undo"` // «Вернуть как было» available
}

type BackupUndoInfo struct {
	Available    bool      `json:"available"`
	Created      time.Time `json:"created"`
	FileName     string    `json:"fileName"`
	Sections     []string  `json:"sections"`     // titles
	ChangedSince []string  `json:"changedSince"` // titles whose files changed after the restore
}

// ErrPlanChanged: the plan re-computed under the locks reads differently
// from the one the user confirmed.
var ErrPlanChanged = sentenceError("Настройки изменились, проверьте план ещё раз")

var errBackupClosed = sentenceError("Файл копии закрыт: откройте его ещё раз")

// ---- controller state ----

// backupState is the Controller's backup state.
type backupState struct {
	// importMu serializes ApplyBackup, UndoRestore and ForgetRestoreUndo.
	// Taken first: before the subscription locks, saveMu and mu.
	importMu sync.Mutex
	// backupMu guards backupOpen, the one backup file open for restore, and
	// undoMeta. A leaf: nothing else is taken while it is held.
	backupMu   sync.Mutex
	backupOpen *openBackup
	undoMeta   *undoMeta // cached metadata of restore-undo.sealed; nil = none or not loaded yet
	undoKnown  bool      // undoMeta reflects the file
	// loadNotes (c.mu): each data file's load texts (loadErr).
	loadNotes map[string][]string
	// restoreWriteHook (tests) runs before each file a restore writes; an
	// error fails that write.
	restoreWriteHook func(file string) error
	// backupDrive (tests) replaces GetDriveTypeW.
	backupDrive func(root string) uint32
	// refreshWG counts the post-restore refreshes running (tests wait).
	refreshWG sync.WaitGroup
}

const backupOpenFor = 10 * time.Minute

type openBackup struct {
	token, name string
	file        *backup.File
	payload     *backup.Payload // nil until unlocked
	preview     BackupPreview
	at          time.Time // expires backupOpenFor after the last use
}

// undoRecord is restore-undo.sealed; undoMeta is it without the bytes.
type undoRecord struct {
	Created     time.Time           `json:"created"`
	File        string              `json:"file"`
	Sections    []string            `json:"sections"`
	Files       map[string]undoFile `json:"files"`
	Subs        []string            `json:"subs"`
	OrphanSnaps []string            `json:"orphanSnaps"`
	Appearance  *BackupAppearance   `json:"appearance,omitempty"`
	// Stats: ExportStats() before a restore of «Статистика», handed to
	// ReplaceStats by the undo.
	Stats json.RawMessage `json:"stats,omitempty"`
}

type undoFile struct {
	Exists bool   `json:"exists"`
	Data   []byte `json:"data,omitempty"`
	After  string `json:"after"` // sha256 hex of what the restore wrote
}

type undoMeta struct {
	Created     time.Time
	File        string
	Sections    []string
	After       map[string]string
	Subs        []string
	OrphanSnaps []string
	moved       bool // a post-restore refresh moved an After hash
}

func (r *undoRecord) meta() *undoMeta {
	m := &undoMeta{Created: r.Created, File: r.File, Sections: r.Sections, After: map[string]string{}, Subs: r.Subs, OrphanSnaps: r.OrphanSnaps}
	for n, f := range r.Files {
		m.After[n] = f.After
	}
	return m
}

// clone copies m (nil stays nil); the caller holds backupMu.
func (m *undoMeta) clone() *undoMeta {
	if m == nil {
		return nil
	}
	cp := *m
	cp.After = maps.Clone(m.After)
	return &cp
}

func rawHash(f store.RawFile) string {
	if !f.Exists {
		return "absent"
	}
	h := sha256.Sum256(f.Data)
	return hex.EncodeToString(h[:])
}

func (c *Controller) fileHash(name string) string {
	f, err := c.Store.ReadRaw(name)
	if err != nil {
		return "error"
	}
	return rawHash(f)
}

func (c *Controller) planEnv(real bool) planEnv {
	env := planEnv{newID: newID, driveType: c.backupDrive}
	if env.driveType == nil {
		env.driveType = driveType
	}
	if !real {
		// Display plans: deterministic IDs; texts never show them.
		n := 0
		env.newID = func() string {
			n++
			return fmt.Sprintf("f%011x", n)
		}
	}
	return env
}

func sectionTitles(keys []string) []string {
	out := []string{}
	for _, def := range backupSections {
		if slices.Contains(keys, def.key) {
			out = append(out, def.title)
		}
	}
	return out
}

// ---- export ----

// ExportBackup builds a backup file of the chosen sections.
func (c *Controller) ExportBackup(o BackupExportOptions) ([]byte, error) {
	b, _, err := c.ExportBackupWarn(o)
	return b, err
}

// ExportBackupWarn is ExportBackup with what the user should know about
// the file (statistics left out for size).
func (c *Controller) ExportBackupWarn(o BackupExportOptions) (_ []byte, warnings []BackupMsg, _ error) {
	warnings = []BackupMsg{}
	if len(o.Sections) == 0 {
		return nil, nil, sentenceError("Ничего не выбрано")
	}
	if o.Password != "" && utf8.RuneCountInString(o.Password) < backup.MinPassword {
		return nil, nil, backup.ErrShort
	}
	for _, k := range o.Sections {
		if def := sectionByKey(k); def != nil && def.secret && o.Password == "" {
			return nil, nil, backup.ErrSecrets
		}
	}
	// stats: its own export, before the snapshot and with no Controller
	// lock held (B1b).
	var stats json.RawMessage
	if slices.Contains(o.Sections, "stats") {
		raw, detail, cut, err := c.ExportStats()
		if err != nil {
			return nil, nil, sentencef("Статистика не сохранилась: %v", err)
		}
		stats = raw
		if cut {
			warnings = append(warnings, BackupMsg{Key: "stats", Text: "Статистика в копии неполная: " + detail + ".", Parts: []BackupPart{}})
			c.Log.Warn("backup: oldest statistics left out for size")
		}
	}
	c.mu.Lock()
	st := c.snapshotLocked()
	c.mu.Unlock()
	app := o.Appearance
	if app != nil && (!slices.Contains(themes, app.Theme) || !slices.Contains(accents, app.Accent)) {
		app = nil
	}
	secrets := o.Password != ""
	sections, targets, err := collectSections(st, o.Sections, secrets, app)
	if err != nil {
		return nil, nil, err
	}
	if stats != nil {
		sections["stats"] = stats
	}
	if err := checkLimits(sections, secrets); err != nil {
		return nil, nil, err
	}
	p := &backup.Payload{App: c.Version, Created: time.Now().UTC().Truncate(time.Second), Secrets: secrets, Targets: targets, Sections: sections}
	b, err := backup.Encode(p, o.Password)
	if err != nil {
		return nil, nil, err
	}
	c.Log.Info("backup exported", "sections", strings.Join(o.Sections, ","), "encrypted", secrets)
	return b, warnings, nil
}

// ---- open, unlock, preview ----

// OpenBackup takes the bytes of a file the user picked. A file without a
// password is previewed at once.
func (c *Controller) OpenBackup(fileName string, b []byte) (BackupOpened, error) {
	f, err := backup.Parse(b)
	if err != nil {
		return BackupOpened{}, err
	}
	ob := &openBackup{token: newID(), name: fileName, file: f, at: time.Now()}
	out := BackupOpened{Token: ob.token, FileName: fileName, Encrypted: f.NeedsPassword()}
	if !f.NeedsPassword() {
		pv, err := c.unlock(ob, "")
		if err != nil {
			return BackupOpened{}, err
		}
		out.Preview = &pv
	}
	c.backupMu.Lock()
	c.backupOpen = ob
	c.backupMu.Unlock()
	return out, nil
}

// UnlockBackup opens an encrypted file with its password.
func (c *Controller) UnlockBackup(token, password string) (BackupPreview, error) {
	ob, _, err := c.openedBackup(token, false)
	if err != nil {
		return BackupPreview{}, err
	}
	return c.unlock(ob, password)
}

func (c *Controller) unlock(ob *openBackup, password string) (BackupPreview, error) {
	p, err := ob.file.Open(password) // Argon2 outside every Controller lock
	if err != nil {
		return BackupPreview{}, err
	}
	if p.Legacy != "" {
		if err := legacySections(p); err != nil {
			return BackupPreview{}, err
		}
	}
	if len(p.Sections) == 0 {
		return BackupPreview{}, sentenceError("В копии нет данных, которые можно восстановить")
	}
	pv := c.previewOf(ob, p)
	c.backupMu.Lock()
	defer c.backupMu.Unlock()
	if ob.payload != nil {
		// A second unlock (a double click, a retry) keeps the first: the
		// payload a plan was made from never changes under it.
		return ob.preview, nil
	}
	ob.payload, ob.preview, ob.at = p, pv, time.Now()
	return pv, nil
}

// openedBackup is the open file of token and its payload, read under
// backupMu (unlocked: the payload must be there).
func (c *Controller) openedBackup(token string, unlocked bool) (*openBackup, *backup.Payload, error) {
	c.backupMu.Lock()
	defer c.backupMu.Unlock()
	ob := c.backupOpen
	if ob == nil || ob.token != token || time.Since(ob.at) > backupOpenFor || unlocked && ob.payload == nil {
		if ob != nil && time.Since(ob.at) > backupOpenFor {
			c.backupOpen = nil
		}
		return nil, nil, errBackupClosed
	}
	ob.at = time.Now()
	return ob, ob.payload, nil
}

// CloseBackup drops the open file of token.
func (c *Controller) CloseBackup(token string) {
	c.backupMu.Lock()
	if c.backupOpen != nil && c.backupOpen.token == token {
		c.backupOpen = nil
	}
	c.backupMu.Unlock()
}

func (c *Controller) previewOf(ob *openBackup, p *backup.Payload) BackupPreview {
	// stats: checked by its own store, with no Controller lock held.
	var statsDetail string
	var statsErr error
	if raw, ok := p.Sections["stats"]; ok && p.Secrets && p.Errors["stats"] == "" {
		statsDetail, statsErr = c.CheckStatsImport(raw)
	}
	c.mu.Lock()
	st := c.snapshotLocked()
	c.mu.Unlock()
	d := decodeSections(p)
	pv := BackupPreview{Token: ob.token, FileName: ob.name, App: p.App, Created: p.Created, Secrets: p.Secrets,
		Legacy: p.Legacy != "", Unknown: slices.Clone(p.Unknown), Sections: []BackupSectionPreview{}}
	if pv.Unknown == nil {
		pv.Unknown = []string{}
	}
	pv.Newer = release.Compare(p.App, c.Version) > 0 || len(d.unknown) > 0 // top-level Unknown has its own note
	for _, def := range backupSections {
		if _, ok := p.Sections[def.key]; !ok {
			continue
		}
		s := BackupSectionPreview{Key: def.key, Title: def.title, Items: []BackupItem{}, Modes: slices.Clone(def.modes), Default: def.defaultOn}
		items := []BackupItem{}
		item := func(t string, sens bool) { items = append(items, BackupItem{Text: t, Sensitive: sens}) }
		if e := d.errs[def.key]; e != "" {
			s.Error, s.Default = e, false
		}
		switch def.key {
		case "servers":
			if d.servers != nil {
				s.Detail = nServers(len(d.servers.List))
				for _, x := range d.servers.List {
					item(x.Name, false)
				}
			}
		case "subscriptions":
			if d.subs != nil {
				s.Detail = nSubs(len(d.subs)) + ", " + nServers(subServers(d.subs))
				for _, x := range d.subs {
					item(x.Name+" — "+maskedHost(x.URL), false)
					items[len(items)-1].Sensitive = true
				}
			}
		case "groups":
			if d.groups != nil {
				s.Detail = nGroups(len(d.groups.Groups))
				for _, g := range d.groups.Groups {
					item(g.Name, false)
				}
			}
		case "rules":
			if d.rules != nil {
				if d.rulesets != nil {
					n := 0
					if a := d.rulesets.Find(d.rulesets.Active); a != nil {
						n = len(a.Config.Rules)
					}
					s.Detail = nRules(n) + " · " + nProfiles(len(d.rulesets.List))
					for _, e := range d.rulesets.List {
						item(e.Name, false)
					}
				} else {
					s.Detail = nRules(len(d.rules.Config.Rules))
					for _, r := range d.rules.Config.Rules {
						item(r.Name, false)
					}
				}
			}
		case "proxies":
			if d.proxies != nil {
				s.Detail = plural(len(d.proxies), "прокси", "прокси", "прокси")
				for _, x := range d.proxies {
					item(fmt.Sprintf("%s (порт %d)", x.Name, x.Port), false)
				}
			}
		case "settings":
			if d.settings != nil {
				var parts []string
				if d.settings.Engine != nil {
					parts = append(parts, "параметры маршрутизации и kill switch")
				}
				if d.settings.Prefs != nil {
					parts = append(parts, "журнал, обновления и запуск")
				}
				s.Detail = strings.Join(parts, "; ")
			}
		case "geo":
			if g := d.geo; g != nil {
				s.Detail = geoDetail(g.GeoSource, g.GeoSource == "custom", g.GeoAutoOff == nil || !*g.GeoAutoOff, g.GeoIntervalHours)
			}
		case "appearance":
			if a := d.appearance; a != nil {
				s.Detail = "тема «" + orDash(themeNames[a.Theme]) + "», акцент «" + orDash(accentNames[a.Accent]) + "»"
			}
		case "networks":
			if n := d.net; n != nil {
				s.Detail = nNetRules(len(n.Rules))
				if !n.Enabled {
					s.Detail += ", выключены"
				}
				for _, r := range n.Rules {
					item(r.Name, true) // often a Wi-Fi or network name
				}
			}
		case "dns":
			if v := d.dns; v != nil {
				s.Detail = dnsDetail(*v)
			}
		case "stats":
			s.Detail = statsDetail
			if statsErr != nil && s.Error == "" {
				s.Error, s.Default = sectionErr(statsErr), false
			}
		}
		if len(items) > 50 {
			s.More = len(items) - 50
			items = items[:50]
		}
		s.Items = items
		for _, f := range def.files {
			if def.key == "settings" || def.key == "geo" {
				break // their broken files are covered by the plan's own checks
			}
			if err := st.Broken[f]; err != nil && (f != "rulesets.json" || d.rulesets != nil) {
				s.Broken = fmt.Sprintf("Сейчас %s не загружен (%v). «Заменить» заменит его, а копия старого файла останется рядом как %s.broken-%s.", f, err, f, time.Now().Format("20060102-150405"))
				s.Modes = []string{"replace"}
			}
		}
		pv.Sections = append(pv.Sections, s)
	}
	for _, k := range d.unknown {
		pv.Sections = append(pv.Sections, BackupSectionPreview{Key: k, Title: k, Items: []BackupItem{}, Modes: []string{},
			Error: "Неизвестный раздел «" + k + "» — сделан более новой версией HyRoute, будет пропущен"})
	}
	return pv
}

// ---- plan ----

// PlanBackup describes what a restore of the choice would change.
func (c *Controller) PlanBackup(token string, ch BackupChoice) (BackupPlan, error) {
	_, p, err := c.openedBackup(token, true)
	if err != nil {
		return BackupPlan{}, err
	}
	env := c.planEnv(false)
	env.statsDetail, env.statsErr = c.checkStats(p, ch)
	c.mu.Lock()
	st := c.snapshotLocked()
	c.mu.Unlock()
	pl := planRestore(st, p, ch, env)
	return planView(pl), nil
}

// checkStats runs CheckStatsImport on the file's «Статистика» when it is
// chosen (no Controller lock held: B1b).
func (c *Controller) checkStats(p *backup.Payload, ch BackupChoice) (string, error) {
	raw, ok := p.Sections["stats"]
	if ch.Sections["stats"] == "" || !ok || !p.Secrets {
		return "", nil
	}
	return c.CheckStatsImport(raw)
}

func planView(pl *restorePlan) BackupPlan {
	v := BackupPlan{Lines: pl.lines, Warnings: pl.warnings, Error: pl.err, Digest: planDigest(pl)}
	if v.Lines == nil {
		v.Lines = []BackupMsg{}
	}
	if v.Warnings == nil {
		v.Warnings = []BackupMsg{}
	}
	return v
}

// ---- apply ----

// lockRestore takes the subscription locks (the IDs of now, plus extra),
// then prefsMu (cli: no UpdatePrefs reads the old prefs.json and writes it
// over the restored one), saveMu and mu; it retries while a subscription
// appears meanwhile. unlockCfg releases mu, saveMu and prefsMu, unlockSubs
// the subscription locks.
func (c *Controller) lockRestore(extra []string) (unlockCfg, unlockSubs func(), err error) {
	for range 3 {
		c.mu.Lock()
		ids := slices.Clone(extra)
		for _, s := range c.subs {
			ids = append(ids, s.ID)
		}
		c.mu.Unlock()
		slices.Sort(ids)
		ids = slices.Compact(ids)
		var unlocks []func()
		for _, id := range ids {
			unlocks = append(unlocks, c.lockSub(id))
		}
		subs := func() {
			for _, u := range slices.Backward(unlocks) {
				u()
			}
		}
		c.prefsMu.Lock()
		c.saveMu.Lock()
		c.mu.Lock()
		ok := true
		for _, s := range c.subs {
			if !slices.Contains(ids, s.ID) {
				ok = false
			}
		}
		if ok {
			return func() { c.mu.Unlock(); c.saveMu.Unlock(); c.prefsMu.Unlock() }, subs, nil
		}
		c.mu.Unlock()
		c.saveMu.Unlock()
		c.prefsMu.Unlock()
		subs()
	}
	return nil, nil, sentenceError("Подписки изменились во время восстановления, повторите")
}

func (c *Controller) loadUndoRecord() (*undoRecord, []byte, error) {
	b, err := c.Store.LoadRestoreUndo()
	if err != nil {
		return nil, nil, err
	}
	var r undoRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, err
	}
	return &r, b, nil
}

// ApplyBackup restores the choice, provided the plan still reads as the
// one the user confirmed (digest).
func (c *Controller) ApplyBackup(token string, ch BackupChoice, cur BackupAppearance, digest string) (BackupApplyResult, error) {
	c.importMu.Lock()
	defer c.importMu.Unlock()
	ob, p, err := c.openedBackup(token, true)
	if err != nil {
		return BackupApplyResult{}, err
	}
	// stats (B1b): checked, and the current statistics kept for the undo,
	// before any other lock.
	env := c.planEnv(true)
	env.statsDetail, env.statsErr = c.checkStats(p, ch)
	var undoStats, stats json.RawMessage
	if raw, ok := p.Sections["stats"]; ok && ch.Sections["stats"] != "" && env.statsErr == nil {
		cur, _, cut, err := c.ExportStats()
		if err != nil {
			return BackupApplyResult{}, sentencef("Восстановление не выполнено, ничего не изменено: не удалось запомнить текущие настройки для «Вернуть как было»: %v", err)
		}
		if cut {
			// «Вернуть как было» would put back only what fit and delete
			// the rest.
			return BackupApplyResult{}, sentenceError("Восстановление не выполнено, ничего не изменено: текущая статистика слишком большая, чтобы её можно было вернуть кнопкой «Вернуть как было». Снимите «Статистику» в списке разделов или удалите старую статистику")
		}
		undoStats, stats = cur, raw
	}
	prev, prevBytes, prevErr := c.loadUndoRecord()
	if prevErr != nil && !errors.Is(prevErr, os.ErrNotExist) {
		prev, prevBytes = nil, nil
	}
	extra := []string{}
	d := decodeSections(p)
	for _, s := range d.subs {
		if importIDRe.MatchString(s.ID) {
			extra = append(extra, s.ID)
		}
	}
	if prev != nil {
		extra = append(extra, prev.OrphanSnaps...)
	}
	unlockCfg, unlockSubs, err := c.lockRestore(extra)
	if err != nil {
		return BackupApplyResult{}, err
	}
	cfgLocked := true
	defer func() {
		if cfgLocked {
			unlockCfg()
		}
		unlockSubs()
	}()
	st := c.snapshotLocked()
	pl := planRestore(st, p, ch, env)
	if pl.err != "" {
		return BackupApplyResult{}, errors.New(pl.err)
	}
	if digest == "" || planDigest(pl) != digest {
		return BackupApplyResult{}, ErrPlanChanged
	}
	before := map[string]store.RawFile{}
	files := slices.Clone(pl.writes)
	if slices.Contains(files, "settings.json") && !slices.Contains(files, "rulesets.json") {
		files = append(files, "rulesets.json") // a pair may write it: the undo holds both
	}
	for _, f := range files {
		raw, err := c.Store.ReadRaw(f)
		if err != nil {
			return BackupApplyResult{}, sentencef("Восстановление не выполнено, ничего не изменено: %v", err)
		}
		before[f] = raw
	}
	rec := &undoRecord{Created: time.Now().UTC().Truncate(time.Millisecond), File: ob.name, Sections: pl.sections,
		Files: map[string]undoFile{}, Subs: []string{}, OrphanSnaps: slices.Clone(pl.removedSubs)}
	for _, s := range st.Subs {
		rec.Subs = append(rec.Subs, s.ID)
	}
	if rec.OrphanSnaps == nil {
		rec.OrphanSnaps = []string{}
	}
	for f, raw := range before {
		rec.Files[f] = undoFile{Exists: raw.Exists, Data: raw.Data}
	}
	if pl.appearance != nil {
		a := cur
		rec.Appearance = &a
	}
	rec.Stats = undoStats
	if err := c.saveUndo(rec); err != nil {
		return BackupApplyResult{}, sentencef("Восстановление не выполнено, ничего не изменено: не удалось запомнить текущие настройки для «Вернуть как было»: %v", err)
	}
	for k, v := range pl.redact {
		c.Redactor.SetGroup(k, v...)
	}
	res, rbErr, err := c.commitRestoreLocked(pl, before)
	if err != nil {
		if rbErr != nil {
			// Files may have changed: the new record holds the exact bytes of
			// before, so «Вернуть как было» can still put them back.
			c.setUndoMeta(rec.meta())
			return BackupApplyResult{}, sentencef("Восстановление прервано: %v. Часть файлов могла измениться — нажмите «Вернуть как было» в «Настройках»", err)
		}
		c.Store.DeleteRestoreUndo()
		if prevBytes != nil {
			c.Store.SaveRestoreUndo(prevBytes)
		}
		return BackupApplyResult{}, sentencef("Восстановление не выполнено, ничего не изменено: %v", err)
	}
	for f, u := range rec.Files {
		u.After = c.fileHash(f)
		rec.Files[f] = u
	}
	if err := c.saveUndo(rec); err != nil {
		c.Log.Warn("restore: the undo record's hashes not saved", "err", err)
	}
	c.setUndoMeta(rec.meta())
	unlockCfg()
	cfgLocked = false
	// Still holding the subscription locks: the snapshots of the
	// subscriptions the previous restore removed live as long as its undo.
	if prev != nil {
		c.mu.Lock()
		ids := c.subIDsLocked()
		c.mu.Unlock()
		for _, id := range prev.OrphanSnaps {
			if !slices.Contains(ids, id) && !slices.Contains(rec.OrphanSnaps, id) {
				c.Store.DeleteSnapshots(id)
			}
		}
	}
	unlockSubs()
	unlockSubs = func() {}

	warns := slices.Clone(pl.warnings)
	warns = append(warns, c.afterRestore(pl.writes, pl.ksChange != 0, res, stats)...)
	c.Log.Info("restored from backup", "sections", strings.Join(pl.sections, ","), "modes", fmt.Sprint(ch.Sections),
		"servers", pl.counts.servers, "rules", pl.counts.rules)
	if len(pl.refreshSubs) > 0 {
		c.refreshWG.Add(1)
		go func() {
			defer c.refreshWG.Done()
			c.refreshAfterRestore(pl.refreshSubs, rec.Created)
		}()
	}
	c.CloseBackup(token)
	out := BackupApplyResult{Restored: sectionTitles(pl.sections), Warnings: warns, Appearance: pl.appearance,
		NeedsReconnect: res.needsReconnect, Undo: true}
	if out.Warnings == nil {
		out.Warnings = []BackupMsg{}
	}
	return out, nil
}

func (c *Controller) subIDsLocked() []string {
	ids := make([]string, 0, len(c.subs))
	for _, s := range c.subs {
		ids = append(ids, s.ID)
	}
	return ids
}

func (c *Controller) saveUndo(r *undoRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return c.Store.SaveRestoreUndo(b)
}

func (c *Controller) setUndoMeta(m *undoMeta) {
	c.backupMu.Lock()
	c.undoMeta, c.undoKnown = m, true
	c.backupMu.Unlock()
}

// afterRestore is the post step of a restore and of its undo, with no
// lock held: as after the same edits in the UI. stats: the statistics to
// put in place (nil = none). It returns the result's warnings.
func (c *Controller) afterRestore(writes []string, ksChanged bool, res commitResult, stats json.RawMessage) []BackupMsg {
	var warns []BackupMsg
	has := func(f string) bool { return slices.Contains(writes, f) }
	if has("proxies.json") || has("profiles.json") {
		c.syncProxiesLife()
	}
	if ksChanged {
		c.applyKillSwitch()
	}
	if has("prefs.json") {
		c.applyLogPrefs()
	}
	if has("settings.json") || has("rulesets.json") || has("prefs.json") {
		c.pokeGeo() // geoDue decides: a restored rule may need a database
	}
	// dns: one flush at most (cached answers followed the old settings).
	switch {
	case res.dnsWritten:
		c.flushDNSAsync("backup")
	case res.flushRules:
		c.flushDNSAsync("rules")
	}
	if res.dnsErr != nil {
		warns = append(warns, msg("dns").t("Настройки DNS восстановлены, но не применены: "+res.dnsErr.Error()).m)
	}
	if stats != nil {
		if err := c.ReplaceStats(stats); err != nil {
			warns = append(warns, msg("stats").t("Статистика не восстановлена: "+err.Error()).m)
		}
	}
	if has("settings.json") || has("rulesets.json") {
		// conn-rules: an «Отменить» of a rule made before must not touch
		// the restored rules by ID.
		c.clearConnUndo()
	}
	c.changed()
	if res.settingsWrote && c.OnSettings != nil {
		c.OnSettings(c.SettingsRev())
	}
	return warns
}

// ---- undo ----

// RestoreUndoInfo describes «Вернуть как было».
func (c *Controller) RestoreUndoInfo() BackupUndoInfo {
	info := BackupUndoInfo{Sections: []string{}, ChangedSince: []string{}}
	if c.cachedUndoMeta() == nil {
		return info
	}
	// Under c.mu: a post-restore refresh writes its files and moves After
	// under it, so the hashes and After read as one state (a copy: the
	// refresh writes the shared map under backupMu).
	c.mu.Lock()
	c.backupMu.Lock()
	m := c.undoMeta.clone()
	c.backupMu.Unlock()
	if m == nil {
		c.mu.Unlock()
		return info
	}
	changed := map[string]bool{}
	for f, after := range m.After {
		if c.fileHash(f) != after {
			changed[f] = true
		}
	}
	c.mu.Unlock()
	info.Available, info.Created, info.FileName, info.Sections = true, m.Created, m.File, sectionTitles(m.Sections)
	for _, def := range backupSections {
		if !slices.Contains(m.Sections, def.key) {
			continue
		}
		for _, f := range def.files {
			if changed[f] {
				info.ChangedSince = append(info.ChangedSince, def.title)
				break
			}
		}
	}
	return info
}

// cachedUndoMeta loads the record's metadata once (one unseal). It returns
// a copy: a post-restore refresh moves the shared After under backupMu
// (restoreHashesAfterLocked) while the caller reads it unlocked.
func (c *Controller) cachedUndoMeta() *undoMeta {
	c.backupMu.Lock()
	m, known := c.undoMeta.clone(), c.undoKnown
	c.backupMu.Unlock()
	if known {
		return m
	}
	r, _, err := c.loadUndoRecord()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.Log.Warn("restore-undo.sealed not read", "err", err)
		}
		c.setUndoMeta(nil)
		return nil
	}
	m = r.meta()
	c.backupMu.Lock()
	if !c.undoKnown {
		c.undoMeta, c.undoKnown = m, true
	}
	m = c.undoMeta.clone()
	c.backupMu.Unlock()
	return m
}

// UndoRestore puts back the files of the last restore exactly as they were.
func (c *Controller) UndoRestore() (BackupApplyResult, error) {
	c.importMu.Lock()
	defer c.importMu.Unlock()
	rec, _, err := c.loadUndoRecord()
	if errors.Is(err, os.ErrNotExist) {
		return BackupApplyResult{}, errNothingToUndo
	}
	if err != nil {
		return BackupApplyResult{}, sentencef("Вернуть не удалось: %v", err)
	}
	unlockCfg, unlockSubs, err := c.lockRestore(rec.Subs)
	if err != nil {
		return BackupApplyResult{}, err
	}
	var names []string
	for _, f := range restoreWrites {
		if _, ok := rec.Files[f]; ok {
			names = append(names, f)
		}
	}
	now := map[string]store.RawFile{}
	for _, f := range names {
		raw, err := c.Store.ReadRaw(f)
		if err != nil {
			unlockCfg()
			unlockSubs()
			return BackupApplyResult{}, sentencef("Вернуть не удалось, ничего не изменено: %v", err)
		}
		now[f] = raw
	}
	var done []string
	for _, f := range names {
		u := rec.Files[f]
		if err := c.Store.WriteRaw(f, store.RawFile{Exists: u.Exists, Data: u.Data}); err != nil {
			// As commitRestoreLocked: a file that cannot be put back is
			// broken in memory, so no save overwrites the mixed state; the
			// record stays for another try.
			var rbErr error
			for _, g := range slices.Backward(done) {
				if rerr := c.Store.WriteRaw(g, now[g]); rerr != nil {
					if rbErr == nil {
						rbErr = rerr
					}
					c.markBrokenLocked(g, fmt.Errorf("файл изменён частично при возврате: %v", rerr))
				}
			}
			unlockCfg()
			unlockSubs()
			if rbErr != nil {
				return BackupApplyResult{}, sentencef("Вернуть не удалось: %v. Часть файлов могла измениться — нажмите «Вернуть как было» ещё раз", err)
			}
			return BackupApplyResult{}, sentencef("Вернуть не удалось, ничего не изменено: %v", err)
		}
		done = append(done, f)
	}
	subsBefore := c.subIDsLocked()
	ksWas := c.settings.KillSwitchOn()
	res := c.reloadRawLocked(names)
	ksNow := c.settings.KillSwitchOn()
	var refresh []string
	if !slices.Contains(names, "subscriptions.json") {
		for _, s := range c.subs {
			if s.Enabled && !slices.ContainsFunc(c.profiles.List, func(p hysteria.Profile) bool { return p.Source == "sub:"+s.ID }) {
				refresh = append(refresh, s.ID)
			}
		}
	}
	subsAfter := c.subIDsLocked()
	c.Store.DeleteRestoreUndo()
	c.setUndoMeta(nil)
	unlockCfg()
	for _, id := range subsBefore {
		if !slices.Contains(subsAfter, id) {
			c.Store.DeleteSnapshots(id) // added by the restore
		}
	}
	unlockSubs()
	warns := c.afterRestore(names, ksWas != ksNow, res, rec.Stats)
	if warns == nil {
		warns = []BackupMsg{}
	}
	c.Log.Info("restore undone", "sections", strings.Join(rec.Sections, ","))
	if len(refresh) > 0 {
		c.refreshWG.Add(1)
		go func() {
			defer c.refreshWG.Done()
			for _, id := range refresh {
				c.UpdateSubscription(id)
			}
		}()
	}
	return BackupApplyResult{Restored: sectionTitles(rec.Sections), Warnings: warns, Appearance: rec.Appearance,
		NeedsReconnect: res.needsReconnect}, nil
}

// ForgetRestoreUndo drops the undo record (and the snapshots of the
// subscriptions only it could bring back).
func (c *Controller) ForgetRestoreUndo() error {
	c.importMu.Lock()
	defer c.importMu.Unlock()
	rec, _, err := c.loadUndoRecord()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if rec != nil {
		ids := slices.Clone(rec.OrphanSnaps)
		slices.Sort(ids)
		var unlocks []func()
		for _, id := range ids {
			unlocks = append(unlocks, c.lockSub(id))
		}
		c.mu.Lock()
		cur := c.subIDsLocked()
		c.mu.Unlock()
		for _, id := range ids {
			if !slices.Contains(cur, id) {
				c.Store.DeleteSnapshots(id)
			}
		}
		for _, u := range slices.Backward(unlocks) {
			u()
		}
	}
	err = c.Store.DeleteRestoreUndo()
	c.setUndoMeta(nil)
	return err
}

// ---- post-restore refresh ----

// refreshAfterRestore updates the subscriptions a restore brought, one by
// one, as part of that restore: files nothing else touched keep their
// «after» hash in step (changedSince stays exact). It stops once the
// restore is undone, forgotten or replaced.
func (c *Controller) refreshAfterRestore(ids []string, tag time.Time) {
	for _, id := range ids {
		if !c.undoTagged(tag) {
			return
		}
		c.updateSubscription(id, tag)
	}
	c.persistRefreshedAfter(tag)
}

func (c *Controller) undoTagged(tag time.Time) bool {
	c.backupMu.Lock()
	defer c.backupMu.Unlock()
	return c.undoMeta != nil && c.undoMeta.Created.Equal(tag)
}

// restoreHashesLocked (c.mu held, inside applyFetched before its writes):
// the hashes of the two files it writes, when a tagged refresh still
// belongs to the current undo record.
func (c *Controller) restoreHashesLocked(tag time.Time) map[string]string {
	if tag.IsZero() || !c.undoTagged(tag) {
		return nil
	}
	return map[string]string{"profiles.json": c.fileHash("profiles.json"), "subscriptions.json": c.fileHash("subscriptions.json")}
}

// restoreHashesAfterLocked moves the record's «after» of each file that
// nothing but the restore changed (its hash was the record's before the
// refresh wrote it).
func (c *Controller) restoreHashesAfterLocked(tag time.Time, before map[string]string) {
	if before == nil {
		return
	}
	now := map[string]string{}
	for f := range before {
		now[f] = c.fileHash(f)
	}
	c.backupMu.Lock()
	defer c.backupMu.Unlock()
	m := c.undoMeta
	if m == nil || !m.Created.Equal(tag) {
		return
	}
	for f, h := range before {
		if a, ok := m.After[f]; ok && a == h && now[f] != h {
			m.After[f] = now[f]
			m.moved = true
		}
	}
}

// persistRefreshedAfter writes the moved hashes into the sealed record.
func (c *Controller) persistRefreshedAfter(tag time.Time) {
	c.importMu.Lock()
	defer c.importMu.Unlock()
	c.backupMu.Lock()
	m := c.undoMeta
	var after map[string]string
	if m != nil && m.Created.Equal(tag) && m.moved {
		after = maps.Clone(m.After)
		m.moved = false
	}
	c.backupMu.Unlock()
	if after == nil {
		return
	}
	rec, _, err := c.loadUndoRecord()
	if err != nil || !rec.Created.Equal(tag) {
		return
	}
	for f, h := range after {
		if u, ok := rec.Files[f]; ok {
			u.After = h
			rec.Files[f] = u
		}
	}
	if err := c.saveUndo(rec); err != nil {
		c.Log.Warn("restore: the undo record's hashes not saved", "err", err)
	}
}

// backupDiagLine is the diagnostics line of the last restore ("" = none;
// the record is unsealed once, as for RestoreUndoInfo, whether or not the
// card was shown).
func (c *Controller) backupDiagLine() string {
	m := c.cachedUndoMeta()
	if m == nil {
		return ""
	}
	return fmt.Sprintf("   резервная копия: последнее восстановление %s (%s), «Вернуть как было» доступно",
		m.Created.Local().Format("2006-01-02 15:04"), strings.Join(sectionTitles(m.Sections), ", "))
}
