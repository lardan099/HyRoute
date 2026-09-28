package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Source is where the databases come from.
type Source struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Short       string `json:"short"` // "runetfreedom": shown next to every list
	Description string `json:"description"`
	Site        string `json:"site"` // geosite.dat URL
	IP          string `json:"ip"`   // geoip.dat URL
	Size        string `json:"size"` // rough download size, for the UI
}

const gh = "https://github.com/"

// Sources are the presets; "custom" takes the URLs from preferences.
var Sources = []Source{
	{
		ID:          "runetfreedom",
		Name:        "Россия — runetfreedom",
		Short:       "runetfreedom",
		Description: "Всё из v2fly плюс списки для России: ru-blocked (заблокированное РКН), ru-available-only-inside (работает только из России). Обновляется каждые 6 часов.",
		Site:        gh + "runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
		IP:          gh + "runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
		Size:        "≈ 90 МБ",
	},
	{
		ID:          "loyalsoldier",
		Name:        "Loyalsoldier",
		Short:       "Loyalsoldier",
		Description: "v2fly с дополнениями (реклама, трекеры, Китай). Без российских списков блокировок. Обновляется ежедневно.",
		Site:        gh + "Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
		IP:          gh + "Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
		Size:        "≈ 28 МБ",
	},
	{
		ID:          "v2fly",
		Name:        "v2fly (официальные)",
		Short:       "v2fly",
		Description: "Исходные списки проекта v2fly: сервисы, страны, реклама. Самые компактные.",
		Site:        gh + "v2fly/domain-list-community/releases/latest/download/dlc.dat",
		IP:          gh + "v2fly/geoip/releases/latest/download/geoip.dat",
		Size:        "≈ 26 МБ",
	},
	{
		ID:          "hysteria-geodata",
		Name:        "hysteria-geodata (lardan099)",
		Short:       "hysteria-geodata",
		Description: "Сборка для серверов Hysteria: v2fly, geoip от Loyalsoldier и списки RoscomVPN (whitelist, category-geoblock-ru, torrent, geoip:direct). Те же списки, что на сервере с этими базами. Без ru-blocked.",
		Site:        gh + "lardan099/hysteria-geodata/releases/latest/download/geosite.dat",
		IP:          gh + "lardan099/hysteria-geodata/releases/latest/download/geoip.dat",
		Size:        "≈ 22 МБ",
	},
}

// DefaultSource is used when nothing is chosen.
const DefaultSource = "runetfreedom"

// URL is the download address of one database ("" when there is none).
func (s Source) URL(k Kind) string {
	if k == IP {
		return s.IP
	}
	return s.Site
}

// FindSource returns a preset.
func FindSource(id string) (Source, bool) {
	for _, s := range Sources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// FileState is one downloaded database.
type FileState struct {
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	Categories int       `json:"categories"`
	Updated    time.Time `json:"updated"` // when this content was installed
	URL        string    `json:"url"`
	Verified   bool      `json:"verified"` // matched the published .sha256sum
	// A rollback put this file in place while the source delivered
	// HeldFor (a URL): scheduled updates leave it and never put back
	// RolledBackFrom (the SHA-256 of the version rolled back from); a
	// manual update or another source ends the hold.
	HeldFor        string `json:"heldFor,omitempty"`
	RolledBackFrom string `json:"rolledBackFrom,omitempty"`
}

// unheld is fs without the rollback hold.
func (fs FileState) unheld() FileState {
	fs.HeldFor, fs.RolledBackFrom = "", ""
	return fs
}

// State is stored in Dir/geo.json.
type State struct {
	// Source is the source of the last update that installed every file
	// it asked for; which source a file belongs to is decided by From.
	Source string     `json:"source"`
	Site   *FileState `json:"site,omitempty"`
	IP     *FileState `json:"ip,omitempty"`
	// Checked is the last attempt, failed or not (the scheduler backs off
	// from it).
	Checked   time.Time `json:"checked"`
	LastError string    `json:"lastError,omitempty"`
}

// From reports whether the installed file of k was downloaded from url.
// A file of another source, or of custom links changed since, is not the
// one the source wants.
func (st State) From(k Kind, url string) bool {
	fs := st.Site
	if k == IP {
		fs = st.IP
	}
	return url != "" && fs != nil && fs.URL == url
}

// Held reports whether the file of k was restored by a rollback while the
// source delivered url: it is not missing for that source, and scheduled
// updates do not undo the rollback.
func (st State) Held(k Kind, url string) bool {
	fs := st.Site
	if k == IP {
		fs = st.IP
	}
	return url != "" && fs != nil && fs.HeldFor == url && fs.RolledBackFrom != ""
}

// Downloader fetches URLs; the default is a plain HTTP client. attempt is
// 0 for the first try and 1 for the retry after a failed download (the app
// retries through the VPN).
type Downloader func(ctx context.Context, url string, attempt int) (*http.Response, error)

// Updater downloads and installs databases into DB.Dir.
type Updater struct {
	DB       *DB
	Download Downloader
	// MaxSize caps a download (default 300 MB).
	MaxSize int64
	// Progress receives (kind, done, total) while downloading.
	Progress func(k Kind, done, total int64)

	mu sync.Mutex // one update at a time
}

func (u *Updater) statePath() string { return filepath.Join(u.DB.Dir, "geo.json") }

// State reads geo.json.
func (u *Updater) State() State {
	var st State
	b, err := readSmall(u.statePath())
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (u *Updater) saveState(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(u.statePath(), b)
}

// readSmall reads a state file through openRead: it refuses links, and
// it shares delete access, so writeFile can replace the file under it.
func readSmall(path string) ([]byte, error) {
	f, err := openRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// writeFile replaces path with b. The folder is writable by every program
// of the user and HyRoute runs elevated, so the data goes to a new file
// with a random name (a fixed one could be a planted link to a file the
// user cannot write), and the rename replaces whatever is at path itself,
// never the target of a link.
func writeFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameRetry(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// renameRetry replaces to with from (a file in the same folder), retrying
// for most of a second: an antivirus or an indexer may hold a file open
// without delete sharing for a moment.
func renameRetry(from, to string) error {
	var err error
	for i := range 5 {
		if i > 0 {
			time.Sleep(time.Duration(25<<i) * time.Millisecond)
		}
		if err = replaceFile(from, to); err == nil {
			return nil
		}
	}
	return err
}

// replaceFile renames from over to, both in the same folder. os.Rename
// (MoveFileEx) cannot replace a file that is open even in a reader that
// shares delete access, as State does all the time (the settings page
// polls it); os.Root renames with POSIX semantics on Windows 10 1709+ and
// NTFS, which can, and falls back to a plain rename elsewhere.
func replaceFile(from, to string) error {
	r, err := os.OpenRoot(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer r.Close()
	return r.Rename(filepath.Base(from), filepath.Base(to))
}

// fileSum returns the SHA-256 of a file on disk.
func fileSum(path string) (string, error) {
	f, err := openRead(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HasPrevious reports whether a rollback is possible.
func (u *Updater) HasPrevious() bool {
	for _, k := range []Kind{Site, IP} {
		if _, err := os.Stat(u.DB.path(k) + ".prev"); err == nil {
			return true
		}
	}
	return false
}

// Result of an update.
type Result struct {
	Changed bool     `json:"changed"`
	Notes   []string `json:"notes"`
}

// Update checks the databases of src that have a URL and installs the
// ones whose published checksum differs from the installed file (force:
// always download). A file is replaced only after its checksum and format
// are verified; the replaced file is kept as .prev for Rollback. It is
// the user's own request: a file held by a rollback is updated too.
func (u *Updater) Update(ctx context.Context, src Source, force bool) (Result, error) {
	return u.update(ctx, src, force, false)
}

// UpdateScheduled is Update for the background schedule: a file restored
// by Rollback is not replaced by the version rolled back from.
func (u *Updater) UpdateScheduled(ctx context.Context, src Source) (Result, error) {
	return u.update(ctx, src, false, true)
}

func (u *Updater) update(ctx context.Context, src Source, force, scheduled bool) (Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := os.MkdirAll(u.DB.Dir, 0o700); err != nil {
		return Result{}, err
	}
	u.removeLeftovers()
	st := u.State()
	var res Result
	var errs []string
	for _, k := range []Kind{Site, IP} {
		url := src.URL(k)
		cur := &st.Site
		if k == IP {
			cur = &st.IP
		}
		if url == "" {
			continue
		}
		// A file of another source (or of changed custom links) is
		// downloaded again: never keep files of the old one, unless the
		// user rolled back to it.
		held := scheduled && st.Held(k, url)
		fs, changed, err := u.updateFile(ctx, k, url, *cur, force || (!held && !st.From(k, url)), held)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k.File(), err))
			continue
		}
		*cur = &fs
		if changed {
			res.Changed = true
			res.Notes = append(res.Notes, fmt.Sprintf("%s обновлён: категорий %d", k.File(), fs.Categories))
		}
	}
	if len(errs) == 0 {
		st.Source = src.ID
	}
	st.Checked = time.Now()
	st.LastError = strings.Join(errs, "; ")
	if err := u.saveState(st); err != nil {
		errs = append(errs, err.Error())
	}
	if res.Changed {
		u.DB.Forget()
	}
	if len(errs) > 0 {
		return res, errors.New(strings.Join(errs, "; "))
	}
	return res, nil
}

// leftovers are the temporary files of an update (see download and
// writeFile), and the fixed names older versions used.
var leftovers = []string{"*.dat.*.new", "geo.json.*.tmp", "*.prev.json.*.tmp", "*.dat.new", "geo.json.tmp"}

// removeLeftovers deletes the temporary files an interrupted update left
// (a crash, or a shutdown during a download): their random names are
// never used again. os.Remove deletes the entry itself, a planted link
// too, never the file it points to. u.mu must be held.
func (u *Updater) removeLeftovers() {
	ents, err := os.ReadDir(u.DB.Dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		for _, pat := range leftovers {
			if ok, _ := filepath.Match(pat, e.Name()); ok {
				_ = os.Remove(filepath.Join(u.DB.Dir, e.Name()))
				break
			}
		}
	}
}

// updateFile installs the file of k from url when it differs from the file
// on disk. held: a scheduled update of a file restored by Rollback, which
// keeps it rather than put back the version rolled back from.
func (u *Updater) updateFile(ctx context.Context, k Kind, url string, cur *FileState, force, held bool) (FileState, bool, error) {
	dst := u.DB.path(k)
	sum := sumURL(url)
	want, sumErr := u.fetchSum(ctx, sum, 0)
	if sumErr != nil && !errors.Is(sumErr, errNoSum) {
		want, sumErr = u.fetchSum(ctx, sum, 1)
	}
	if sumErr != nil && !errors.Is(sumErr, errNoSum) {
		// The file itself would be unverified: do not install it.
		return FileState{}, false, fmt.Errorf("не удалось получить контрольную сумму: %v", sumErr)
	}
	// The file on disk decides, not geo.json: a damaged file (a power cut,
	// a disk error) or one the state does not describe is replaced even by
	// the same version.
	_, statErr := os.Stat(dst)
	disk := ""
	if statErr == nil {
		disk, _ = fileSum(dst)
	}
	described := cur != nil && disk != "" && strings.EqualFold(disk, cur.SHA256)
	// A held file is kept only while it is intact.
	held = held && described
	var keep FileState
	if cur != nil {
		keep = *cur
		if !held {
			keep = keep.unheld()
		}
	}
	if held && want != "" && strings.EqualFold(want, cur.RolledBackFrom) {
		return keep, false, nil // still the version the user rolled back from
	}
	if !force && described && want != "" && strings.EqualFold(want, disk) {
		return keep, false, nil
	}
	tmp, got, size, err := u.download(ctx, k, url, 0)
	if err != nil && ctx.Err() == nil {
		tmp, got, size, err = u.download(ctx, k, url, 1)
	}
	if err != nil {
		return FileState{}, false, err
	}
	defer os.Remove(tmp)
	if want != "" && !strings.EqualFold(got, want) {
		return FileState{}, false, fmt.Errorf("контрольная сумма не совпала (ожидалась %s…, получена %s…): файл не установлен", want[:12], got[:12])
	}
	n, err := Check(tmp)
	if err != nil {
		return FileState{}, false, fmt.Errorf("скачанный файл не похож на базу правил: %v", err)
	}
	if held && strings.EqualFold(got, cur.RolledBackFrom) {
		return keep, false, nil
	}
	if disk != "" && strings.EqualFold(got, disk) {
		// Same content (no .sha256sum published, or the same file at a
		// new URL): keep it, now as the file of url.
		fs := keep
		if !described {
			fs = FileState{SHA256: got, Size: size, Categories: n, Updated: time.Now()}
		}
		fs.URL = url
		fs.Verified = want != ""
		return fs, false, nil
	}
	// The file replaced is kept as .prev for Rollback, unless it is not a
	// database (damaged, or planted): then it is simply replaced, and the
	// .prev there stays the previous version.
	keepPrev := statErr == nil
	if keepPrev && !described {
		_, cerr := Check(dst)
		keepPrev = cerr == nil
	}
	if statErr == nil && !keepPrev {
		if err := renameRetry(tmp, dst); err != nil {
			return FileState{}, false, err
		}
	} else {
		if keepPrev {
			// The rename replaces the old .prev: removing it first would
			// lose it when the rename fails (the file is open in another
			// program).
			if err := os.Rename(dst, dst+".prev"); err != nil {
				return FileState{}, false, err
			}
		}
		if err := os.Rename(tmp, dst); err != nil {
			if keepPrev {
				_ = os.Rename(dst+".prev", dst)
			}
			return FileState{}, false, err
		}
	}
	if keepPrev {
		// .prev.json describes the file now in .prev, or nothing: a stale
		// one would make Rollback describe the restored file wrongly.
		if described {
			writePrevState(dst, *cur)
		} else {
			_ = os.Remove(dst + ".prev.json")
		}
	}
	return FileState{SHA256: got, Size: size, Categories: n, Updated: time.Now(), URL: url, Verified: want != "" && sumErr == nil}, true, nil
}

func writePrevState(dst string, fs FileState) {
	if b, err := json.Marshal(fs.unheld()); err == nil {
		_ = writeFile(dst+".prev.json", b)
	}
}

func (u *Updater) get(ctx context.Context, url string, attempt int) (*http.Response, error) {
	if u.Download != nil {
		return u.Download(ctx, url, attempt)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HyRoute")
	return defaultClient.Do(req)
}

var defaultClient = &http.Client{CheckRedirect: NoDowngrade}

// NoDowngrade is an http.Client CheckRedirect that refuses a redirect from
// https:// to anything else: the checksum comes the same way as the
// database, so over http anyone on the network could swap both.
func NoDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("сервер перенаправил на незащищённый адрес %s://%s, нужна https://…", req.URL.Scheme, req.URL.Host)
	}
	if len(via) >= 10 {
		return errors.New("слишком много перенаправлений")
	}
	return nil
}

var errNoSum = errors.New("контрольная сумма не опубликована")

// sumURL is the address of the checksum next to a file: the suffix goes
// into the path, not into the query ("…/geosite.dat?raw=true" →
// "…/geosite.dat.sha256sum?raw=true").
func sumURL(file string) string {
	u, err := neturl.Parse(file)
	if err != nil {
		return file + ".sha256sum"
	}
	u.Path += ".sha256sum"
	if u.RawPath != "" {
		u.RawPath += ".sha256sum"
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

// fetchSum reads "<hex>  file" and returns the hash ("" when there is no
// checksum file). A host without the file (404, 410, or 401/403 from
// S3-like storage) or with something else than a checksum there (an
// HTML page) has not published one; a network or server error is an
// error.
func (u *Updater) fetchSum(ctx context.Context, url string, attempt int) (string, error) {
	resp, err := u.get(ctx, url, attempt)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return "", errNoSum
	default:
		return "", fmt.Errorf("%s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return "", errNoSum
	}
	h := strings.ToLower(f[0])
	if _, err := hex.DecodeString(h); err != nil || len(h) != 64 {
		return "", errNoSum
	}
	return h, nil
}

// download fetches url into a new file next to the database and returns
// its path, SHA-256 and size. The file gets a random name that did not
// exist (see writeFile) and reaches the disk before it is renamed into
// place: after a power cut the database is not left full of zeros.
func (u *Updater) download(ctx context.Context, k Kind, url string, attempt int) (path, sum string, size int64, err error) {
	resp, err := u.get(ctx, url, attempt)
	if err != nil {
		return "", "", 0, fmt.Errorf("не удалось скачать: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("сервер ответил %s", resp.Status)
	}
	limit := u.MaxSize
	if limit <= 0 {
		limit = 300 << 20
	}
	if resp.ContentLength > limit {
		return "", "", 0, fmt.Errorf("файл больше %d МБ", limit>>20)
	}
	f, err := os.CreateTemp(u.DB.Dir, k.File()+".*.new")
	if err != nil {
		return "", "", 0, err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	pw := &progressWriter{total: resp.ContentLength, f: func(done, total int64) {
		if u.Progress != nil {
			u.Progress(k, done, total)
		}
	}}
	n, err := io.Copy(io.MultiWriter(f, h, pw), io.LimitReader(resp.Body, limit+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", "", 0, fmt.Errorf("загрузка оборвалась: %v", err)
	}
	if n > limit {
		return "", "", 0, fmt.Errorf("файл больше %d МБ", limit>>20)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		return "", "", 0, fmt.Errorf("загрузка оборвалась: %d из %d байт", n, resp.ContentLength)
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), n, nil
}

type progressWriter struct {
	done, total int64
	last        time.Time
	f           func(done, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.done += int64(len(b))
	if time.Since(p.last) > 200*time.Millisecond || p.done == p.total {
		p.last = time.Now()
		p.f(p.done, p.total)
	}
	return len(b), nil
}

// Rollback restores the previous version of every database that has one.
// It is all or nothing: when a file cannot be swapped (it is open in
// another program), the swaps already made are undone.
func (u *Updater) Rollback() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.State()
	// A damaged previous version is not restored: the rules would stop
	// working, and the hold would keep it until a new version comes out.
	for _, k := range []Kind{Site, IP} {
		prev := u.DB.path(k) + ".prev"
		if _, serr := os.Stat(prev); serr != nil {
			continue
		}
		if _, cerr := Check(prev); cerr != nil {
			return fmt.Errorf("предыдущая версия %s повреждена, откат невозможен: %v", k.File(), cerr)
		}
	}
	var done []Kind
	var err error
	for _, k := range []Kind{Site, IP} {
		if _, serr := os.Stat(u.DB.path(k) + ".prev"); serr != nil {
			continue
		}
		if err = u.swapPrev(k, &st); err != nil {
			break
		}
		done = append(done, k)
	}
	if err != nil {
		for len(done) > 0 && u.swapPrev(done[len(done)-1], &st) == nil {
			done = done[:len(done)-1]
		}
	} else if len(done) == 0 {
		return errors.New("предыдущей версии баз нет")
	}
	if len(done) > 0 {
		// Swapped (and not undone): the state follows the files on disk.
		u.DB.Forget()
		if serr := u.saveState(st); err == nil {
			err = serr
		}
	}
	return err
}

// swapPrev swaps a database with its .prev, and their states (st and
// .prev.json), so a second swap returns to the newer file. The restored
// file is held: scheduled updates do not put back the file it replaced.
func (u *Updater) swapPrev(k Kind, st *State) error {
	dst := u.DB.path(k)
	var prev FileState
	if b, err := readSmall(dst + ".prev.json"); err == nil {
		_ = json.Unmarshal(b, &prev)
	}
	if sum, err := fileSum(dst + ".prev"); err == nil && !strings.EqualFold(sum, prev.SHA256) {
		// .prev.json describes another file (or is gone): describe the
		// file itself, of unknown origin (the hold below keeps it for the
		// source in use).
		prev = FileState{SHA256: sum}
		if fi, err := os.Stat(dst + ".prev"); err == nil {
			prev.Size, prev.Updated = fi.Size(), fi.ModTime()
		}
		prev.Categories, _ = Check(dst + ".prev")
	}
	cur := &st.Site
	if k == IP {
		cur = &st.IP
	}
	if *cur != nil && prev.SHA256 != "" {
		prev.HeldFor, prev.RolledBackFrom = (*cur).HeldFor, (*cur).SHA256
		if prev.HeldFor == "" {
			prev.HeldFor = (*cur).URL
		}
	}
	tmp := dst + ".swap"
	if err := os.Rename(dst, tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(dst+".prev", dst); err != nil {
		_ = os.Rename(tmp, dst)
		return err
	}
	_ = os.Rename(tmp, dst+".prev")
	if *cur != nil {
		writePrevState(dst, **cur)
	} else {
		_ = os.Remove(dst + ".prev.json") // it described the file now in place
	}
	*cur = nil
	if prev.SHA256 != "" {
		*cur = &prev
	}
	return nil
}
