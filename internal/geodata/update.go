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
	b, err := os.ReadFile(u.statePath())
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
	tmp := u.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.statePath())
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
// are verified; the replaced file is kept as .prev for Rollback.
func (u *Updater) Update(ctx context.Context, src Source, force bool) (Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := os.MkdirAll(u.DB.Dir, 0o700); err != nil {
		return Result{}, err
	}
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
		// downloaded again: never keep files of the old one.
		fs, changed, err := u.updateFile(ctx, k, url, *cur, force || !st.From(k, url))
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

func (u *Updater) updateFile(ctx context.Context, k Kind, url string, cur *FileState, force bool) (FileState, bool, error) {
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
	_, statErr := os.Stat(dst)
	if !force && statErr == nil && cur != nil && want != "" && strings.EqualFold(want, cur.SHA256) {
		return *cur, false, nil
	}
	tmp := dst + ".new"
	defer os.Remove(tmp)
	got, size, err := u.download(ctx, k, url, tmp, 0)
	if err != nil && ctx.Err() == nil {
		got, size, err = u.download(ctx, k, url, tmp, 1)
	}
	if err != nil {
		return FileState{}, false, err
	}
	if want != "" && !strings.EqualFold(got, want) {
		return FileState{}, false, fmt.Errorf("контрольная сумма не совпала (ожидалась %s…, получена %s…): файл не установлен", want[:12], got[:12])
	}
	n, err := Check(tmp)
	if err != nil {
		return FileState{}, false, fmt.Errorf("скачанный файл не похож на базу правил: %v", err)
	}
	if statErr == nil && cur != nil && strings.EqualFold(got, cur.SHA256) {
		// Same content (no .sha256sum published, or the same file at a
		// new URL): keep it, now as the file of url.
		fs := *cur
		fs.URL = url
		fs.Verified = want != ""
		return fs, false, nil
	}
	if statErr == nil {
		// The rename replaces the old .prev: removing it first would lose
		// it when the rename fails (the file is open in another program).
		if err := os.Rename(dst, dst+".prev"); err != nil {
			return FileState{}, false, err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if statErr == nil {
			_ = os.Rename(dst+".prev", dst)
		}
		return FileState{}, false, err
	}
	if cur != nil {
		writePrevState(dst, *cur)
	}
	return FileState{SHA256: got, Size: size, Categories: n, Updated: time.Now(), URL: url, Verified: want != "" && sumErr == nil}, true, nil
}

func writePrevState(dst string, fs FileState) {
	if b, err := json.Marshal(fs); err == nil {
		_ = os.WriteFile(dst+".prev.json", b, 0o600)
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
	return http.DefaultClient.Do(req)
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

func (u *Updater) download(ctx context.Context, k Kind, url, path string, attempt int) (string, int64, error) {
	resp, err := u.get(ctx, url, attempt)
	if err != nil {
		return "", 0, fmt.Errorf("не удалось скачать: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("сервер ответил %s", resp.Status)
	}
	limit := u.MaxSize
	if limit <= 0 {
		limit = 300 << 20
	}
	if resp.ContentLength > limit {
		return "", 0, fmt.Errorf("файл больше %d МБ", limit>>20)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	pw := &progressWriter{total: resp.ContentLength, f: func(done, total int64) {
		if u.Progress != nil {
			u.Progress(k, done, total)
		}
	}}
	n, err := io.Copy(io.MultiWriter(f, h, pw), io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, fmt.Errorf("загрузка оборвалась: %v", err)
	}
	if n > limit {
		return "", 0, fmt.Errorf("файл больше %d МБ", limit>>20)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		return "", 0, fmt.Errorf("загрузка оборвалась: %d из %d байт", n, resp.ContentLength)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
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
// .prev.json), so a second swap returns to the newer file.
func (u *Updater) swapPrev(k Kind, st *State) error {
	dst := u.DB.path(k)
	var prev FileState
	if b, err := os.ReadFile(dst + ".prev.json"); err == nil {
		_ = json.Unmarshal(b, &prev)
	}
	cur := &st.Site
	if k == IP {
		cur = &st.IP
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
