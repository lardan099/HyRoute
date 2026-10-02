// Package geo keeps the geo databases (geoip.dat and geosite.dat of
// Loyalsoldier/v2ray-rules-dat) at the controller, for checking rules and
// for putting them on servers (P3-07).
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// The databases.
const (
	GeoIP   = "geoip.dat"
	GeoSite = "geosite.dat"
)

// Names are the databases in order.
var Names = []string{GeoIP, GeoSite}

// DefaultBase is the releases page the databases come from.
const DefaultBase = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases"

// maxFile bounds a download (the databases are about 10 MB).
const maxFile = 64 << 20

// ErrNone: the controller has no databases yet.
var ErrNone = errors.New("у controller ещё нет баз geo: скачайте их")

// File is a database the controller has.
type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// URL is the file in its release, for servers that download it
	// themselves.
	URL string `json:"url"`
}

// Info is what the controller has.
type Info struct {
	// Release is the tag of the release the files are from ("": none).
	Release string    `json:"release"`
	Files   []File    `json:"files"`
	At      time.Time `json:"at"` // when they were downloaded
	// CheckedAt is the last look for a newer release.
	CheckedAt time.Time `json:"checkedAt"`
}

// File is the database name.
func (i Info) File(name string) (File, bool) {
	for _, f := range i.Files {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// Store keeps the databases in a directory of the controller.
type Store struct {
	Dir  string // <data dir>/geo
	Base string // DefaultBase if ""
	HTTP *http.Client
	Now  func() time.Time

	mu      sync.Mutex
	parsed  string // the release ip and site are of
	ip      map[string]*v2geo.GeoIP
	site    map[string]*v2geo.GeoSite
	updates sync.Mutex
}

func (s *Store) base() string {
	if s.Base == "" {
		return DefaultBase
	}
	return strings.TrimRight(s.Base, "/")
}

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *Store) client() *http.Client {
	c := http.DefaultClient
	if s.HTTP != nil {
		c = s.HTTP
	}
	// The latest release is where /latest redirects.
	nc := *c
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &nc
}

// Info is what the controller has (Release "" when nothing).
func (s *Store) Info() (Info, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "info.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Info{Files: []File{}}, nil
	} else if err != nil {
		return Info{}, err
	}
	var i Info
	if err := json.Unmarshal(b, &i); err != nil {
		return Info{}, fmt.Errorf("geo: info.json: %w", err)
	}
	return i, nil
}

func (s *Store) writeInfo(i Info) error {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return replace(filepath.Join(s.Dir, "info.json"), b)
}

// replace writes a file whole or not at all.
func replace(p string, b []byte) error {
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

var tagRe = regexp.MustCompile(`^[0-9A-Za-z._-]{1,64}$`)

// Update looks for a newer release and downloads its databases, each
// checked against its .sha256sum and read as a database before it
// replaces the old one. It reports whether the files changed.
func (s *Store) Update(ctx context.Context) (Info, bool, error) {
	s.updates.Lock()
	defer s.updates.Unlock()
	cur, err := s.Info()
	if err != nil {
		return cur, false, err
	}
	tag, err := s.latest(ctx)
	if err != nil {
		return cur, false, err
	}
	cur.CheckedAt = s.now()
	if tag == cur.Release && len(cur.Files) == len(Names) {
		return cur, false, s.writeInfo(cur)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return cur, false, err
	}
	next := Info{Release: tag, At: s.now(), CheckedAt: cur.CheckedAt}
	data := map[string][]byte{}
	for _, name := range Names {
		f, b, err := s.download(ctx, tag, name)
		if err != nil {
			return cur, false, err
		}
		next.Files, data[name] = append(next.Files, f), b
	}
	for _, name := range Names {
		if err := replace(filepath.Join(s.Dir, name), data[name]); err != nil {
			return cur, false, err
		}
	}
	if err := s.writeInfo(next); err != nil {
		return cur, false, err
	}
	return next, true, nil
}

// latest is the tag of the latest release.
func (s *Store) latest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base()+"/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось узнать последний релиз баз geo: %w", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tag := path.Base(loc)
	if resp.StatusCode/100 != 3 || !strings.Contains(loc, "/releases/tag/") || !tagRe.MatchString(tag) {
		return "", fmt.Errorf("не удалось узнать последний релиз баз geo: ответ %s", resp.Status)
	}
	return tag, nil
}

// download fetches a database of release tag and checks it.
func (s *Store) download(ctx context.Context, tag, name string) (File, []byte, error) {
	url := s.base() + "/download/" + tag + "/" + name
	sumText, err := s.get(ctx, url+".sha256sum", 4096)
	if err != nil {
		return File{}, nil, err
	}
	want := strings.ToLower(strings.Fields(string(sumText) + " ")[0])
	if len(want) != 64 || strings.Trim(want, "0123456789abcdef") != "" {
		return File{}, nil, fmt.Errorf("в %s.sha256sum нет хеша", name)
	}
	b, err := s.get(ctx, url, maxFile)
	if err != nil {
		return File{}, nil, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		return File{}, nil, fmt.Errorf("%s не совпадает с хешем релиза %s", name, tag)
	}
	if err := parse(name, b); err != nil {
		return File{}, nil, fmt.Errorf("%s релиза %s не читается как база: %w", name, tag, err)
	}
	return File{Name: name, SHA256: want, Size: int64(len(b)), URL: url}, b, nil
}

func (s *Store) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := http.DefaultClient
	if s.HTTP != nil {
		c = s.HTTP
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать %s: %w", path.Base(url), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("не удалось скачать %s: %s", path.Base(url), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать %s: %w", path.Base(url), err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s больше %d МБ", path.Base(url), limit>>20)
	}
	return b, nil
}

// parse reads b as the database name.
func parse(name string, b []byte) error {
	var err error
	if name == GeoIP {
		_, err = parseGeoIP(b)
	} else {
		_, err = parseGeoSite(b)
	}
	return err
}

// parseGeoIP and parseGeoSite read a database as v2geo.LoadGeoIP and
// LoadGeoSite read its file: by lower-case code or name.
func parseGeoIP(b []byte) (map[string]*v2geo.GeoIP, error) {
	var list v2geo.GeoIPList
	if err := proto.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	m := map[string]*v2geo.GeoIP{}
	for _, e := range list.Entry {
		m[strings.ToLower(e.CountryCode)] = e
	}
	return m, nil
}

func parseGeoSite(b []byte) (map[string]*v2geo.GeoSite, error) {
	var list v2geo.GeoSiteList
	if err := proto.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	m := map[string]*v2geo.GeoSite{}
	for _, e := range list.Entry {
		m[strings.ToLower(e.CountryCode)] = e
	}
	return m, nil
}

// Open is a database's file, checked against the recorded hash.
func (s *Store) Open(name string) ([]byte, File, error) {
	i, err := s.Info()
	if err != nil {
		return nil, File{}, err
	}
	f, ok := i.File(name)
	if !ok {
		return nil, File{}, ErrNone
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, f, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != f.SHA256 {
		return nil, f, fmt.Errorf("%s у controller повреждён: скачайте базы заново", name)
	}
	return b, f, nil
}

// Loader is the databases for the rule checks; nil while there are none.
func (s *Store) Loader() hacl.GeoLoader {
	if s == nil {
		return nil
	}
	if i, err := s.Info(); err != nil || i.Release == "" {
		return nil
	}
	return s
}

// load parses the databases once per release.
func (s *Store) load() error {
	i, err := s.Info()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.parsed == i.Release && s.ip != nil {
		return nil
	}
	b, _, err := s.Open(GeoIP)
	if err != nil {
		return err
	}
	ip, err := parseGeoIP(b)
	if err != nil {
		return err
	}
	if b, _, err = s.Open(GeoSite); err != nil {
		return err
	}
	site, err := parseGeoSite(b)
	if err != nil {
		return err
	}
	s.parsed, s.ip, s.site = i.Release, ip, site
	return nil
}

// LoadGeoIP is geoip.dat by lower-case code (hacl.GeoLoader).
func (s *Store) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip, nil
}

// LoadGeoSite is geosite.dat by lower-case name (hacl.GeoLoader).
func (s *Store) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.site, nil
}

// maxCategories bounds a category search.
const maxCategories = 200

// Categories are the codes of geoip (kind geoip) or the names of geosite
// that contain q, sorted, at most 200.
func (s *Store) Categories(kind, q string) ([]string, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	var names []string
	q = strings.ToLower(q)
	add := func(n string) {
		if strings.Contains(n, q) {
			names = append(names, n)
		}
	}
	if kind == "geoip" {
		for n := range s.ip {
			add(n)
		}
	} else {
		for n := range s.site {
			add(n)
		}
	}
	s.mu.Unlock()
	slices.Sort(names)
	if len(names) > maxCategories {
		names = names[:maxCategories]
	}
	return names, nil
}
