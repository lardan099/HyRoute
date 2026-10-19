// Package groups holds server groups: named, ordered lists of servers with
// a strategy that picks the member a new connection goes through. A group
// is a routing target like a server (rules, the default route, fallback
// lists, local proxies and the main target hold its ID). This file is the
// data model of groups.json and its validation; runtime.go is the live
// selector, probe.go the latency prober. The package is cross-platform
// and knows nothing of the store, the controller or the tunnels.
package groups

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Strategy is how a group picks the member of a new connection.
type Strategy string

const (
	Failover   Strategy = "failover"
	Latency    Strategy = "latency"
	RoundRobin Strategy = "roundrobin"
	Random     Strategy = "random"
	Sticky     Strategy = "sticky"
)

// Group is one group as groups.json stores it. Members are server IDs in
// order; an ID that is no longer a server dangles (ignored at runtime,
// pruned on the next write).
type Group struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Strategy Strategy `json:"strategy"`
	Members  []string `json:"members"`
	// Revert (failover): a member earlier in the list that has been
	// healthy for RevertAfter takes over again.
	Revert bool `json:"revert,omitempty"`
	// ToleranceMs (latency): hysteresis, 0 = DefaultToleranceMs.
	ToleranceMs int `json:"toleranceMs,omitempty"`
	// SwitchAfterErrors: a member whose N new connections in a row failed
	// is skipped for PenaltyFor (0 = off).
	SwitchAfterErrors int `json:"switchAfterErrors,omitempty"`
}

// Probe is the latency probe: the URL requested through every running
// member of the used groups, and how often.
type Probe struct {
	URL         string `json:"url,omitempty"`
	IntervalSec int    `json:"intervalSec,omitempty"`
}

// File is groups.json.
type File struct {
	Version int `json:"version"`
	// Main is a group used as the main target instead of profiles.json's
	// active server ("" = the server main).
	Main   string  `json:"main,omitempty"`
	Probe  *Probe  `json:"probe,omitempty"`
	Groups []Group `json:"groups"`
}

const (
	FormatVersion      = 1
	MaxGroups          = 64
	MaxMembers         = 32
	MaxNameRunes       = 64
	MaxFileSize        = 1 << 20
	DefaultProbeURL    = "http://cp.cloudflare.com/generate_204"
	DefaultInterval    = 60 * time.Second
	DefaultToleranceMs = 50
	PenaltyFor         = 60 * time.Second // error-streak skip
	TrialTimeout       = 15 * time.Second // half-open trial without a NoteDial (relay SOCKS dial timeout 10 s + margin)
	RevertAfter        = 30 * time.Second // failover revert stability
	ProbeTimeout       = 5 * time.Second
	ProbeFailLimit     = 2
	ProbePeerWindow    = 3                // × interval: how recent a peer's probe success must be
	ProbeGroupBudget   = 60 * time.Second // whole «Проверить» on a group
	ProbeGroupWorkers  = 4

	minInterval = 30
	maxInterval = 600
	maxURL      = 512
)

// idPrefix keeps group IDs apart from server IDs: both live in one target
// namespace (rules, proxies and the main target hold either).
const idPrefix = "grp-"

var idRe = regexp.MustCompile(`^grp-[0-9a-f]{12}$`)

// IsGroupID reports whether a target ID names a group (by its prefix).
func IsGroupID(id string) bool { return strings.HasPrefix(id, idPrefix) }

// NewID is a group ID for hex12, twelve random lowercase hex digits (the
// controller's newID).
func NewID(hex12 string) string { return idPrefix + hex12 }

// ValidID reports whether id is a well-formed group ID: "grp-" and twelve
// lowercase hex digits (import paths: backup, cli).
func ValidID(id string) bool { return idRe.MatchString(id) }

// StrategyLabel is the strategy for logs and diagnostics.
func StrategyLabel(s Strategy) string {
	switch s {
	case Failover:
		return "по порядку"
	case Latency:
		return "самый быстрый"
	case RoundRobin:
		return "по кругу"
	case Random:
		return "случайно"
	case Sticky:
		return "закреплять сайт"
	}
	return string(s)
}

func knownStrategy(s Strategy) bool {
	switch s {
	case Failover, Latency, RoundRobin, Random, Sticky:
		return true
	}
	return false
}

// Parse reads groups.json: a BOM is skipped, unknown fields are refused,
// the format version must be exactly FormatVersion, and the load rules
// (Validate) must hold. The size is the store's to bound.
func Parse(b []byte) (*File, error) {
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("после данных лишний текст")
	}
	switch {
	case f.Version > FormatVersion:
		return nil, fmt.Errorf("groups.json создан более новой версией HyRoute (формат %d): группы не загружены, файл не изменяется", f.Version)
	case f.Version != FormatVersion:
		return nil, errors.New("groups.json: нет версии формата")
	}
	if f.Groups == nil {
		f.Groups = []Group{}
	}
	for i := range f.Groups {
		// A hand edit may leave "members" out or null: the UI reads an
		// array (as SaveGroups writes it).
		if f.Groups[i].Members == nil {
			f.Groups[i].Members = []string{}
		}
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// MainOf is the "main" of a groups.json that does not parse: read
// leniently, kept only when it names a group, "" when even that fails. A
// broken file whose main was a group then still fails closed.
func MainOf(b []byte) string {
	var m struct {
		Main string `json:"main"`
	}
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF")), &m) != nil || !IsGroupID(m.Main) {
		return ""
	}
	return m.Main
}

// nameErr checks a group name (already trimmed).
func nameErr(name string) error {
	switch {
	case name == "":
		return Errorf("Укажите название группы")
	case utf8.RuneCountInString(name) > MaxNameRunes:
		return Errorf("Название группы — не длиннее %d символов", MaxNameRunes)
	case !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl):
		return Errorf("В названии группы не может быть управляющих символов")
	}
	return nil
}

// Validate checks the load rules, which every write checks for the whole
// file too: names trimmed, 1..64 runes, no control characters, unique
// (case-insensitive); IDs well-formed and unique; a known strategy;
// 0..32 unique members, never a group; the option bounds; Main "" or an
// existing group; the probe. Dangling server IDs and empty groups pass:
// they fail closed at runtime, and one broken group must not block edits
// of the others.
func (f *File) Validate() error {
	if len(f.Groups) > MaxGroups {
		return Errorf("Групп может быть не больше %d", MaxGroups)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, g := range f.Groups {
		if !ValidID(g.ID) {
			return fmt.Errorf("неверный id группы %q", g.ID)
		}
		if ids[g.ID] {
			return fmt.Errorf("id группы %s повторяется", g.ID)
		}
		ids[g.ID] = true
		if g.Name != strings.TrimSpace(g.Name) {
			return fmt.Errorf("название группы %q с пробелами по краям", g.Name)
		}
		if err := nameErr(g.Name); err != nil {
			return err
		}
		if k := strings.ToLower(g.Name); names[k] {
			return Errorf("Группа «%s» уже есть", g.Name)
		} else {
			names[k] = true
		}
		if err := checkGroup(g); err != nil {
			return err
		}
	}
	if f.Main != "" && !ids[f.Main] {
		return fmt.Errorf("основная группа %s не найдена", f.Main)
	}
	if f.Probe != nil {
		if err := ValidateProbe(*f.Probe); err != nil {
			return err
		}
	}
	return nil
}

// checkGroup is the part of the load rules that concerns one group alone.
func checkGroup(g Group) error {
	if !knownStrategy(g.Strategy) {
		return Errorf("Неизвестный способ выбора сервера %q", string(g.Strategy))
	}
	if len(g.Members) > MaxMembers {
		return Errorf("В группе может быть не больше %d серверов", MaxMembers)
	}
	seen := map[string]bool{}
	for _, m := range g.Members {
		if m == "" || IsGroupID(m) {
			return Errorf("Сервер %s не найден", m)
		}
		if seen[m] {
			return fmt.Errorf("сервер %s в группе «%s» дважды", m, g.Name)
		}
		seen[m] = true
	}
	if n := g.SwitchAfterErrors; n != 0 && (n < 2 || n > 20) {
		return Errorf("Число ошибок — от 2 до 20")
	}
	if n := g.ToleranceMs; n != 0 && (n < 10 || n > 1000) {
		return Errorf("Порог переключения — от 10 до 1000 мс")
	}
	return nil
}

// ValidateEdited is the stricter save rule for the one group being
// created or edited: a valid name and options, and 1..32 members that are
// all existing servers (server reports it).
func ValidateEdited(g Group, server func(id string) bool) error {
	if err := nameErr(strings.TrimSpace(g.Name)); err != nil {
		return err
	}
	if len(g.Members) == 0 {
		return Errorf("Добавьте в группу хотя бы один сервер")
	}
	if err := checkGroup(g); err != nil {
		return err
	}
	for _, m := range g.Members {
		if !server(m) {
			return Errorf("Сервер %s не найден", m)
		}
	}
	return nil
}

// Prune drops the member IDs that are no servers (server reports false)
// from every group, keeping the order, and returns how many went. It never
// fails; every write runs it (the documented "dropped on the next save").
func (f *File) Prune(server func(id string) bool) (removed int) {
	for i := range f.Groups {
		g := &f.Groups[i]
		kept := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if server(m) {
				kept = append(kept, m)
			} else {
				removed++
			}
		}
		g.Members = kept
	}
	return removed
}

// ValidateProbe checks the probe settings: the URL empty (the default) or
// http(s) with a host name or a public address, no user info, at most 512
// bytes; the interval 0 (the default) or 30..600 seconds. The request only
// ever goes through a member's Hysteria, never from this computer: the
// local-address refusal is defence in depth (a SOCKS server that resolves
// locally, like the stub).
func ValidateProbe(p Probe) error {
	if p.URL != "" {
		if len(p.URL) > maxURL {
			return Errorf("Адрес проверки — не длиннее %d символов", maxURL)
		}
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
			return Errorf("Адрес проверки: только http:// или https:// с именем сервера")
		}
		if localHost(u.Hostname()) {
			return Errorf("Адрес проверки не должен вести в локальную сеть или на этот компьютер")
		}
		if ps := u.Port(); ps != "" {
			// As probeOnce reads it: a port past 65535, or 0, fails every
			// probe before it connects.
			if n, err := strconv.Atoi(ps); err != nil || n < 1 || n > 65535 {
				return Errorf("Адрес проверки: порт — от 1 до 65535")
			}
		}
	}
	if n := p.IntervalSec; n != 0 && (n < minInterval || n > maxInterval) {
		return Errorf("Интервал проверки — от 30 с до 10 мин")
	}
	return nil
}

// localHost: "localhost" (and its subdomains) or an address of this
// computer or a local network.
func localHost(h string) bool {
	l := strings.TrimSuffix(strings.ToLower(h), ".")
	if l == "localhost" || strings.HasSuffix(l, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() || a.IsMulticast()
}

// Effective is the probe URL and interval with the defaults filled in. A
// nil Probe is the default one.
func (p *Probe) Effective() (url string, every time.Duration) {
	url, every = DefaultProbeURL, DefaultInterval
	if p == nil {
		return url, every
	}
	if p.URL != "" {
		url = p.URL
	}
	if p.IntervalSec > 0 {
		every = time.Duration(p.IntervalSec) * time.Second
	}
	return url, every
}

// Find returns the group with id, or nil.
func (f *File) Find(id string) *Group {
	for i := range f.Groups {
		if f.Groups[i].ID == id {
			return &f.Groups[i]
		}
	}
	return nil
}

// Clone is a deep copy (the controller edits a copy and installs it only
// once it is saved).
func (f *File) Clone() *File {
	out := &File{Version: f.Version, Main: f.Main, Groups: make([]Group, len(f.Groups))}
	if f.Probe != nil {
		p := *f.Probe
		out.Probe = &p
	}
	for i, g := range f.Groups {
		g.Members = append([]string{}, g.Members...)
		out.Groups[i] = g
	}
	return out
}

// Refs lists the server IDs the groups name as members, each once, in
// file order (backup: servers a restored group keeps).
func (f *File) Refs() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range f.Groups {
		for _, m := range g.Members {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// Remap rewrites the IDs of an imported file (backup «добавить»): members
// through server, group IDs and Main through group. An entry mapped to ""
// is dropped: a member, a whole group, or Main (also when its group was
// dropped).
func (f *File) Remap(server func(id string) string, group func(id string) string) {
	var out []Group
	gone := map[string]bool{}
	for _, g := range f.Groups {
		id := group(g.ID)
		if id == "" {
			gone[g.ID] = true
			continue
		}
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if n := server(m); n != "" {
				members = append(members, n)
			}
		}
		g.ID, g.Members = id, members
		out = append(out, g)
	}
	if out == nil {
		out = []Group{}
	}
	f.Groups = out
	if f.Main != "" {
		if gone[f.Main] {
			f.Main = ""
		} else {
			f.Main = group(f.Main)
		}
	}
}

// userError is an error whose text is a sentence for the user, capital
// letter first (the UI shows it as is).
type userError string

func (e userError) Error() string { return string(e) }

// Errorf formats an error for the user (see userError).
func Errorf(format string, a ...any) error { return userError(fmt.Sprintf(format, a...)) }
