package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/rules"
)

// Rule profiles (rulesets.json): named sets of rules, one of them active.
// settings.json keeps holding the active profile's rules and is
// authoritative for them; rulesets.json holds every profile, its copy of
// the active one refreshed at each of its writes. The file exists only
// once the user has a second profile. The pair protocol between the two
// files is internal/app's (rulesets.go); here are the format, its checks
// and the file writes.

const (
	RulesetsVersion  = 1
	MaxRulesets      = 50
	MaxRulesetName   = 40       // runes
	maxRulesetsBytes = 16 << 20 // refused above this
)

// Ruleset is one rule profile.
type Ruleset struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Config rules.Config `json:"config"`
	// raw is set only for an entry whose config has fields this version
	// does not know (Newer): Config is then a lenient decode, for
	// reference checks only, and MarshalJSON writes raw back unchanged.
	raw json.RawMessage
}

// Newer reports an entry saved by a newer HyRoute: its rules carry fields
// this version does not know. It cannot be switched to or edited; its
// bytes are kept.
func (r Ruleset) Newer() bool { return r.raw != nil }

// SetConfig replaces the rules with a copy of c (a newer entry becomes an
// ordinary one: its old fields are gone).
func (r *Ruleset) SetConfig(c rules.Config) {
	r.Config = CloneConfig(c)
	r.raw = nil
}

type rulesetEntry struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

// MarshalJSON writes the config as it was read for a newer entry.
func (r Ruleset) MarshalJSON() ([]byte, error) {
	cfg := r.raw
	if cfg == nil {
		b, err := json.Marshal(CloneConfig(r.Config))
		if err != nil {
			return nil, err
		}
		cfg = b
	}
	return json.Marshal(rulesetEntry{ID: r.ID, Name: r.Name, Config: cfg})
}

// RulesetsPending marks a pair write under way: settings.json held rules
// with hash Was ("" = there was no settings.json) and is being rewritten
// to rules with hash To.
type RulesetsPending struct {
	Was string `json:"was"`
	To  string `json:"to"`
}

// Rulesets is rulesets.json.
type Rulesets struct {
	Version int              `json:"version"`
	Active  string           `json:"active"`
	Pending *RulesetsPending `json:"pending,omitempty"`
	List    []Ruleset        `json:"list"`
}

// Find returns the profile with id, or nil.
func (r *Rulesets) Find(id string) *Ruleset {
	if i := r.Index(id); i >= 0 {
		return &r.List[i]
	}
	return nil
}

// Index returns the position of profile id, or -1.
func (r *Rulesets) Index(id string) int {
	for i := range r.List {
		if r.List[i].ID == id {
			return i
		}
	}
	return -1
}

// Clone is a deep copy: nothing is shared with r.
func (r *Rulesets) Clone() *Rulesets {
	if r == nil {
		return nil
	}
	out := *r
	if r.Pending != nil {
		p := *r.Pending
		out.Pending = &p
	}
	out.List = make([]Ruleset, len(r.List))
	for i, e := range r.List {
		e.Config = CloneConfig(e.Config)
		e.raw = bytes.Clone(e.raw)
		out.List[i] = e
	}
	return &out
}

var (
	rulesetIDRe = regexp.MustCompile(`^[0-9a-f]{8,32}$`)
	hashRe      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidRulesetID reports an ID rulesets.json may hold (also on import).
func ValidRulesetID(id string) bool { return rulesetIDRe.MatchString(id) }

// Validate checks the structure: version, count, IDs, the active one,
// names and the pending marker. The rules are internal/app's to check.
func (r *Rulesets) Validate() error {
	switch {
	case r.Version == 0:
		return errors.New("rulesets.json: нет версии формата")
	case r.Version > RulesetsVersion:
		return newerRulesetsError(r.Version)
	case r.Version < 0:
		return fmt.Errorf("rulesets.json: неверная версия формата %d", r.Version)
	case len(r.List) == 0:
		return errors.New("rulesets.json: нет ни одного профиля правил")
	case len(r.List) > MaxRulesets:
		return fmt.Errorf("rulesets.json: профилей правил больше %d", MaxRulesets)
	}
	ids := map[string]bool{}
	var names []string // at most MaxRulesets: pairwise, as the app compares
	for _, e := range r.List {
		if !ValidRulesetID(e.ID) {
			return fmt.Errorf("rulesets.json: неверный ID профиля правил %q", e.ID)
		}
		if ids[e.ID] {
			return fmt.Errorf("rulesets.json: ID профиля правил %q повторяется", e.ID)
		}
		ids[e.ID] = true
		n, err := CleanRulesetName(e.Name)
		if err == nil && n != e.Name {
			err = errRulesetName // spaces at the ends
		}
		if err != nil {
			return fmt.Errorf("rulesets.json: профиль %q: %w", e.ID, err)
		}
		// strings.EqualFold, as create and rename check it (ToLower
		// disagrees with it for a few letters, e.g. «ſ» and «s»).
		if slices.ContainsFunc(names, func(m string) bool { return strings.EqualFold(m, n) }) {
			return fmt.Errorf("rulesets.json: название профиля правил «%s» повторяется", n)
		}
		names = append(names, n)
	}
	if !ids[r.Active] {
		return fmt.Errorf("rulesets.json: включённого профиля правил %q нет в списке", r.Active)
	}
	if p := r.Pending; p != nil && (!hashRe.MatchString(p.To) || p.Was != "" && !hashRe.MatchString(p.Was)) {
		return errors.New("rulesets.json: неверная отметка незавершённой записи")
	}
	return nil
}

func newerRulesetsError(v int) error {
	return fmt.Errorf("rulesets.json: создан более новой версией HyRoute (формат %d), обновите HyRoute", v)
}

// Remap replaces every routing target of every config (rules' Profile and
// Fallback, DefaultProfile, DefaultFallback): fn gets kind "target" and the
// ID, and returns the new one, once per target. A newer entry has them
// replaced in its saved bytes (the fields it does not know are kept), and
// its lenient Config is decoded again from them.
func (r *Rulesets) Remap(fn func(kind, id string) string) {
	for i := range r.List {
		e := &r.List[i]
		if e.raw != nil && e.remapRaw(fn) {
			continue
		}
		c := &e.Config
		c.DefaultProfile = fn("target", c.DefaultProfile)
		for j := range c.DefaultFallback {
			c.DefaultFallback[j] = fn("target", c.DefaultFallback[j])
		}
		for k := range c.Rules {
			c.Rules[k].Profile = fn("target", c.Rules[k].Profile)
			for j := range c.Rules[k].Fallback {
				c.Rules[k].Fallback[j] = fn("target", c.Rules[k].Fallback[j])
			}
		}
	}
}

// remapRaw is Remap for a newer entry: the targets of its raw config
// (defaultProfile, defaultFallback, rules[].profile and .fallback) as a
// generic JSON object, numbers kept exact. False (fn not called) when raw
// is not such an object; it always is after ParseRulesets.
func (e *Ruleset) remapRaw(fn func(kind, id string) string) bool {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(e.raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		return false
	}
	one := func(v any) any {
		if id, ok := v.(string); ok {
			return fn("target", id)
		}
		return v
	}
	list := func(v any) {
		if l, ok := v.([]any); ok {
			for j := range l {
				l[j] = one(l[j])
			}
		}
	}
	remapIn := func(o map[string]any, target, fallback string) {
		if v, ok := o[target]; ok {
			o[target] = one(v)
		}
		list(o[fallback])
	}
	remapIn(m, "defaultProfile", "defaultFallback")
	if rs, ok := m["rules"].([]any); ok {
		for _, r := range rs {
			if o, ok := r.(map[string]any); ok {
				remapIn(o, "profile", "fallback")
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return true // cannot happen: m was decoded from JSON
	}
	var c rules.Config
	if json.Unmarshal(b, &c) == nil {
		e.Config = CloneConfig(c)
	}
	e.raw = b
	return true
}

// ParseRulesets parses rulesets.json: the envelope strictly (an unknown
// key there is a newer format), each config strictly too, except that a
// config whose only problem is a field this version does not know is kept
// as a newer entry (see Ruleset.raw). Then Validate.
func ParseRulesets(b []byte) (*Rulesets, error) {
	if len(b) > maxRulesetsBytes {
		return nil, errors.New("rulesets.json: файл слишком большой")
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	// The version first: a newer format may have keys this one refuses.
	var ver struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &ver); err != nil {
		return nil, fmt.Errorf("rulesets.json: %w", err)
	}
	if ver.Version > RulesetsVersion {
		return nil, newerRulesetsError(ver.Version)
	}
	var f struct {
		Version int              `json:"version"`
		Active  string           `json:"active"`
		Pending *RulesetsPending `json:"pending,omitempty"`
		List    []rulesetEntry   `json:"list"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("rulesets.json: %w", err)
	}
	out := &Rulesets{Version: f.Version, Active: f.Active, Pending: f.Pending, List: make([]Ruleset, 0, len(f.List))}
	for _, e := range f.List {
		cfg, raw, err := parseRulesetConfig(e.Config)
		if err != nil {
			return nil, fmt.Errorf("rulesets.json: профиль %q: %w", e.ID, err)
		}
		out.List = append(out.List, Ruleset{ID: e.ID, Name: e.Name, Config: cfg, raw: raw})
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseRulesetConfig decodes one entry's config; raw != nil marks a newer
// one (unknown fields only).
func parseRulesetConfig(b json.RawMessage) (rules.Config, json.RawMessage, error) {
	var c rules.Config
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return c, nil, errors.New("правила должны быть объектом JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	err := dec.Decode(&c)
	if err == nil {
		c = CloneConfig(c)
		return c, nil, nil
	}
	if !strings.HasPrefix(err.Error(), `json: unknown field "`) {
		return c, nil, err
	}
	c = rules.Config{}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, nil, err
	}
	return CloneConfig(c), bytes.Clone(b), nil
}

// LoadRulesets reads rulesets.json: (nil, nil) when there is none. A link,
// a junction or a folder in its place is refused, never followed.
func (s *Store) LoadRulesets() (*Rulesets, error) {
	b, err := s.readRegular("rulesets.json", maxRulesetsBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case errors.Is(err, ErrNotRegular):
		return nil, errors.New("rulesets.json: не обычный файл — HyRoute его не читает")
	case errors.Is(err, ErrTooLarge):
		return nil, errors.New("rulesets.json: файл слишком большой")
	case err != nil:
		return nil, fmt.Errorf("rulesets.json: %w", err)
	}
	return ParseRulesets(b)
}

// SaveRulesets validates and writes rulesets.json.
func (s *Store) SaveRulesets(r *Rulesets) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if s.TestRulesetsWrite != nil {
		if err := s.TestRulesetsWrite(r.Pending != nil); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path("rulesets.json"), b)
}

// WriteRulesPair writes settings.json (b, from ValidateSettings) together
// with next, the rule profiles whose active entry holds the same rules:
//
//  1. the bytes of rulesets.json as they are (even broken; or none);
//  2. next with the pending marker {was, to} (the hashes of the rules in
//     settings.json before and after);
//  3. settings.json; on failure the bytes of step 1 are put back (or the
//     file removed when there was none): err, plus revertErr when that
//     failed too;
//  4. next without the marker: a failure only leaves cleared false.
//
// It takes no lock but s.mu per file: the caller serializes writers.
func (s *Store) WriteRulesPair(b []byte, next *Rulesets, was, to string) (cleared bool, revertErr, err error) {
	old, err := s.ReadRaw("rulesets.json")
	if err != nil {
		return false, nil, err
	}
	marked := *next
	marked.Pending = &RulesetsPending{Was: was, To: to}
	if err := s.SaveRulesets(&marked); err != nil {
		return false, nil, err
	}
	if err := s.WriteSettings(b); err != nil {
		return false, s.WriteRaw("rulesets.json", old), err
	}
	clean := *next
	clean.Pending = nil
	return s.SaveRulesets(&clean) == nil, nil, nil
}

// ConfigHash identifies the rules part of settings: "sha256:" and the hex
// SHA-256 of its JSON (nil rules count as none).
func ConfigHash(c rules.Config) string {
	b, err := json.Marshal(CloneConfig(c))
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// CloneConfig is a deep copy of c with nil rules made empty.
func CloneConfig(c rules.Config) rules.Config {
	c = c.Clone()
	if c.Rules == nil {
		c.Rules = []rules.Rule{}
	}
	return c
}

// CleanRulesetName trims a profile name and checks it: 1–40 characters,
// no control or format characters (line breaks, bidi overrides,
// zero-width).
func CleanRulesetName(s string) (string, error) {
	s = strings.TrimSpace(s)
	bad := s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxRulesetName
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			bad = true
		}
	}
	if bad {
		return s, errRulesetName
	}
	return s, nil
}

// errRulesetName is a sentence for the user (a type of its own: it starts
// with a capital letter).
var errRulesetName error = sentence("Название профиля правил: от 1 до 40 символов, без управляющих символов")

type sentence string

func (e sentence) Error() string { return string(e) }

// UniqueRulesetName returns name, or «name (2)», «name (3)»… when a profile
// of list already has it (ignoring case), shortened to fit the limit.
func UniqueRulesetName(list []Ruleset, name string) string {
	taken := func(n string) bool {
		for _, e := range list {
			if strings.EqualFold(e.Name, n) {
				return true
			}
		}
		return false
	}
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf(" (%d)", i)
		base := []rune(name)
		if max := MaxRulesetName - utf8.RuneCountInString(suffix); len(base) > max {
			base = base[:max]
		}
		n := strings.TrimSpace(string(base)) + suffix
		if !taken(n) {
			return n
		}
	}
}
