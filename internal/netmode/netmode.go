// Package netmode holds network rules ("Сети"): what HyRoute does when the
// computer moves to another network. Pure logic; reading the networks is
// internal/netwatch's job.
package netmode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Version is the format of networks.json.
const Version = 1

// Connect values.
const (
	Keep       = ""           // «Не менять»
	Connect    = "connect"    // «Подключить»
	Disconnect = "disconnect" // «Отключить — всё напрямую»
)

// Category and adapter kinds.
const (
	Public, Private, Domain       = "public", "private", "domain"
	WiFi, Ethernet, Mobile, Other = "wifi", "ethernet", "mobile", "other"
)

// UnknownName is the decision when no rule matches.
const UnknownName = "Неизвестная сеть"

// Limits of networks.json (checked on load and save).
const (
	MaxFileSize  = 1 << 20
	MaxRules     = 100
	MaxItems     = 32 // values in one condition group
	MaxRuleName  = 100
	MaxNetName   = 256 // Windows network names and «Именно эта сеть» names
	maxSSIDBytes = 32
)

// ErrSSIDDenied: Windows refused the Wi-Fi name (location privacy in
// Windows 11 24H2 and later).
var ErrSSIDDenied error = sentence("Windows не даёт HyRoute имя Wi-Fi")

// sentence is an error message that is a sentence of its own (it starts
// with a capital letter: shown to the user as is).
type sentence string

func (e sentence) Error() string { return string(e) }

func sentencef(format string, a ...any) error { return sentence(fmt.Sprintf(format, a...)) }

// Action is what a network rule does: the ruleset first, then the
// connection.
type Action struct {
	Connect string `json:"connect,omitempty"`
	Ruleset string `json:"ruleset,omitempty"`
}

// None: the action changes nothing.
func (a Action) None() bool { return a.Connect == Keep && a.Ruleset == "" }

// Known is a network Windows identified («Именно эта сеть»).
type Known struct {
	ID   string `json:"id"`   // NLM network ID "{GUID}"
	Name string `json:"name"` // shown only
}

// Match holds a rule's conditions: every filled group must hold, any value
// inside a group.
type Match struct {
	Networks   []Known  `json:"networks,omitempty"`
	SSIDs      []string `json:"ssids,omitempty"`
	Names      []string `json:"names,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Adapters   []string `json:"adapters,omitempty"`
}

// Empty: no condition at all (never valid in a rule).
func (m Match) Empty() bool {
	return len(m.Networks) == 0 && len(m.SSIDs) == 0 && len(m.Names) == 0 && len(m.Categories) == 0 && len(m.Adapters) == 0
}

// Rule is one network rule.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty"`
	Match   Match  `json:"match"`
	Action
}

// On: the rule is enabled (omitted = on).
func (r Rule) On() bool { return r.Enabled == nil || *r.Enabled }

// Config is networks.json.
type Config struct {
	Version int    `json:"version"`
	Enabled bool   `json:"enabled"`
	Rules   []Rule `json:"rules"`
	Unknown Action `json:"unknown"`
}

// Default is the configuration without networks.json: off, no rules, and
// «Неизвестная сеть: подключить» (fail closed). Parse never applies it: a
// file without "unknown" means «Не менять».
func Default() Config {
	return Config{Version: Version, Rules: []Rule{}, Unknown: Action{Connect: Connect}}
}

// Clone is a deep copy.
func (c Config) Clone() Config {
	out := c
	out.Rules = make([]Rule, len(c.Rules))
	for i, r := range c.Rules {
		if r.Enabled != nil {
			v := *r.Enabled
			r.Enabled = &v
		}
		r.Match = Match{
			Networks:   append([]Known(nil), r.Match.Networks...),
			SSIDs:      append([]string(nil), r.Match.SSIDs...),
			Names:      append([]string(nil), r.Match.Names...),
			Categories: append([]string(nil), r.Match.Categories...),
			Adapters:   append([]string(nil), r.Match.Adapters...),
		}
		out.Rules[i] = r
	}
	return out
}

// Network is what Windows reports about one connected network.
type Network struct {
	ID          string `json:"id"`          // NLM network ID, "" unknown
	Name        string `json:"name"`        // NLM name (Wi-Fi: usually the SSID)
	Category    string `json:"category"`    // public|private|domain|""
	Adapter     string `json:"adapter"`     // wifi|ethernet|mobile|other
	AdapterName string `json:"adapterName"` // friendly name, UI only
	SSID        string `json:"ssid"`        // "" not Wi-Fi / not asked / refused
	SSIDDenied  bool   `json:"ssidDenied"`  // Windows refused the SSID (location privacy)
	// Identified: ID belongs to a network Windows has identified;
	// false for «Идентификация…» / «Неопознанная сеть», whose GUID may be
	// shared. Without it the ID is shown but never matched, never added by
	// «Добавить текущую» and never part of Ident.
	Identified bool `json:"identified"`

	// Change detection only: never matched, never shown, never logged
	// (json "-" keeps them out of the UI, Status and the CLI).
	AdapterID  string `json:"-"` // adapter GUID "{…}"
	GatewayIP  string `json:"-"` // default gateway of the adapter (IPv4 if any, else IPv6), "" unknown
	GatewayMAC string `json:"-"` // its MAC from the neighbour table, "" not resolved yet
}

// Ident is what change detection compares: what stays the same while the
// computer stays on one network. Category, SSID and names are left out on
// purpose (they change without the network changing: Settings, the location
// permission, which fields HyRoute asks for).
type Ident struct {
	NetID      string // NLM network ID, upper-case; "" none/unknown
	AdapterID  string
	GatewayIP  string
	GatewayMAC string
}

// Ident of n (nil → zero); NetID only when Windows identified the network.
func (n *Network) Ident() Ident {
	if n == nil {
		return Ident{}
	}
	id := Ident{AdapterID: n.AdapterID, GatewayIP: n.GatewayIP, GatewayMAC: n.GatewayMAC}
	if n.Identified && n.ID != "" {
		id.NetID = strings.ToUpper(n.ID)
	}
	return id
}

// Empty: no NetID and no AdapterID (no network).
func (i Ident) Empty() bool { return i.NetID == "" && i.AdapterID == "" }

// Hash8 is the first 8 hex of SHA-256 over the fields: Debug log
// correlation only.
func (i Ident) Hash8() string {
	if i.Empty() {
		return "-"
	}
	h := sha256.Sum256([]byte(strings.ToUpper(i.NetID) + "\x00" + strings.ToUpper(i.AdapterID) + "\x00" + i.GatewayIP + "\x00" + i.GatewayMAC))
	return hex.EncodeToString(h[:4])
}

// Fill copies GatewayIP/GatewayMAC from r where i has them empty (baseline
// learning from Same/Refined reads).
func (i *Ident) Fill(r Ident) {
	if i.GatewayIP == "" {
		i.GatewayIP = r.GatewayIP
	}
	if i.GatewayMAC == "" {
		i.GatewayMAC = r.GatewayMAC
	}
}

// macsDiffer: both MACs are known and different.
func macsDiffer(a, b Ident) bool {
	return a.GatewayMAC != "" && b.GatewayMAC != "" && !strings.EqualFold(a.GatewayMAC, b.GatewayMAC)
}

// link: the same adapter and gateway IP, MACs not known-and-different.
func link(a, b Ident) bool {
	return strings.EqualFold(a.AdapterID, b.AdapterID) && a.GatewayIP == b.GatewayIP && !macsDiffer(a, b)
}

// SameRead: a later read of the same pending identity: NetID equal, same
// AdapterID and GatewayIP, MACs not known-and-different.
func SameRead(a, b Ident) bool {
	return strings.EqualFold(a.NetID, b.NetID) && link(a, b)
}

// Refines: b is a with its NLM ID now (a had none; the same link).
func Refines(a, b Ident) bool {
	return a.NetID == "" && b.NetID != "" && link(a, b)
}

// Relation of a read to the baseline.
type Relation int

const (
	Same    Relation = iota // the baseline network (proved by the NLM ID or by both gateway MACs)
	Refined                 // the baseline network, now with its NLM ID
	Unclear                 // no ID, same adapter and gateway IP, a MAC unknown: cannot tell
	Changed                 // another network
)

func (r Relation) String() string {
	switch r {
	case Same:
		return "same"
	case Refined:
		return "refined"
	case Unclear:
		return "unclear"
	}
	return "changed"
}

// Compare classifies a read against the baseline:
//
//	base empty                                   → Changed
//	both NetIDs set:  EqualFold                  → Same, else Changed
//	cur.NetID set, base.NetID "": link           → Refined, else Changed
//	cur.NetID "":                 link           → Same if both MACs known and equal, else Unclear;
//	                                               no link → Changed
//
// link = same AdapterID && gateway IP equal (both "" counts as equal) &&
// !(both GatewayMACs known && different).
func Compare(base, cur Ident) Relation {
	switch {
	case base.Empty():
		return Changed
	case base.NetID != "" && cur.NetID != "":
		if strings.EqualFold(base.NetID, cur.NetID) {
			return Same
		}
		return Changed
	case cur.NetID != "":
		if link(base, cur) {
			return Refined
		}
		return Changed
	case !link(base, cur):
		return Changed
	case base.GatewayMAC != "" && cur.GatewayMAC != "":
		return Same // link: equal
	}
	return Unclear
}

// Decision is the rule a network gets.
type Decision struct {
	RuleID  string // "" for unknown
	Name    string // rule name, or UnknownName
	Unknown bool
	Action
}

// UnknownDecision is «Неизвестная сеть» with cfg.Unknown.
func UnknownDecision(cfg Config) Decision {
	return Decision{Name: UnknownName, Unknown: true, Action: cfg.Unknown}
}

// Decide: the first enabled rule whose conditions all hold, else Unknown.
func Decide(cfg Config, n Network) Decision {
	for _, r := range cfg.Rules {
		if r.On() && r.Match.Matches(n) {
			return Decision{RuleID: r.ID, Name: r.Name, Action: r.Action}
		}
	}
	return UnknownDecision(cfg)
}

// Matches reports whether one rule's conditions hold (an empty match
// never does).
func (m Match) Matches(n Network) bool {
	if m.Empty() {
		return false
	}
	if len(m.Networks) > 0 && !m.networkHolds(n) {
		return false
	}
	if len(m.SSIDs) > 0 && !m.ssidHolds(n) {
		return false
	}
	if len(m.Names) > 0 && !anyFold(m.Names, n.Name) {
		return false
	}
	if len(m.Categories) > 0 && (n.Category == "" || !contains(m.Categories, n.Category)) {
		return false
	}
	if len(m.Adapters) > 0 && !contains(m.Adapters, n.Adapter) {
		return false
	}
	return true
}

func (m Match) networkHolds(n Network) bool {
	if !n.Identified || n.ID == "" {
		return false
	}
	for _, k := range m.Networks {
		if strings.EqualFold(k.ID, n.ID) {
			return true
		}
	}
	return false
}

// ssidHolds: Wi-Fi only; the exact stored form, or the NLM name while
// Windows does not give the SSID (denied or not asked).
func (m Match) ssidHolds(n Network) bool {
	if n.Adapter != WiFi {
		return false
	}
	have := n.SSID
	if have == "" {
		have = n.Name
	}
	return have != "" && contains(m.SSIDs, have)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func anyFold(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// UsesSSID: an enabled rule has an SSID condition (only then the WLAN API
// is asked).
func UsesSSID(cfg Config) bool {
	for _, r := range cfg.Rules {
		if r.On() && len(r.Match.SSIDs) > 0 {
			return true
		}
	}
	return false
}

// Protective is the part of d that may run on an unconfirmed read: Connect
// when d says Connect, or when !identified and cfg.Unknown says Connect;
// Ruleset = cfg.Unknown.Ruleset when rsByNetwork (the active ruleset was set
// by a network rule) and it differs from activeRS.
func Protective(cfg Config, d Decision, identified bool, activeRS string, rsByNetwork bool) Action {
	var p Action
	if d.Connect == Connect || (!identified && cfg.Unknown.Connect == Connect) {
		p.Connect = Connect
	}
	if rsByNetwork && cfg.Unknown.Ruleset != "" && cfg.Unknown.Ruleset != activeRS {
		p.Ruleset = cfg.Unknown.Ruleset
	}
	return p
}

// Relaxing reports whether d has anything Protective left out (a
// disconnect, or a ruleset other than the protective one): only then does
// a start wait for the confirming read.
func Relaxing(d Decision, p Action) bool {
	return d.Connect == Disconnect || (d.Ruleset != "" && d.Ruleset != p.Ruleset)
}

// SelectsRuleset: an enabled rule (not «Неизвестная сеть») switches to id.
func SelectsRuleset(cfg Config, id string) bool {
	if id == "" {
		return false
	}
	for _, r := range cfg.Rules {
		if r.On() && r.Ruleset == id {
			return true
		}
	}
	return false
}

// Snapshot is what Windows reports: the network of the default route and
// the others.
type Snapshot struct {
	Active *Network  `json:"active"` // carries the default route; nil = none
	Others []Network `json:"others"`
	Err    string    `json:"error,omitempty"` // partial failure (NLM, WLAN)
	// NLMDown: the NLM thread hung too often and is no longer restarted;
	// IDs, names and categories stay empty until HyRoute restarts.
	NLMDown bool `json:"nlmDown,omitempty"`
}

// Clone is a deep copy.
func (s Snapshot) Clone() Snapshot {
	out := s
	if s.Active != nil {
		a := *s.Active
		out.Active = &a
	}
	out.Others = append([]Network(nil), s.Others...)
	return out
}

// ---- file ----

var (
	idRe   = regexp.MustCompile(`^[0-9a-f]{8,32}$`)
	guidRe = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
)

// ValidID reports whether id is a rule or ruleset ID (^[0-9a-f]{8,32}$).
func ValidID(id string) bool { return idRe.MatchString(id) }

// CanonGUID is g upper-cased with braces ("" when it is not a GUID).
func CanonGUID(g string) string {
	g = strings.ToUpper(strings.TrimSpace(g))
	if !strings.HasPrefix(g, "{") {
		g = "{" + g + "}"
	}
	if !guidRe.MatchString(g) {
		return ""
	}
	return g
}

// Parse decodes networks.json: BOM, size limit, unknown fields, version;
// then Normalize and Validate.
func Parse(b []byte) (Config, error) {
	if len(b) > MaxFileSize {
		return Config{}, errors.New("networks.json больше 1 МБ")
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, errors.New("лишние данные после JSON")
	}
	switch {
	case cfg.Version == 0:
		cfg.Version = Version
	case cfg.Version > Version:
		return Config{}, fmt.Errorf("networks.json создан более новой версией HyRoute (формат %d)", cfg.Version)
	case cfg.Version < 0:
		return Config{}, fmt.Errorf("неверная версия формата %d", cfg.Version)
	}
	Normalize(&cfg)
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Normalize trims names, drops empty values, dedupes, upper-cases GUIDs
// (with braces), names unnamed rules «Сеть N» and drops enabled: true. It
// builds new slices: the caller's are left alone. IDs are the caller's.
func Normalize(cfg *Config) {
	*cfg = cfg.Clone()
	if cfg.Rules == nil {
		cfg.Rules = []Rule{}
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = fmt.Sprintf("Сеть %d", i+1)
		}
		if r.Enabled != nil && *r.Enabled {
			r.Enabled = nil
		}
		m := &r.Match
		var nets []Known
		seen := map[string]bool{}
		for _, k := range m.Networks {
			id := CanonGUID(k.ID)
			if id == "" {
				id = strings.TrimSpace(k.ID) // Validate names it
			}
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			nets = append(nets, Known{ID: id, Name: strings.TrimSpace(k.Name)})
		}
		m.Networks = nets
		m.SSIDs = dedupe(m.SSIDs, false, false)
		m.Names = dedupe(m.Names, true, true)
		m.Categories = dedupe(m.Categories, true, false)
		m.Adapters = dedupe(m.Adapters, true, false)
	}
	cfg.Unknown.Ruleset = strings.TrimSpace(cfg.Unknown.Ruleset)
}

// dedupe drops empty and repeated values; trim trims them, fold compares
// case-insensitively (the first spelling stays).
func dedupe(list []string, trim, fold bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range list {
		if trim {
			s = strings.TrimSpace(s)
		}
		k := s
		if fold {
			k = strings.ToLower(s)
		}
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// Validate returns the first problem as a Russian message.
func Validate(cfg Config) error {
	if len(cfg.Rules) > MaxRules {
		return sentencef("Правил сетей больше %d", MaxRules)
	}
	ids := map[string]bool{}
	for i, r := range cfg.Rules {
		name := r.Name
		if badText(name) {
			// Not quoted: the name itself would break the message's line.
			return sentencef("Правило сети №%d: в названии не может быть управляющих символов и переводов строки", i+1)
		}
		if utf8.RuneCountInString(name) > MaxRuleName {
			return sentencef("Правило сети «%s…»: название длиннее %d символов", string([]rune(name)[:20]), MaxRuleName)
		}
		pre := "Правило сети «" + name + "»: "
		if r.ID != "" {
			if !ValidID(r.ID) {
				return sentencef("%sневерный id %q", pre, r.ID)
			}
			if ids[r.ID] {
				return sentencef("Два правила сетей с одним id %q", r.ID)
			}
			ids[r.ID] = true
		}
		m := r.Match
		if m.Empty() {
			return sentencef("%sукажите хотя бы одно условие", pre)
		}
		if max(len(m.Networks), len(m.SSIDs), len(m.Names), len(m.Categories), len(m.Adapters)) > MaxItems {
			return sentencef("%sбольше %d значений в одном условии", pre, MaxItems)
		}
		for _, k := range m.Networks {
			if !guidRe.MatchString(k.ID) {
				return sentencef("%sневерный идентификатор сети %q", pre, k.ID)
			}
			if utf8.RuneCountInString(k.Name) > MaxNetName {
				return sentencef("%sслишком длинное имя сети", pre)
			}
			if badText(k.Name) {
				return sentencef("%sв имени сети не может быть управляющих символов и переводов строки", pre)
			}
		}
		for _, s := range m.SSIDs {
			if _, ok := ParseSSID(s); !ok {
				return sentencef("%sимя Wi-Fi пустое или длиннее 32 байт", pre)
			}
		}
		for _, s := range m.Names {
			if utf8.RuneCountInString(s) > MaxNetName {
				return sentencef("%sслишком длинное имя сети", pre)
			}
			if badText(s) {
				return sentencef("%sв имени сети не может быть управляющих символов и переводов строки", pre)
			}
		}
		for _, s := range m.Categories {
			if s != Public && s != Private && s != Domain {
				return sentencef("%sнеизвестный тип сети %q", pre, s)
			}
		}
		for _, s := range m.Adapters {
			if s != WiFi && s != Ethernet && s != Mobile && s != Other {
				return sentencef("%sнеизвестный вид подключения %q", pre, s)
			}
		}
		if err := validateAction(pre, r.Action); err != nil {
			return err
		}
	}
	return validateAction(UnknownName+": ", cfg.Unknown)
}

// badText: s would break a line where it is shown (the diagnostics
// report, logs): invalid UTF-8, control characters, line or paragraph
// separators.
func badText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp)
	})
}

func validateAction(pre string, a Action) error {
	switch a.Connect {
	case Keep, Connect, Disconnect:
	default:
		return sentencef("%sнеизвестное действие %q", pre, a.Connect)
	}
	if a.Ruleset != "" && !ValidID(a.Ruleset) {
		return sentencef("%sневерный профиль правил %q", pre, a.Ruleset)
	}
	return nil
}

// SSIDString is the stored form of raw SSID bytes: the string when it is
// valid UTF-8 without control characters, else "hex:" and lowercase hex.
func SSIDString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) && !strings.ContainsFunc(string(raw), unicode.IsControl) && !strings.HasPrefix(string(raw), "hex:") {
		return string(raw)
	}
	return "hex:" + hex.EncodeToString(raw)
}

// ParseSSID is the raw bytes of a stored SSID (1–32 bytes).
func ParseSSID(s string) ([]byte, bool) {
	var raw []byte
	if h, ok := strings.CutPrefix(s, "hex:"); ok {
		b, err := hex.DecodeString(h)
		if err != nil || h != strings.ToLower(h) {
			return nil, false
		}
		raw = b
	} else {
		raw = []byte(s)
	}
	return raw, len(raw) >= 1 && len(raw) <= maxSSIDBytes
}

// Refs are the ruleset IDs the config refers to (rules and unknown), each
// once (backup contract B3).
func (c Config) Refs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, r := range c.Rules {
		add(r.Ruleset)
	}
	add(c.Unknown.Ruleset)
	return out
}

// Remap replaces each ruleset reference with f("ruleset", id); an empty
// result clears only the ruleset part of that action (a connect stays).
func (c *Config) Remap(f func(kind, id string) string) {
	for i := range c.Rules {
		if id := c.Rules[i].Ruleset; id != "" {
			c.Rules[i].Ruleset = f("ruleset", id)
		}
	}
	if id := c.Unknown.Ruleset; id != "" {
		c.Unknown.Ruleset = f("ruleset", id)
	}
}
