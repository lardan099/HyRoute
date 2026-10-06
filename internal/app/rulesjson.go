package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
)

// Rules JSON: a rules config as a file the user exports and imports
// (hyroutectl rules export/import, «Правила текстом» → JSON). Never stored
// by HyRoute. The envelope names every target ID it references, so a file
// from another computer maps onto the servers and groups of this one by
// exact name:
//
//	{"hyroute": "rules", "version": 1, "defaultAction": "tunnel", …,
//	 "rules": [ …rules.Rule as in settings.json… ],
//	 "targets": {"a1b2c3d4e5f6": {"name": "DE-1"}, "grp-…": {"name": "Auto", "group": true}}}

const rulesJSONVersion = 1

// rulesTarget describes a target ID of the file: its name at export time
// ("" = it no longer existed then) and whether it is a group.
type rulesTarget struct {
	Name  string `json:"name"`
	Group bool   `json:"group,omitempty"`
}

// rulesJSONOut is the envelope as exported.
type rulesJSONOut struct {
	HyRoute         string                 `json:"hyroute"`
	Version         int                    `json:"version"`
	DefaultAction   rules.Action           `json:"defaultAction"`
	DefaultProfile  string                 `json:"defaultProfile,omitempty"`
	DefaultFallback []string               `json:"defaultFallback,omitempty"`
	Rules           []rules.Rule           `json:"rules"`
	Targets         map[string]rulesTarget `json:"targets"`
}

// rulesJSONIn is the envelope as imported: rules one by one, the default
// route only when the file has one.
type rulesJSONIn struct {
	HyRoute         string                 `json:"hyroute"`
	Version         int                    `json:"version"`
	DefaultAction   *rules.Action          `json:"defaultAction"`
	DefaultProfile  string                 `json:"defaultProfile"`
	DefaultFallback []string               `json:"defaultFallback"`
	Rules           []json.RawMessage      `json:"rules"`
	Targets         map[string]rulesTarget `json:"targets"`
}

// formatRulesJSON writes cfg as the envelope; target names an ID (name ""
// when unknown).
func formatRulesJSON(cfg rules.Config, target func(id string) (name string, group bool)) ([]byte, error) {
	out := rulesJSONOut{HyRoute: "rules", Version: rulesJSONVersion, DefaultAction: cfg.DefaultAction,
		DefaultProfile: cfg.DefaultProfile, DefaultFallback: cfg.DefaultFallback, Rules: cfg.Rules, Targets: map[string]rulesTarget{}}
	if out.Rules == nil {
		out.Rules = []rules.Rule{}
	}
	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := out.Targets[id]; ok {
			return
		}
		name, group := target(id)
		out.Targets[id] = rulesTarget{Name: name, Group: group || groups.IsGroupID(id)}
	}
	add(cfg.DefaultProfile)
	for _, id := range cfg.DefaultFallback {
		add(id)
	}
	for _, r := range cfg.Rules {
		add(r.Profile)
		for _, id := range r.Fallback {
			add(id)
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // regexp:^a<b stays readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// targetLookup names IDs from a target list.
func targetLookup(ts []target) func(string) (string, bool) {
	return func(id string) (string, bool) {
		for _, t := range ts {
			if t.ID == id {
				return t.Name, t.Group
			}
		}
		return "", false
	}
}

// RulesJSONFor renders the rules the token names (as RulesTextFor) as the
// rules JSON envelope.
func (c *Controller) RulesJSONFor(token string) ([]byte, error) {
	c.mu.Lock()
	editID, err := c.rulesetTargetLocked(token)
	if errors.Is(err, errRulesetChanged) {
		err = rulesetChangedError("Профиль правил сменился, пока было открыто это окно: закройте его и откройте снова.")
	}
	var cfg rules.Config
	if p, ok := c.configOfLocked(editID); ok {
		cfg = p.Clone()
	}
	ts := c.targetsLocked()
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return formatRulesJSON(cfg, targetLookup(ts))
}

// RulesJSON is the active rules as the rules JSON envelope.
func (c *Controller) RulesJSON() ([]byte, error) { return c.RulesJSONFor("") }

// bom is the UTF-8 byte order mark (U+FEFF).
const bom = "\xef\xbb\xbf"

// looksLikeJSON: the first character that is not a space is "{".
func looksLikeJSON(text string) bool {
	return strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"+bom), "{")
}

// parseRules reads text as rules JSON or as rules text: format "json",
// "text" or "auto" (JSON when the first non-space character is "{").
// replace only matters for JSON: its default route is taken only when
// replacing all rules.
func parseRules(text, format string, replace bool, ts []target) RulesTextResult {
	if format == "json" || (format != "text" && looksLikeJSON(text)) {
		return parseRulesJSON([]byte(text), replace, ts)
	}
	return parseRulesText(text, ts)
}

// ParseRulesTextAs parses rules text or rules JSON (format "auto", "text"
// or "json") against the current servers and groups; replace: the result
// is to replace all rules (a JSON default route counts only then).
func (c *Controller) ParseRulesTextAs(text, format string, replace bool) RulesTextResult {
	c.mu.Lock()
	ts := c.targetsLocked()
	c.mu.Unlock()
	return parseRules(text, format, replace, ts)
}

// ApplyRulesTextAs is ApplyRulesText for a given format. An appended rule
// whose ID a current rule already has gets a new one.
func (c *Controller) ApplyRulesTextAs(text, format string, replace bool, g EditGuard) (SaveResult, RulesTextResult, error) {
	res := c.ParseRulesTextAs(text, format, replace)
	if len(res.Errors) > 0 {
		return SaveResult{}, res, fmt.Errorf("в тексте ошибки (%d): ничего не сохранено", len(res.Errors))
	}
	if res.HasDefault && !replace {
		return SaveResult{}, res, fmt.Errorf("строка «* -> …» меняет «Всё остальное», а «Добавить пачкой» только добавляет правила: уберите её или измените «Всё остальное» в режиме «Все правила»")
	}
	if !replace {
		// Appended rules go after whatever the list is now.
		g.Rev, g.EditRev = 0, 0
	}
	sr, err := c.editRulesIn(g, func(cfg *rules.Config) (bool, error) {
		if replace {
			cfg.Rules = res.Rules
		} else {
			used := map[string]bool{}
			for _, r := range cfg.Rules {
				used[r.ID] = true
			}
			// One the list has already (or an earlier line added) is not
			// added a second time; a copy that is off is switched on, as a
			// rule from a connection does. The keys are built once: a
			// Duplicate per line compiled the whole list again.
			keys := map[string]int{}
			for i, r := range cfg.Rules {
				if k := rules.RepeatKey(r); k != "" {
					if _, ok := keys[k]; !ok {
						keys[k] = i
					}
				}
			}
			skipped, enabled := 0, 0
			for _, r := range res.Rules {
				k := rules.RepeatKey(r)
				if i, ok := keys[k]; ok && k != "" {
					if !cfg.Rules[i].On() && r.On() {
						cfg.Rules[i].Enabled = nil
						enabled++
					} else {
						skipped++
					}
					continue
				}
				if r.ID != "" && used[r.ID] {
					r.ID = newID() // taken by a current rule
				}
				used[r.ID] = true
				if k != "" {
					keys[k] = len(cfg.Rules)
				}
				cfg.Rules = append(cfg.Rules, r)
			}
			if skipped > 0 {
				res.Skipped = skipped
				res.Summary += fmt.Sprintf(", из них уже были в списке и не добавлены: %d", skipped)
			}
			if enabled > 0 {
				res.Enabled = enabled
				res.Summary += fmt.Sprintf(", уже были, но выключены, и включены: %d", enabled)
			}
			if skipped == len(res.Rules) && !res.HasDefault {
				return false, nil // nothing new
			}
		}
		if res.HasDefault {
			cfg.DefaultAction, cfg.DefaultProfile, cfg.DefaultFallback = res.DefaultAction, res.DefaultProfile, res.DefaultFallback
		}
		return true, nil
	})
	return sr, res, err
}

// danglingID is what a target ID without a usable descriptor must look
// like to be kept (HyRoute's 12-hex and grp- IDs).
var danglingID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// parseRulesJSON reads the rules JSON envelope against the targets of this
// computer. Line in the result is the rule's number (1-based), 0 for the
// file and the default route.
func parseRulesJSON(b []byte, replace bool, ts []target) RulesTextResult {
	res := RulesTextResult{Rules: []rules.Rule{}, Errors: []RuleLine{}, Warnings: []RuleLine{}}
	fail := func(n int, f string, a ...any) { res.Errors = append(res.Errors, RuleLine{n, fmt.Sprintf(f, a...)}) }
	warn := func(n int, f string, a ...any) {
		res.Warnings = append(res.Warnings, RuleLine{n, fmt.Sprintf(f, a...)})
	}
	b = bytes.TrimPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte(bom))

	// What the file is, before any strictness: another kind of JSON gets
	// «not a rules file», not a complaint about its fields.
	var head struct {
		HyRoute string `json:"hyroute"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		fail(0, "Это не файл правил HyRoute: %s", jsonProblem(err))
		return res
	}
	switch {
	case head.HyRoute != "rules" || head.Version < 1:
		fail(0, "Это не файл правил HyRoute")
		return res
	case head.Version > rulesJSONVersion:
		fail(0, "Файл правил из более новой версии HyRoute (формат %d)", head.Version)
		return res
	}
	var in rulesJSONIn
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		if f, ok := unknownField(err); ok {
			fail(0, "Неизвестное поле «%s» — файл из более новой версии HyRoute?", f)
		} else {
			fail(0, "Файл правил не читается: %s", jsonProblem(err))
		}
		return res
	}

	byID := map[string]target{}
	for _, t := range ts {
		byID[t.ID] = t
	}
	// mapID turns a target ID of the file into one of this computer. what
	// prefixes the messages («YouTube»: or «Всё остальное»:).
	mapID := func(n int, what, id string) (string, bool) {
		if id == "" {
			return "", true // the main target
		}
		if _, ok := byID[id]; ok {
			return id, true
		}
		d, ok := in.Targets[id]
		name := strings.TrimSpace(d.Name)
		group := d.Group || groups.IsGroupID(id)
		noun := "сервер"
		if group {
			noun = "группа"
		}
		if !ok || name == "" {
			// A target that no longer existed at export (the user's own
			// rule whose server was deleted): kept, and refused by the
			// engine as in settings.json.
			if !danglingID.MatchString(id) {
				fail(n, "%sневерный id сервера", what)
				return "", false
			}
			if group {
				warn(n, "%sгруппа не найдена — соединения будут отклоняться", what)
			} else {
				warn(n, "%sсервер не найден — соединения будут отклоняться", what)
			}
			return id, true
		}
		var hits []target
		for _, t := range ts {
			if t.Group == group && strings.EqualFold(strings.TrimSpace(t.Name), name) {
				hits = append(hits, t)
			}
		}
		switch {
		case len(hits) == 1:
			return hits[0].ID, true
		case len(hits) > 1 && group:
			fail(n, "%sнесколько групп с именем «%s» — оставьте одну или поправьте файл", what, name)
		case len(hits) > 1:
			fail(n, "%sнесколько серверов с именем «%s» — оставьте один или поправьте файл", what, name)
		case group:
			fail(n, "%s%s «%s» не найдена — добавьте её в HyRoute или поправьте файл", what, noun, name)
		default:
			fail(n, "%s%s «%s» не найден — добавьте его в HyRoute или поправьте файл", what, noun, name)
		}
		return "", false
	}
	mapChain := func(n int, what string, ids []string) []string {
		if ids == nil {
			return nil
		}
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			if m, ok := mapID(n, what, id); ok {
				out = append(out, m)
			}
		}
		return out
	}

	seen := map[string]bool{}
	for i, raw := range in.Rules {
		n := i + 1
		var r rules.Rule
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&r); err != nil {
			if f, ok := unknownField(err); ok {
				fail(n, "неизвестное поле «%s» — файл из более новой версии HyRoute?", f)
			} else {
				fail(n, "%s", jsonProblem(err))
			}
			continue
		}
		what := ""
		if strings.TrimSpace(r.Name) != "" {
			what = "«" + strings.TrimSpace(r.Name) + "»: "
		}
		errsBefore := len(res.Errors)
		var ok bool
		if r.Profile, ok = mapID(n, what, r.Profile); !ok {
			continue
		}
		r.Fallback = mapChain(n, what, r.Fallback)
		if len(res.Errors) > errsBefore {
			continue
		}
		// Checked alone, as a line of rules text is (a disabled rule too,
		// without warnings: it matches nothing yet).
		rc := r
		rc.Name, rc.Enabled = "-", nil
		set, err := rules.Compile(rules.Config{Rules: []rules.Rule{rc}})
		if err != nil {
			msg := err.Error()
			if _, after, ok := strings.Cut(msg, ": "); ok {
				msg = after
			}
			fail(n, "%s%s", what, msg)
			continue
		}
		if r.On() {
			for _, w := range set.Warnings {
				if _, after, ok := strings.Cut(w, ": "); ok {
					w = after
				}
				warn(n, "%s%s", what, w)
			}
		}
		switch {
		case r.ID == "":
		case !danglingID.MatchString(r.ID):
			warn(n, "%sневерный id правила — выдан новый", what)
			r.ID = ""
		case seen[r.ID]:
			warn(n, "%sповторный id — выдан новый", what)
			r.ID = ""
		default:
			seen[r.ID] = true
		}
		res.Rules = append(res.Rules, r)
	}

	if in.DefaultAction != nil {
		// Without replace it is not mapped at all: a file from another
		// computer names servers this one may not have, and nothing of it
		// is used.
		const what = "«Всё остальное»: "
		if !replace {
			warn(0, "«Всё остальное» из файла не применено: оно меняется только вместе со всеми правилами (--replace, «Все правила»)")
		} else {
			prof, ok := mapID(0, what, in.DefaultProfile)
			fb := mapChain(0, what, in.DefaultFallback)
			if ok {
				res.HasDefault = true
				res.DefaultAction, res.DefaultProfile, res.DefaultFallback = *in.DefaultAction, prof, fb
			}
		}
	}
	if len(res.Errors) > 0 {
		res.Rules = []rules.Rule{}
	}
	res.Summary = fmt.Sprintf("Правил в файле: %d", len(in.Rules))
	if res.HasDefault {
		res.Summary += ", «Всё остальное»: " + targetWords(res.DefaultAction, res.DefaultProfile, res.DefaultFallback, ts)
	}
	return res
}

// unknownField is the field name of a DisallowUnknownFields error.
func unknownField(err error) (string, bool) {
	f, ok := strings.CutPrefix(err.Error(), "json: unknown field ")
	if !ok {
		return "", false
	}
	return strings.Trim(f, `"`), true
}

// jsonProblem words a JSON decoding error.
func jsonProblem(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("ошибка JSON у символа %d: %v", se.Offset, se)
	case errors.As(err, &te):
		if te.Field != "" {
			return fmt.Sprintf("поле «%s»: неверный тип значения", te.Field)
		}
		return "неверный тип значения"
	}
	return err.Error()
}
