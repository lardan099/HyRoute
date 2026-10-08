package reconcile

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// The summaries say what differs for people and for events: names, paths
// and section names, never a value (a password, an address).

func configSummary(file string, rev int, before, after []byte, missing bool) string {
	if missing {
		return fmt.Sprintf("Конфига Hysteria %s на сервере нет; HyRoute записал ревизию %d.", file, rev)
	}
	s := fmt.Sprintf("Конфиг Hysteria %s изменён вне HyRoute: он не такой, как ревизия %d.", file, rev)
	names, ok := sections(before, after)
	switch {
	case !ok:
		s += " Конфиг на сервере не читается как YAML."
	case len(names) == 0:
		s += " Отличаются только комментарии или оформление."
	default:
		s += " Изменены разделы: " + strings.Join(names, ", ") + "."
	}
	return s
}

// sectionRe is a section name that may be shown: what Hysteria names its
// sections like. Others are counted, not named.
var sectionRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// sections are the top-level keys whose values (with their comments)
// differ between two configs, in the order of after then before; ok is
// false when either is not a YAML mapping.
func sections(before, after []byte) (names []string, ok bool) {
	a, okA := topLevel(before)
	b, okB := topLevel(after)
	if !okA || !okB {
		return nil, false
	}
	var keys []string
	for _, m := range []*orderedMap{b, a} {
		for _, k := range m.keys {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	others := 0
	for _, k := range keys {
		if a.values[k] == b.values[k] {
			continue
		}
		if sectionRe.MatchString(k) {
			names = append(names, k)
		} else {
			others++
		}
	}
	if others > 0 {
		names = append(names, fmt.Sprintf("ещё %d с другими именами", others))
	}
	return names, true
}

type orderedMap struct {
	keys   []string
	values map[string]string
}

// topLevel is each top-level key of a config with its value encoded.
func topLevel(b []byte) (*orderedMap, bool) {
	m := &orderedMap{values: map[string]string{}}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, false
	}
	if doc.Kind == 0 {
		return m, true // empty
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false
	}
	n := doc.Content[0]
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		kb, err1 := yaml.Marshal(k)
		vb, err2 := yaml.Marshal(v)
		if err1 != nil || err2 != nil {
			return nil, false
		}
		if _, dup := m.values[k.Value]; !dup {
			m.keys = append(m.keys, k.Value)
		}
		m.values[k.Value] += string(kb) + string(vb)
	}
	return m, true
}

func unitSummary(name string, files []string, missing bool) string {
	if missing {
		return fmt.Sprintf("Службы %s на сервере нет: её файл удалён вне HyRoute.", name)
	}
	s := fmt.Sprintf("Служба %s изменена вне HyRoute. Файлы службы сейчас: %s.", name, strings.Join(files, ", "))
	if len(files) > 1 {
		s += " Дополнения (drop-in) HyRoute не ставит и не убирает."
	}
	return s
}

func binarySummary(file, version string, missing bool) string {
	if missing {
		return fmt.Sprintf("Бинарника Hysteria %s на сервере нет.", file)
	}
	if version != "" {
		return fmt.Sprintf("Бинарник Hysteria %s заменён вне HyRoute: это не тот файл, что записал HyRoute (Hysteria %s).", file, version)
	}
	return fmt.Sprintf("Бинарник Hysteria %s заменён вне HyRoute: это не тот файл, что записал HyRoute.", file)
}

func geoSummary(files []model.DriftFile, release string) string {
	var parts []string
	for _, f := range files {
		if f.Got == "" {
			parts = append(parts, path.Base(f.Path)+" удалён")
		} else {
			parts = append(parts, path.Base(f.Path)+" заменён")
		}
	}
	return fmt.Sprintf("Базы geo изменены вне HyRoute (HyRoute ставил релиз %s): %s.", release, strings.Join(parts, ", "))
}

func linkSummary(chain string, idx, nodes int, files []model.DriftFile, units []string) string {
	var parts []string
	for _, f := range files {
		unit := strings.HasSuffix(f.Path, ".service")
		switch {
		case unit && f.Got == "":
			parts = append(parts, "службы "+f.Path+" нет")
		case unit:
			parts = append(parts, "служба "+f.Path+" изменена (файлы: "+strings.Join(units, ", ")+")")
		case f.Got == "":
			parts = append(parts, "конфига клиента связи "+f.Path+" нет")
		default:
			parts = append(parts, "конфиг клиента связи "+f.Path+" изменён")
		}
	}
	link := fmt.Sprintf("Связь каскада «%s»", chain)
	if nodes > 2 {
		link += fmt.Sprintf(" (участок %d из %d)", idx+1, nodes-1)
	}
	return link + " изменена вне HyRoute: " + strings.Join(parts, "; ") + "."
}
