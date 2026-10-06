// Package apply edits a server's Hysteria config: the config as the
// editor sees it (secrets masked), the candidate built from the editor's
// text or fields, its check and diff, and the job that installs it with a
// rollback.
package apply

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Hidden stands for a secret the editor does not show; a candidate that
// keeps it keeps the current value.
const Hidden = redact.Mask

// secretValue: a scalar under this key is a secret (the whole value).
func secretValue(key, parent string) bool {
	return strings.EqualFold(parent, "userpass") || redact.IsSecretKey(key)
}

// secret is a scalar of a document that holds a secret, at the path where
// the document defines it.
type secret struct {
	path string
	node *yaml.Node
}

// secretsOf lists the secret scalars of a document in document order:
//   - values under secret-named keys and every password of userpass;
//   - the anchored value an alias in such a place points to (the value is
//     defined under a harmless key and only used as a password);
//   - any string that carries a secret pattern: a password inside a URL,
//     a share link, a private key.
func secretsOf(doc *yaml.Node) []secret {
	var out []secret
	seen := map[*yaml.Node]bool{}
	pathOf := map[*yaml.Node]string{}
	add := func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode && n.Value != "" && !seen[n] {
			seen[n] = true
			out = append(out, secret{pathOf[n], n})
		}
	}
	// values adds every value inside n (the keys of a userpass mapping
	// are user names).
	var values func(n *yaml.Node)
	values = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.ScalarNode:
			add(n)
		case yaml.MappingNode:
			for i := 1; i < len(n.Content); i += 2 {
				values(n.Content[i])
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				values(c)
			}
		case yaml.AliasNode:
			if n.Alias != nil {
				values(n.Alias)
			}
		}
	}
	walk(doc, "", "", func(n *yaml.Node, p, key, parent string) {
		if _, ok := pathOf[n]; !ok {
			pathOf[n] = p
		}
		switch n.Kind {
		case yaml.ScalarNode:
			if secretValue(key, parent) || redact.String(n.Value) != n.Value {
				add(n)
			}
		case yaml.AliasNode:
			if n.Alias == nil {
				return
			}
			switch {
			case strings.EqualFold(key, "userpass") && parent != "userpass":
				values(n.Alias)
			case secretValue(key, parent) && n.Alias.Kind == yaml.ScalarNode:
				add(n.Alias)
			}
		}
	})
	return out
}

// maskComments redacts secret patterns in the comments of every node.
func maskComments(doc *yaml.Node) {
	walk(doc, "", "", func(n *yaml.Node, _, _, _ string) {
		n.HeadComment, n.LineComment, n.FootComment = redact.String(n.HeadComment), redact.String(n.LineComment), redact.String(n.FootComment)
	})
	// Keys carry comments of their own.
	var keys func(n *yaml.Node)
	keys = func(n *yaml.Node) {
		for i, c := range n.Content {
			if n.Kind == yaml.MappingNode && i%2 == 0 {
				c.HeadComment, c.LineComment, c.FootComment = redact.String(c.HeadComment), redact.String(c.LineComment), redact.String(c.FootComment)
			}
			keys(c)
		}
	}
	keys(doc)
}

func hide(n *yaml.Node) { n.Value, n.Tag, n.Style = Hidden, "!!str", 0 }

// Mask hides the secret values of a config (see secretsOf) and secret
// patterns in its comments. Order and comments stay. It also lists the
// paths of the secrets it hid.
func Mask(b []byte) ([]byte, []string, error) {
	doc, err := parse(b)
	if err != nil {
		return nil, nil, err
	}
	var paths []string
	for _, s := range secretsOf(doc) {
		hide(s.node)
		paths = append(paths, s.path)
	}
	maskComments(doc)
	out, err := encode(doc)
	return out, paths, err
}

// MaskUnchanged hides the secrets of a candidate that are the same as in
// current; new ones (typed or generated) stay visible, so the next edit
// round-trips them.
func MaskUnchanged(candidate, current []byte) ([]byte, error) {
	cand, err := parse(candidate)
	if err != nil {
		return nil, err
	}
	cur, err := parse(current)
	if err != nil {
		return nil, err
	}
	// The secrets of either side: a value that was a secret through an
	// alias in current is a plain copy after the typed model. By path
	// only: the editor sends this text back, and Unmask restores a hidden
	// value from the same path.
	for _, s := range secretsOf(cand) {
		if v := lookup(cur, s.path); v != nil && v.Kind == yaml.ScalarNode && v.Value == s.node.Value {
			hide(s.node)
		}
	}
	for _, s := range secretsOf(cur) {
		if n := lookup(cand, s.path); n != nil && n.Kind == yaml.ScalarNode && n.Value == s.node.Value {
			hide(n)
		}
	}
	// The stats secret is the panel's: never shown, even when new.
	if n := lookup(cand, statsSecret); n != nil && n.Kind == yaml.ScalarNode && n.Value != "" {
		hide(n)
	}
	maskComments(cand)
	return encode(cand)
}

// HideCurrent hides in a check's text every secret equal to a secret of
// current anywhere (a renamed list item keeps its password) and diffs it
// again. Only for checks whose text never comes back as a candidate: a
// hidden value there would be restored from its own path.
func HideCurrent(ch *Check, current []byte) error {
	doc, err := parse([]byte(ch.YAML))
	if err != nil {
		return err
	}
	cur, err := parse(current)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, s := range secretsOf(cur) {
		known[s.node.Value] = true
	}
	for _, s := range secretsOf(doc) {
		if known[s.node.Value] {
			hide(s.node)
		}
	}
	out, err := encode(doc)
	if err != nil {
		return err
	}
	curMasked, _, err := Mask(current)
	if err != nil {
		return err
	}
	ch.YAML, ch.Diff = string(out), Diff(string(curMasked), string(out))
	return nil
}

// statsSecret is the path of the stats API's secret.
const statsSecret = "trafficstats.secret"

// fillStatsSecret generates the stats secret a candidate keeps Hidden
// when current has none: the editor never shows a new one, so the text it
// sends back hides it too.
func fillStatsSecret(candidate, current []byte) ([]byte, error) {
	cand, err := parse(candidate)
	if err != nil {
		return nil, err
	}
	n := lookup(cand, statsSecret)
	if n == nil || n.Kind != yaml.ScalarNode || n.Value != Hidden {
		return candidate, nil
	}
	if cur, err := parse(current); err == nil {
		if v := lookup(cur, statsSecret); v != nil && v.Kind == yaml.ScalarNode && v.Value != "" {
			return candidate, nil // Unmask puts it back
		}
	}
	n.Value, n.Tag, n.Style = generated(), "!!str", 0
	return encode(cand)
}

// Unmask puts the current secrets back where the candidate keeps Hidden,
// and the current comments where the candidate keeps their masked form.
// Lists are matched by the "name" of their items (outbounds), else by
// position. A Hidden with nothing behind it is a *model.FieldError.
func Unmask(candidate, current []byte) ([]byte, error) {
	cand, err := parse(candidate)
	if err != nil {
		return nil, err
	}
	cur, err := parse(current)
	if err != nil {
		return nil, fmt.Errorf("текущий конфиг: %w", err)
	}
	var bad []string
	unmaskComments(cand, cur) // above and below the whole file
	walk(cand, "", "", func(n *yaml.Node, p, key, parent string) {
		if n.Kind == yaml.DocumentNode {
			return
		}
		v := lookup(cur, p)
		if v != nil {
			unmaskComments(n, v)
			// The keys hold the comments above and below their entries.
			if n.Kind == yaml.MappingNode && v.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(n.Content); i += 2 {
					if k := keyOf(v, n.Content[i].Value); k != nil {
						unmaskComments(n.Content[i], k)
					}
				}
			}
		}
		if n.Kind != yaml.ScalarNode || n.Value != Hidden {
			return
		}
		if v == nil || v.Kind != yaml.ScalarNode {
			bad = append(bad, p)
			return
		}
		n.Value, n.Tag, n.Style = v.Value, v.Tag, v.Style
	})
	if len(bad) > 0 {
		return nil, &model.FieldError{Field: bad[0], Msg: "Значение скрыто, но в текущем конфиге его нет: введите его в поле " + bad[0] + "."}
	}
	return encode(cand)
}

// unmaskComments gives n back the comments of v that n keeps in their
// masked form.
func unmaskComments(n, v *yaml.Node) {
	for _, c := range [][2]*string{{&n.HeadComment, &v.HeadComment}, {&n.LineComment, &v.LineComment}, {&n.FootComment, &v.FootComment}} {
		if *c[0] != *c[1] && *c[0] == redact.String(*c[1]) {
			*c[0] = *c[1]
		}
	}
}

// keyOf is the key node of mapping m named k (as paths match keys).
func keyOf(m *yaml.Node, k string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, k) {
			return m.Content[i]
		}
	}
	return nil
}

// ChangedSecrets are the paths of secrets that differ between two
// configs (both unmasked): the diff of masked texts does not show them.
func ChangedSecrets(before, after []byte) []string {
	a, err1 := parse(before)
	b, err2 := parse(after)
	if err1 != nil || err2 != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	check := func(x, y *yaml.Node) {
		for _, s := range secretsOf(x) {
			if seen[s.path] {
				continue
			}
			seen[s.path] = true
			if o := lookup(y, s.path); o == nil || o.Kind != yaml.ScalarNode || o.Value != s.node.Value {
				out = append(out, s.path)
			}
		}
	}
	check(b, a)
	check(a, b)
	return out
}

func parse(b []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, errors.New("конфиг пуст")
	}
	return &doc, nil
}

func encode(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// walk visits every node with its path ("auth.password",
// "outbounds[proxy].socks5.password", "outbounds[2].name"), its key and
// the key of the mapping that holds it.
func walk(n *yaml.Node, p, key string, fn func(n *yaml.Node, p, key, parent string)) {
	walkIn(n, p, key, "", fn)
}

func walkIn(n *yaml.Node, p, key, parent string, fn func(*yaml.Node, string, string, string)) {
	fn(n, p, key, parent)
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkIn(c, p, key, parent, fn)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			walkIn(n.Content[i+1], join(p, k), k, key, fn)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			walkIn(c, p+"["+itemID(c, i)+"]", key, parent, fn)
		}
	}
}

func join(p, k string) string {
	if p == "" {
		return strings.ToLower(k)
	}
	return p + "." + strings.ToLower(k)
}

// itemID names a list item: its "name" when it has one, else its index.
func itemID(n *yaml.Node, i int) string {
	if n.Kind == yaml.MappingNode {
		for j := 0; j+1 < len(n.Content); j += 2 {
			if strings.EqualFold(n.Content[j].Value, "name") && n.Content[j+1].Kind == yaml.ScalarNode && n.Content[j+1].Value != "" {
				return "name=" + n.Content[j+1].Value
			}
		}
	}
	return strconv.Itoa(i)
}

// lookup finds the node at path p (as walk writes paths), following
// aliases: the typed model writes an alias out as a copy of its value.
func lookup(doc *yaml.Node, p string) *yaml.Node {
	var found *yaml.Node
	inside := map[*yaml.Node]bool{} // aliases being followed (no cycles)
	var visit func(n *yaml.Node, q, key, parent string)
	visit = func(n *yaml.Node, q, key, parent string) {
		if found != nil {
			return
		}
		if n.Kind == yaml.AliasNode && n.Alias != nil {
			if inside[n] {
				return
			}
			inside[n] = true
			visit(n.Alias, q, key, parent)
			delete(inside, n)
			return
		}
		if q == p && n.Kind != yaml.DocumentNode {
			found = n
			return
		}
		if q != "" && !strings.HasPrefix(p, q) {
			return // not on the way to p
		}
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				visit(c, q, key, parent)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i].Value
				visit(n.Content[i+1], join(q, k), k, key)
			}
		case yaml.SequenceNode:
			// Only the item at index i can be [i] (a named one is
			// [name=…]): a long list (an inline ACL) is not scanned for it.
			if id, ok := strings.CutPrefix(p[len(q):], "["); ok {
				if id, _, ok = strings.Cut(id, "]"); ok {
					if i, err := strconv.Atoi(id); err == nil {
						if i >= 0 && i < len(n.Content) && itemID(n.Content[i], i) == id {
							visit(n.Content[i], q+"["+id+"]", key, parent)
						}
						return
					}
				}
			}
			for i, c := range n.Content {
				visit(c, q+"["+itemID(c, i)+"]", key, parent)
			}
		}
	}
	visit(doc, "", "", "")
	return found
}
