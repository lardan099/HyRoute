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

// Mask hides the secret values of a config: fields named like secrets
// and every password of userpass. Order and comments stay. It also lists
// the paths of the secrets it hid.
func Mask(b []byte) ([]byte, []string, error) {
	doc, err := parse(b)
	if err != nil {
		return nil, nil, err
	}
	var paths []string
	walk(doc, "", "", func(n *yaml.Node, p, key, parent string) {
		if n.Kind == yaml.ScalarNode && n.Value != "" && secretValue(key, parent) {
			n.Value, n.Tag, n.Style = Hidden, "!!str", 0
			paths = append(paths, p)
		}
	})
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
	walk(cand, "", "", func(n *yaml.Node, p, key, parent string) {
		if n.Kind != yaml.ScalarNode || n.Value == "" || !secretValue(key, parent) {
			return
		}
		if v := lookup(cur, p); v != nil && v.Kind == yaml.ScalarNode && v.Value == n.Value {
			n.Value, n.Tag, n.Style = Hidden, "!!str", 0
		}
	})
	return encode(cand)
}

// Unmask puts the current secrets back where the candidate keeps Hidden.
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
	walk(cand, "", "", func(n *yaml.Node, p, key, parent string) {
		if n.Kind != yaml.ScalarNode || n.Value != Hidden {
			return
		}
		v := lookup(cur, p)
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
		walk(x, "", "", func(n *yaml.Node, p, key, parent string) {
			if n.Kind != yaml.ScalarNode || !secretValue(key, parent) || seen[p] {
				return
			}
			seen[p] = true
			if o := lookup(y, p); o == nil || o.Kind != yaml.ScalarNode || o.Value != n.Value {
				out = append(out, p)
			}
		})
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

// lookup finds the node at path p (as walk writes paths).
func lookup(doc *yaml.Node, p string) *yaml.Node {
	var found *yaml.Node
	walk(doc, "", "", func(n *yaml.Node, q, _, _ string) {
		if found == nil && q == p && n.Kind != yaml.DocumentNode {
			found = n
		}
	})
	return found
}
