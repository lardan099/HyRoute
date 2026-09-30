// Package hyconfig is a typed model of the Hysteria 2 server and client
// YAML configs (fields as in Hysteria app v2.12.3).
//
// Every mapping level keeps the keys the model does not know in Unknown and
// writes them back after the known ones, so fields of newer Hysteria
// versions survive a parse and a save. YAML comments do not survive.
// Keys match case-insensitively, as in Hysteria (viper lowercases them),
// and are written in their canonical spelling.
package hyconfig

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Unknown holds the keys of one mapping level that the model does not
// know, in their original order, as key and value node pairs.
type Unknown []*yaml.Node

// Keys lists the unknown key names.
func (u Unknown) Keys() []string {
	var ks []string
	for i := 0; i+1 < len(u); i += 2 {
		ks = append(ks, u[i].Value)
	}
	return ks
}

// Duration is a Go duration as written ("30s", "1m30s"). Hysteria also
// takes a bare integer as nanoseconds; such a value stays an integer when
// written back.
type Duration string

// MarshalYAML writes a bare number as a YAML integer.
func (d Duration) MarshalYAML() (any, error) {
	if digitsRe.MatchString(string(d)) {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: string(d)}, nil
	}
	return string(d), nil
}

var digitsRe = regexp.MustCompile(`^[0-9]+$`)

var knownCache sync.Map // reflect.Type → map[lower]canonical

// knownKeys maps the lowercased yaml names of a struct's fields to their
// canonical spelling.
func knownKeys(t reflect.Type) map[string]string {
	if m, ok := knownCache.Load(t); ok {
		return m.(map[string]string)
	}
	m := map[string]string{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			m[strings.ToLower(name)] = name
		}
	}
	knownCache.Store(t, m)
	return m
}

// decodeKnown decodes the known keys of mapping n into v (a pointer to a
// struct type without YAML methods) and puts the rest into unk.
func decodeKnown(n *yaml.Node, v any, unk *Unknown) error {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil // "quic:" with nothing under it
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("строка %d: здесь ожидается набор полей", n.Line)
	}
	known := knownKeys(reflect.TypeOf(v).Elem())
	filtered := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Line: n.Line, Column: n.Column}
	var rest Unknown
	seen := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" {
			return fmt.Errorf("строка %d: слияние YAML (<<) не поддерживается", k.Line)
		}
		name, ok := known[strings.ToLower(k.Value)]
		if !ok || k.Kind != yaml.ScalarNode {
			// The anchor an alias points to may sit in a known field,
			// which is written back without it: keep a copy instead.
			budget := maxExpand
			cv, err := expandAliases(val, &budget)
			if err != nil {
				return fmt.Errorf("строка %d: %w", val.Line, err)
			}
			rest = append(rest, k, cv)
			continue
		}
		if line, dup := seen[name]; dup {
			return fmt.Errorf("строка %d: поле %s уже задано в строке %d", k.Line, name, line)
		}
		seen[name] = k.Line
		ck := *k
		ck.Value = name
		filtered.Content = append(filtered.Content, &ck, val)
	}
	if err := filtered.Decode(v); err != nil {
		return typeError(err)
	}
	*unk = rest
	return nil
}

const maxExpand = 10000

// expandAliases copies n with every alias replaced by a copy of its
// target, within a node budget (alias bombs).
func expandAliases(n *yaml.Node, budget *int) (*yaml.Node, error) {
	if *budget--; *budget < 0 {
		return nil, errors.New("слишком много ссылок YAML")
	}
	if n.Kind == yaml.AliasNode {
		return expandAliases(n.Alias, budget)
	}
	c := *n
	c.Anchor = ""
	c.Content = nil
	for _, ch := range n.Content {
		cc, err := expandAliases(ch, budget)
		if err != nil {
			return nil, err
		}
		c.Content = append(c.Content, cc)
	}
	return &c, nil
}

// encodeKnown encodes v (the plain twin of a model struct) and appends the
// unknown pairs.
func encodeKnown(v any, unk Unknown) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	n.Content = append(n.Content, unk...)
	return &n, nil
}

// typeError turns yaml.v3's "cannot unmarshal" into one readable message.
func typeError(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return errors.New(strings.Join(te.Errors, "; "))
	}
	return err
}

// parseDoc reads a single YAML document into v.
func parseDoc(b []byte, v any) error {
	var doc yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("конфиг пуст")
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("в файле несколько YAML-документов")
	}
	if len(doc.Content) == 0 {
		return errors.New("конфиг пуст")
	}
	return doc.Content[0].Decode(v)
}

func marshalDoc(v any) ([]byte, error) {
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}
