package redact

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// YAML redacts a YAML document structurally: scalar values of secret
// fields (IsSecretKey), every value under "userpass" (Hysteria's user →
// password map) and patterns inside any other string. Order and comments
// stay.
func (r *Redactor) YAML(data []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	r.node(&doc, false)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	enc.Close()
	return buf.Bytes(), nil
}

// YAMLString is YAML for text; a document that does not parse is
// redacted as plain text.
func (r *Redactor) YAMLString(s string) string {
	b, err := r.YAML([]byte(s))
	if err != nil {
		return r.String(s)
	}
	return string(b)
}

// node redacts n; secret says every scalar inside is a secret.
func (r *Redactor) node(n *yaml.Node, secret bool) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			r.node(c, secret)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			// A secret-named key hides a scalar value; a block under it
			// (the server's "auth:" with type and password) is walked like
			// any other. Every value of "userpass" is a password.
			sec := secret || k.Value == "userpass" || (v.Kind == yaml.ScalarNode && IsSecretKey(k.Value))
			r.node(v, sec)
		}
	case yaml.ScalarNode:
		if secret {
			if n.Value != "" {
				n.Value, n.Tag, n.Style = Mask, "!!str", 0
			}
			return
		}
		if red := r.String(n.Value); red != n.Value {
			n.Value, n.Style = red, 0
		}
	case yaml.AliasNode:
		// Aliases point at anchored nodes that are redacted where defined.
	}
}
