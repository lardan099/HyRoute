package ctlserver

import (
	"bytes"
	"encoding/json"

	"github.com/lardan099/hyroute/internal/ctl"
)

// Private passes every string value of a JSON document (not the keys)
// through mask: --private, the masking of exported logs and diagnostics.
func Private(raw []byte, mask func(string) string) ([]byte, error) {
	if mask == nil {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return ctl.Marshal(maskValue(v, mask))
}

func maskValue(v any, mask func(string) string) any {
	switch x := v.(type) {
	case string:
		return mask(x)
	case []any:
		for i := range x {
			x[i] = maskValue(x[i], mask)
		}
	case map[string]any:
		for k := range x {
			x[k] = maskValue(x[k], mask)
		}
	}
	return v
}
