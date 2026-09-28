package rules

import "slices"

// Clone returns a deep copy of r: no slice or pointer is shared with r, so
// the copy may be edited in place. A new slice or pointer field of Rule
// must be copied here too (TestCloneShares checks it).
func (r Rule) Clone() Rule {
	r.Enabled = clonePtr(r.Enabled)
	r.Apps = slices.Clone(r.Apps)
	r.Domains = slices.Clone(r.Domains)
	r.App = clonePtr(r.App)
	r.Domain = clonePtr(r.Domain)
	r.Fallback = slices.Clone(r.Fallback)
	return r
}

// Clone returns a deep copy of c (see Rule.Clone). A nil Rules stays nil.
func (c Config) Clone() Config {
	c.DefaultFallback = slices.Clone(c.DefaultFallback)
	if c.Rules != nil {
		rs := make([]Rule, len(c.Rules))
		for i := range c.Rules {
			rs[i] = c.Rules[i].Clone()
		}
		c.Rules = rs
	}
	return c
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
