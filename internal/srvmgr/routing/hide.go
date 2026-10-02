package routing

import (
	"slices"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// hiddenDoc is an ACL as the editor and the exports see it: secret
// patterns in its lines (a password in a URL in a comment, a share link)
// redacted, as the config editor shows them.
func hiddenDoc(d acl.Document) acl.Document {
	d.Rules = slices.Clone(d.Rules)
	for i, r := range d.Rules {
		r.Text, r.Comment = redact.String(r.Text), redact.String(r.Comment)
		r.Before = hiddenLines(r.Before)
		d.Rules[i] = r
	}
	d.Tail = hiddenLines(d.Tail)
	return d
}

func hiddenLines(ls []string) []string {
	if ls == nil {
		return nil
	}
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = redact.String(l)
	}
	return out
}

// restoreDoc puts back the lines of current that hiddenDoc redacted, where
// the editor sent them back as it got them: a redacted line never reaches
// the config in place of the real one.
func restoreDoc(in, current acl.Document) acl.Document {
	orig := map[string]string{}
	keep := func(l string) {
		if h := redact.String(l); h != l {
			orig[h] = l
		}
	}
	for _, r := range current.Rules {
		keep(r.Text)
		for _, l := range r.Before {
			keep(l)
		}
	}
	for _, l := range current.Tail {
		keep(l)
	}
	if len(orig) == 0 {
		return in
	}
	back := func(ls []string) []string {
		if ls == nil {
			return nil
		}
		out := make([]string, len(ls))
		for i, l := range ls {
			if o, ok := orig[l]; ok {
				l = o
			}
			out[i] = l
		}
		return out
	}
	in.Rules = slices.Clone(in.Rules)
	for i, r := range in.Rules {
		if o, ok := orig[r.Text]; ok {
			if was := acl.Parse(o); len(was.Rules) == 1 && r.Comment == redact.String(was.Rules[0].Comment) {
				r.Comment = was.Rules[0].Comment
			}
			r.Text = o
		}
		r.Before = back(r.Before)
		in.Rules[i] = r
	}
	in.Tail = back(in.Tail)
	return in
}
