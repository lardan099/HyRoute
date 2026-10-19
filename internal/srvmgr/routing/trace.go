package routing

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Draft is a server's rules and outbound names as the editor has them,
// not saved yet.
type Draft struct {
	ACL       acl.Document
	Outbounds []string
}

// TraceHop is what one server of a chain does with a request.
type TraceHop struct {
	ServerID int64            `json:"serverId"`
	Name     string           `json:"name"`
	Role     model.ServerRole `json:"role"`
	// Verdict is the rule that matched there; nil: the server's rules
	// were not read (Error says why), and the trace ends.
	Verdict *acl.Verdict `json:"verdict,omitempty"`
	Error   string       `json:"error,omitempty"`
	// Next: the connection goes on to the next server, through the
	// outbound of the chain's link.
	Next bool `json:"next"`
}

// Trace is where a request goes along a chain (P4-08).
type Trace struct {
	Hops []TraceHop `json:"hops"`
	// Rejected: a server of the chain refuses the connection.
	Rejected bool `json:"rejected"`
	// Summary says where it ends, for people: «Уйдёт в интернет с «X»
	// через «direct».»
	Summary string `json:"summary"`
}

// linkUp: something of the link is on its servers, so the outbound
// "cascade" of its first server sends there.
func linkUp(l model.ChainLink) bool {
	return l.State != model.LinkNew && l.State != model.LinkFailed
}

// Sender is the deployed chain a server sends its traffic through (as its
// entry or a relay) and its place in it; ok false: none.
func Sender(chains []model.Chain, server int64) (c model.Chain, idx int, ok bool) {
	for _, c := range chains {
		i := slices.Index(c.Nodes, server)
		if i >= 0 && i < len(c.Nodes)-1 && i < len(c.Links) && linkUp(c.Links[i]) {
			return c, i, true
		}
	}
	return model.Chain{}, 0, false
}

// Trace follows request q along chain c from node from: on each server
// acl.Match with its current rules, as Hysteria matches them there (on
// the first server the editor's draft instead, when given); a verdict of
// the outbound "cascade" of a deployed link goes on to the next server,
// which sees the same domain (SOCKS5 passes it on) or the address a rule
// hijacked it to. It ends where the connection leaves for the internet,
// where a server refuses it, or at a server whose rules HyRoute does not
// have (no config, rules in acl.file). names are the servers' names.
func (s *Service) Trace(ctx context.Context, c model.Chain, from int, draft *Draft, q acl.Request, names map[int64]string) (Trace, error) {
	t := Trace{Hops: []TraceHop{}}
	for i := from; i < len(c.Nodes); i++ {
		id := c.Nodes[i]
		h := TraceHop{ServerID: id, Name: names[id], Role: model.NodeRole(i, len(c.Nodes))}
		doc, env, why, err := s.rulesOf(ctx, id, i == from, draft)
		if err != nil {
			return t, err
		}
		if why != "" {
			h.Error = why
			t.Hops = append(t.Hops, h)
			t.Summary = "На «" + h.Name + "» маршрут не проверить: " + why
			return t, nil
		}
		v, err := acl.Match(doc, env, q)
		if err != nil {
			return t, &model.FieldError{Field: "request", Msg: err.Error()}
		}
		h.Verdict = &v
		cascadeOut := !v.Builtin && strings.EqualFold(v.Outbound, cascade.OutboundName) && i+1 < len(c.Nodes)
		h.Next = cascadeOut && i < len(c.Links) && linkUp(c.Links[i])
		t.Hops = append(t.Hops, h)
		switch {
		case h.Next:
			if v.Hijack != "" {
				q.Host, q.IPs = v.Hijack, nil
			}
			continue
		case v.Builtin && v.Outbound == "reject":
			t.Rejected = true
			t.Summary = "Соединение отклонит «" + h.Name + "»."
		case cascadeOut:
			t.Summary = "Уйдёт в outbound «" + v.Outbound + "» сервера «" + h.Name + "», но связь каскада до «" + names[c.Nodes[i+1]] + "» не развёрнута."
		default:
			t.Summary = "Уйдёт в интернет с «" + h.Name + "» через «" + v.Outbound + "»."
		}
		return t, nil
	}
	return t, nil
}

// rulesOf are the rules of a server to match a request against: the
// draft for the first server when given, else its current config's. why
// says why there are none to use.
func (s *Service) rulesOf(ctx context.Context, id int64, first bool, draft *Draft) (doc acl.Document, env acl.Env, why string, err error) {
	if first && draft != nil {
		g, err := s.GeoOf(ctx, id)
		if err != nil {
			return doc, env, "", err
		}
		return draft.ACL, acl.Env{Outbounds: draft.Outbounds, Geo: g}, "", nil
	}
	_, b, err := s.Editor.Current(ctx, id)
	if errors.Is(err, apply.ErrNoConfig) {
		return doc, env, "HyRoute не знает конфиг этого сервера.", nil
	} else if err != nil {
		return doc, env, "", err
	}
	c, err := hyconfig.ParseServer(b)
	switch {
	case err != nil:
		return doc, env, "конфиг сервера не разобрать.", nil
	case c.ACL.File != "":
		return doc, env, "правила сервера в файле " + c.ACL.File + ", перенесите их в конфиг (маршрутизация сервера).", nil
	}
	env = acl.EnvOf(c)
	env.Geo = s.geoOf(c)
	return acl.ParseInline(c.ACL.Inline), env, "", nil
}
