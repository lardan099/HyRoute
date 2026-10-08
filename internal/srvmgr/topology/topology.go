// Package topology checks and keeps cascades (P3-01): chains of servers,
// entry first and exit last, and the links between neighbours.
package topology

import (
	"fmt"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// MaxNodes is how many servers a chain may have (P4-08): the entry, up to
// two relays and the exit. Each hop adds a link client and its latency;
// the schema has no limit.
const MaxNodes = 4

func nodesErr(format string, a ...any) error {
	return &model.FieldError{Field: "nodes", Msg: fmt.Sprintf(format, a...)}
}

// countNodes checks how many servers a chain has.
func countNodes(n int) error {
	switch {
	case n < 2:
		return nodesErr("Выберите сервер входа и сервер выхода.")
	case n > MaxNodes:
		return nodesErr("В каскаде может быть до %d серверов: вход, до %d промежуточных и выход.", MaxNodes, MaxNodes-2)
	}
	return nil
}

// Check accepts chain c among existing, every chain stored so far (c is
// not among them). name gives a server's name for the messages.
//
// The outbound of a link is the default of its server: all traffic of the
// server goes that way. So a server sends through at most one link, and a
// server that receives a link of one chain sends through none of another:
// A → B with B → A would pass traffic round in circles until both servers
// fall over, and A → B with B → C would leave A → B through C unseen.
// Within one chain that is what a relay does (P4-08): it is the exit of
// the link before it and the entry of the next, and the chain shows the
// whole way. An exit may serve several chains. The graph of all links is
// checked for circles as well.
func Check(c model.Chain, existing []model.Chain, name func(id int64) string) error {
	for _, o := range existing {
		if strings.EqualFold(o.Name, c.Name) {
			return &model.FieldError{Field: "name", Msg: "Каскад с таким названием уже есть."}
		}
	}
	if err := countNodes(len(c.Nodes)); err != nil {
		return err
	}
	seen := map[int64]bool{}
	for _, id := range c.Nodes {
		if seen[id] {
			return nodesErr("Сервер %s встречается в каскаде дважды: каждый узел каскада — свой сервер.", name(id))
		}
		seen[id] = true
	}

	// sends: the chain a server sends through; receives: one that ends at it.
	sends, receives := map[int64]model.Chain{}, map[int64]model.Chain{}
	for _, o := range existing {
		for i, id := range o.Nodes {
			if i < len(o.Nodes)-1 {
				sends[id] = o
			}
			if i > 0 {
				receives[id] = o
			}
		}
	}
	for i, id := range c.Nodes {
		as := nodeName(i, len(c.Nodes), true)
		if i < len(c.Nodes)-1 {
			if o, ok := sends[id]; ok {
				return nodesErr("%s уже %s каскада «%s»: сервер выпускает трафик только через один каскад.", name(id), roleIn(o, id), o.Name)
			}
			if o, ok := receives[id]; ok {
				return nodesErr("%s — выход каскада «%s» и не может быть %s другого: трафик того каскада ушёл бы дальше незаметно или пошёл по кругу.", name(id), o.Name, as)
			}
		}
		if i > 0 {
			if o, ok := sends[id]; ok {
				return nodesErr("%s — %s каскада «%s» и не может быть %s другого: трафик этого каскада ушёл бы дальше незаметно или пошёл по кругу.", name(id), roleIn(o, id), o.Name, as)
			}
		}
	}
	if loop := circle(append(existing, c)); loop != nil {
		names := make([]string, len(loop))
		for i, id := range loop {
			names[i] = name(id)
		}
		return nodesErr("Каскады образовали бы круг: %s.", strings.Join(names, " → "))
	}
	return nil
}

// roleIn names the role of server id in chain o, for the messages.
func roleIn(o model.Chain, id int64) string {
	switch model.NodeRole(slices.Index(o.Nodes, id), len(o.Nodes)) {
	case model.RoleEntry:
		return "вход"
	case model.RoleRelay:
		return "промежуточный узел"
	}
	return "выход"
}

// nodeName names node idx of a chain of n nodes in the instrumental case
// («быть входом»), or in the genitive with the word server («сервер
// входа», «промежуточный сервер»: instr false) for the messages.
func nodeName(idx, n int, instr bool) string {
	role := model.NodeRole(idx, n)
	switch {
	case instr && role == model.RoleEntry:
		return "входом"
	case instr && role == model.RoleRelay:
		return "промежуточным узлом"
	case instr:
		return "выходом"
	case role == model.RoleEntry:
		return "сервера входа"
	case role == model.RoleRelay:
		return "промежуточного сервера"
	}
	return "сервера выхода"
}

// circle is a cycle of the graph of all links, as servers from the first
// back to it; nil: none.
func circle(chains []model.Chain) []int64 {
	next := map[int64][]int64{}
	for _, c := range chains {
		for i := 0; i+1 < len(c.Nodes); i++ {
			next[c.Nodes[i]] = append(next[c.Nodes[i]], c.Nodes[i+1])
		}
	}
	const (
		white = iota
		grey
		black
	)
	color := map[int64]int{}
	var path []int64
	var found []int64
	var visit func(id int64) bool
	visit = func(id int64) bool {
		color[id] = grey
		path = append(path, id)
		for _, n := range next[id] {
			switch color[n] {
			case grey:
				for i, p := range path {
					if p == n {
						found = append(append([]int64{}, path[i:]...), n)
					}
				}
				return true
			case white:
				if visit(n) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		color[id] = black
		return false
	}
	for _, c := range chains {
		for _, id := range c.Nodes {
			if color[id] == white && visit(id) {
				return found
			}
		}
	}
	return nil
}

// State is the state of a chain from its links: a job at work first, then
// what needs attention (failed, stale), then new; active when every link
// is.
func State(c model.Chain) model.LinkState {
	rank := map[model.LinkState]int{
		model.LinkLinking: 6, model.LinkUnlinking: 5, model.LinkFailed: 4,
		model.LinkStale: 3, model.LinkNew: 2, model.LinkActive: 1,
	}
	st := model.LinkActive
	for _, l := range c.Links {
		if rank[l.State] > rank[st] {
			st = l.State
		}
	}
	if len(c.Links) == 0 {
		return model.LinkNew
	}
	return st
}

// Deployed reports whether any link of the chain may be in effect on its
// servers: only a chain whose links are all new or failed (rolled back)
// is removed without a job.
func Deployed(c model.Chain) bool {
	for _, l := range c.Links {
		if l.State != model.LinkNew && l.State != model.LinkFailed {
			return true
		}
	}
	return false
}
