package topology

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func chain(name string, nodes ...int64) model.Chain {
	c := model.Chain{Name: name, Nodes: nodes}
	for i := 0; i+1 < len(nodes); i++ {
		c.Links = append(c.Links, model.ChainLink{Idx: i, From: nodes[i], To: nodes[i+1], State: model.LinkNew})
	}
	return c
}

func name(id int64) string { return "S" + strconv.FormatInt(id, 10) }

func TestCheck(t *testing.T) {
	ab, abc := chain("AB", 1, 2), chain("ABC", 1, 2, 3)
	for _, tc := range []struct {
		desc     string
		c        model.Chain
		existing []model.Chain
		want     string // "" accepted, else a piece of the message
	}{
		{"first chain", chain("x", 1, 2), nil, ""},
		{"exit serves a second entry", chain("x", 3, 2), []model.Chain{ab}, ""},
		{"name taken in another case", chain("ab", 3, 4), []model.Chain{chain("Ab", 1, 2)}, "названием"},
		{"name taken, Cyrillic", chain("через германию", 3, 4), []model.Chain{chain("Через Германию", 1, 2)}, "названием"},
		{"one node", chain("x", 1), nil, "входа и сервер выхода"},
		{"five nodes", chain("x", 1, 2, 3, 4, 5), nil, "до 4 серверов"},
		{"same server twice", chain("x", 1, 1), nil, "дважды"},
		{"entry of two chains", chain("x", 1, 3), []model.Chain{ab}, "уже вход каскада «AB»"},
		{"A → B and B → A", chain("x", 2, 1), []model.Chain{ab}, "S2 — выход каскада «AB»"},
		{"A → B and B → C", chain("x", 2, 3), []model.Chain{ab}, "S2 — выход каскада «AB»"},
		{"C → A with A → B", chain("x", 3, 1), []model.Chain{ab}, "S1 — вход каскада «AB»"},

		// N nodes (P4-08): a relay is the exit of one link and the entry of
		// the next within its chain, and in no other chain.
		{"three nodes", chain("x", 1, 2, 3), nil, ""},
		{"four nodes", chain("x", 1, 2, 3, 4), nil, ""},
		{"a relay twice", chain("x", 1, 2, 3, 2), nil, "дважды"},
		{"the exit of a 3-node chain serves another", chain("x", 4, 5, 3), []model.Chain{abc}, ""},
		{"a relay of two chains", chain("x", 4, 2, 5), []model.Chain{abc}, "S2 уже промежуточный узел каскада «ABC»"},
		{"a relay as the exit of another", chain("x", 4, 2), []model.Chain{abc}, "S2 — промежуточный узел каскада «ABC» и не может быть выходом другого"},
		{"a relay as the entry of another", chain("x", 2, 4), []model.Chain{abc}, "S2 уже промежуточный узел каскада «ABC»"},
		{"an exit as the relay of another", chain("x", 4, 3, 5), []model.Chain{abc}, "S3 — выход каскада «ABC» и не может быть промежуточным узлом другого"},
		{"an entry as the relay of another", chain("x", 4, 1, 5), []model.Chain{abc}, "S1 уже вход каскада «ABC»"},
		{"an entry as the exit of another", chain("x", 5, 1), []model.Chain{abc}, "S1 — вход каскада «ABC» и не может быть выходом другого"},
		// A loop through a relay: the exit sends back into the chain.
		{"a loop through a relay", chain("x", 3, 1), []model.Chain{abc}, "S3 — выход каскада «ABC» и не может быть входом другого"},
		{"a loop into a relay", chain("x", 3, 4, 2), []model.Chain{abc}, "S3 — выход каскада «ABC»"},
		{"a loop of two 3-node chains", chain("x", 3, 4, 1), []model.Chain{abc}, "S3 — выход каскада «ABC»"},
	} {
		err := Check(tc.c, tc.existing, name)
		var fe *model.FieldError
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.desc, err)
		case tc.want != "" && (!errors.As(err, &fe) || !strings.Contains(fe.Msg, tc.want)):
			t.Errorf("%s: %v, want …%s…", tc.desc, err, tc.want)
		}
	}
}

// The circle check covers N-node chains (Phase 4) on its own.
func TestCircle(t *testing.T) {
	if c := circle([]model.Chain{chain("a", 1, 2, 3), chain("b", 4, 5)}); c != nil {
		t.Fatalf("no circle, got %v", c)
	}
	c := circle([]model.Chain{chain("a", 1, 2, 3), chain("b", 3, 4, 2)})
	if len(c) != 4 || c[0] != c[len(c)-1] {
		t.Fatalf("circle %v", c)
	}
}

func TestState(t *testing.T) {
	st := func(states ...model.LinkState) model.LinkState {
		var c model.Chain
		for _, s := range states {
			c.Links = append(c.Links, model.ChainLink{State: s})
		}
		return State(c)
	}
	for _, tc := range []struct {
		in   []model.LinkState
		want model.LinkState
	}{
		{nil, model.LinkNew},
		{[]model.LinkState{model.LinkActive}, model.LinkActive},
		{[]model.LinkState{model.LinkActive, model.LinkStale}, model.LinkStale},
		{[]model.LinkState{model.LinkFailed, model.LinkLinking}, model.LinkLinking},
		{[]model.LinkState{model.LinkNew, model.LinkActive}, model.LinkNew},
	} {
		if got := st(tc.in...); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, s := range []model.LinkState{model.LinkNew, model.LinkFailed} {
		if Deployed(model.Chain{Links: []model.ChainLink{{State: s}}}) {
			t.Errorf("%s counts as deployed", s)
		}
	}
	for _, s := range []model.LinkState{model.LinkLinking, model.LinkActive, model.LinkStale, model.LinkUnlinking} {
		if !Deployed(model.Chain{Links: []model.ChainLink{{State: s}}}) {
			t.Errorf("%s counts as not deployed", s)
		}
	}
}
