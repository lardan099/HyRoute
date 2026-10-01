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
	ab := chain("AB", 1, 2)
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
		{"three nodes", chain("x", 1, 2, 3), nil, "только из двух"},
		{"same server twice", chain("x", 1, 1), nil, "дважды"},
		{"entry of two chains", chain("x", 1, 3), []model.Chain{ab}, "уже вход каскада «AB»"},
		{"A → B and B → A", chain("x", 2, 1), []model.Chain{ab}, "S2 — выход каскада «AB»"},
		{"A → B and B → C", chain("x", 2, 3), []model.Chain{ab}, "S2 — выход каскада «AB»"},
		{"C → A with A → B", chain("x", 3, 1), []model.Chain{ab}, "S1 — вход каскада «AB»"},
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
