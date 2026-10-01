package topology

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what cascades keep in the controller's database.
type Store interface {
	store.Chains
	store.Servers
	store.Configs
	store.Audit
}

// Service manages chains. Deploying a link is a job (P3-02); the service
// only keeps the chains and checks them.
type Service struct {
	Store Store
	Now   func() time.Time
}

// ErrDeployed: a link of the chain may be in effect on its servers, so the
// chain is removed with a job, not deleted.
var ErrDeployed = errors.New("topology: the chain is deployed")

// Info is a chain with the state of its links taken together.
type Info struct {
	model.Chain
	State model.LinkState
}

// Of is the chain with its state.
func Of(c model.Chain) Info { return Info{Chain: c, State: State(c)} }

// Input is a new chain as the admin enters it.
type Input struct {
	Name  string
	Notes string
	// Nodes are the server IDs, entry first and exit last.
	Nodes []int64
	// Link are the settings of every link of the chain.
	Link cascade.Params
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func checkName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return "", &model.FieldError{Field: "name", Msg: "Название каскада: от 1 до 64 символов."}
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", &model.FieldError{Field: "name", Msg: "В названии каскада непечатаемые символы."}
		}
	}
	return name, nil
}

func checkNotes(notes string) error {
	if utf8.RuneCountInString(notes) > 4000 {
		return &model.FieldError{Field: "notes", Msg: "Заметки: до 4000 символов."}
	}
	return nil
}

// authOK are the auth types of an exit a link can get credentials from:
// a user of its own (userpass) or the shared password (password). With
// http or command auth HyRoute cannot make credentials for the link.
var authOK = map[string]bool{"password": true, "userpass": true}

// Create checks and stores a new chain; its links are new (not deployed).
func (s *Service) Create(ctx context.Context, in Input, actor int64) (Info, error) {
	name, err := checkName(in.Name)
	if err != nil {
		return Info{}, err
	}
	if err := checkNotes(in.Notes); err != nil {
		return Info{}, err
	}
	if len(in.Nodes) < 2 {
		return Info{}, nodesErr("Выберите сервер входа и сервер выхода.")
	}
	if err := in.Link.Validate(); err != nil {
		return Info{}, err
	}
	names := map[int64]string{}
	for _, id := range in.Nodes {
		srv, err := s.Store.ServerByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return Info{}, nodesErr("Сервер %d не найден.", id)
		} else if err != nil {
			return Info{}, err
		}
		names[id] = srv.Name
	}
	// Every node runs a Hysteria server HyRoute knows the config of: the
	// entry gets the outbound, the exit the link's credentials.
	for i, id := range in.Nodes {
		cur, err := s.Store.CurrentConfig(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			role := "входа"
			if i == len(in.Nodes)-1 {
				role = "выхода"
			}
			return Info{}, nodesErr("HyRoute не знает конфиг сервера %s %s: разверните на нём Hysteria или импортируйте его.", role, names[id])
		} else if err != nil {
			return Info{}, err
		}
		if i == len(in.Nodes)-1 && !authOK[cur.Meta.Auth] {
			return Info{}, nodesErr("На сервере выхода %s вход клиентов — %q: каскад умеет только password и userpass (для связи нужен свой пароль или пользователь).", names[id], cur.Meta.Auth)
		}
	}

	now := s.now()
	c := model.Chain{Name: name, Notes: in.Notes, Nodes: in.Nodes, Links: make([]model.ChainLink, len(in.Nodes)-1), CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	for i := range c.Links {
		c.Links[i].Params = in.Link.Raw()
	}
	name2 := func(id int64) string { return "«" + names[id] + "»" }
	err = s.Store.CreateChain(ctx, &c, func(existing []model.Chain) error { return Check(c, existing, name2) })
	if errors.Is(err, store.ErrConflict) {
		return Info{}, &model.FieldError{Field: "name", Msg: "Каскад с таким названием уже есть."}
	} else if err != nil {
		return Info{}, err
	}
	s.audit(ctx, actor, "chain_created", c)
	return Of(c), nil
}

// Update renames a chain and changes its notes.
func (s *Service) Update(ctx context.Context, id int64, name, notes string, actor int64) (Info, error) {
	name, err := checkName(name)
	if err != nil {
		return Info{}, err
	}
	if err := checkNotes(notes); err != nil {
		return Info{}, err
	}
	cs, err := s.Store.ListChains(ctx)
	if err != nil {
		return Info{}, err
	}
	for _, o := range cs {
		// SQLite folds only ASCII: other scripts are compared here.
		if o.ID != id && strings.EqualFold(o.Name, name) {
			return Info{}, &model.FieldError{Field: "name", Msg: "Каскад с таким названием уже есть."}
		}
	}
	if err := s.Store.UpdateChain(ctx, id, name, notes, s.now()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Info{}, &model.FieldError{Field: "name", Msg: "Каскад с таким названием уже есть."}
		}
		return Info{}, err
	}
	c, err := s.Store.ChainByID(ctx, id)
	if err != nil {
		return Info{}, err
	}
	s.audit(ctx, actor, "chain_updated", c)
	return Of(c), nil
}

// Delete removes a chain none of whose links is deployed (ErrDeployed
// otherwise: unlink first, P3-02c).
func (s *Service) Delete(ctx context.Context, id, actor int64) error {
	c, err := s.Store.ChainByID(ctx, id)
	if err != nil {
		return err
	}
	if Deployed(c) {
		return ErrDeployed
	}
	if err := s.Store.DeleteChain(ctx, id, s.now()); err != nil {
		return err
	}
	s.audit(ctx, actor, "chain_deleted", c)
	return nil
}

func (s *Service) audit(ctx context.Context, actor int64, action string, c model.Chain) {
	s.Store.AddAudit(ctx, model.AuditEntry{Time: s.now(), UserID: actor, Action: action, Target: fmt.Sprintf("chain/%d", c.ID), Details: c.Name})
}
