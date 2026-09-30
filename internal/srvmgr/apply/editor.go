package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Editor serves the config editor from the controller's revisions.
type Editor struct {
	Store store.Configs
	Keys  *secrets.Keyring
}

// ErrNoConfig: the controller has no config of this server.
var ErrNoConfig = errors.New("no config")

// StaleError: the editor started from a revision that is not the current
// one any more.
type StaleError struct{ Current int }

func (e *StaleError) Error() string {
	return fmt.Sprintf("Конфиг сервера изменился (сейчас ревизия %d), пока вы его правили. Откройте редактор заново.", e.Current)
}

// View is the config as the editor opens it.
type View struct {
	Revision int      `json:"revision"`
	SHA256   string   `json:"sha256"`
	YAML     string   `json:"yaml"`
	Fields   Fields   `json:"fields"`
	Unknown  []string `json:"unknown"`
}

// Current is the current revision and its config.
func (e *Editor) Current(ctx context.Context, serverID int64) (model.ServerConfig, []byte, error) {
	cur, err := e.Store.CurrentConfig(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return cur, nil, ErrNoConfig
	} else if err != nil {
		return cur, nil, err
	}
	b, err := e.Keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	return cur, b, err
}

// Open is the current config with its secrets masked.
func (e *Editor) Open(ctx context.Context, serverID int64) (View, error) {
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return View{}, err
	}
	m, _, err := Mask(b)
	if err != nil {
		return View{}, err
	}
	v := View{Revision: cur.Revision, SHA256: cur.SHA256, YAML: string(m), Unknown: []string{}}
	if c, err := hyconfig.ParseServer(m); err == nil {
		v.Fields = FieldsOf(c)
		v.Unknown = append(v.Unknown, hyconfig.UnknownFields(c)...)
	}
	return v, nil
}

// Render checks the editor's text (and fields) against the revision the
// editor started from, which must still be the current one.
func (e *Editor) Render(ctx context.Context, serverID int64, base int, text string, fields *Fields) (Check, []byte, model.ServerConfig, error) {
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return Check{}, nil, cur, err
	}
	if cur.Revision != base {
		return Check{}, nil, cur, &StaleError{Current: cur.Revision}
	}
	ch, cand, err := Build(b, text, fields)
	return ch, cand, cur, err
}
