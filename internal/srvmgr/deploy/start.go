package deploy

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Submitter starts deploys: it checks the params, makes the secrets and
// queues the job.
type Submitter struct {
	Store Store
	Keys  *secrets.Keyring
	Jobs  *jobs.Engine
}

// ErrConfigChanged: the server's current config was not made by a deploy
// (it was edited, rolled back or imported), and a deploy, which builds the
// config from its params alone, would silently drop what they do not
// cover. Params.Overwrite confirms the replacement.
var ErrConfigChanged = errors.New("deploy: the current config was not made by a deploy")

// Submit queues a deploy of serverID. A server with a config keeps its
// client passwords (of every auth type), so client links stay valid. A
// config no deploy made is replaced only with Params.Overwrite, else
// ErrConfigChanged. Bad params are a *model.FieldError.
func (s *Submitter) Submit(ctx context.Context, serverID int64, p Params, actor int64) (model.Job, error) {
	if err := p.Normalize(); err != nil {
		return model.Job{}, &model.FieldError{Field: "params", Msg: sentence(err.Error())}
	}
	srv, err := s.Store.ServerByID(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	cur, err := s.Store.CurrentConfig(ctx, serverID)
	if err == nil && cur.Source != model.ConfigDeploy && !p.Overwrite {
		return model.Job{}, ErrConfigChanged
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.Job{}, err
	}
	reuse, err := CurrentSecrets(ctx, s.Store, s.Keys, serverID)
	if err != nil {
		return model.Job{}, err
	}
	sec, err := NewSecrets(p, srv.Host, reuse)
	if err != nil {
		return model.Job{}, err
	}
	return s.Jobs.Submit(ctx, JobKind, serverID, p, sec, actor)
}

// CurrentSecrets are the secrets of the server's current config revision
// a redeploy keeps: those of its auth section (AuthSecrets) and the
// Salamander password; nil when it has no config.
func CurrentSecrets(ctx context.Context, st store.Configs, keys *secrets.Keyring, serverID int64) (map[string]string, error) {
	cur, err := st.CurrentConfig(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, err := keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	if err != nil {
		return nil, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil, err
	}
	out := AuthSecrets(c.Auth)
	if strings.EqualFold(c.Obfs.Type, "salamander") && c.Obfs.Salamander.Password != "" {
		out[SecretObfs] = c.Obfs.Salamander.Password
	}
	return out, nil
}

// sentence makes an error text a sentence for the UI.
func sentence(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[n:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
