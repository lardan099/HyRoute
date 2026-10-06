package apply

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Rotation is what a rotation replaces with new values. Every client
// link with an old value stops working once the job restarts Hysteria.
type Rotation struct {
	// Auth: the password of password auth, or of userpass users (Users;
	// empty: all of them but Links).
	Auth  bool     `json:"auth"`
	Users []string `json:"users,omitempty"`
	// Links are the users of cascade links into the server (the caller
	// names them): their passwords are the cascade's, and a new one would
	// only cut the link until it is updated.
	Links []string `json:"-"`
	// Obfs: the Salamander password.
	Obfs bool `json:"obfs"`
	// Cert: a new self-signed certificate and key in the files the config
	// names (clients check it by its pinSHA256, which changes).
	Cert bool `json:"cert"`
}

// The secrets of a rotation job besides the config.
const (
	SecretCert = "cert" // the new certificate (PEM)
	SecretKey  = "key"  // its private key (PEM)
)

// Rotate queues the apply job that replaces the chosen secrets of the
// current config (base must still be it). The config is changed through
// the typed model; a certificate alone leaves it as it is. Requests that
// do not fit the config are a *model.FieldError.
func (a *Applier) Rotate(ctx context.Context, serverID int64, base int, r Rotation, actor int64) (model.Job, error) {
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if cur.Revision != base {
		return model.Job{}, &StaleError{Current: cur.Revision}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	if !r.Auth && !r.Obfs && !r.Cert {
		return model.Job{}, &model.FieldError{Field: "rotate", Msg: "Выберите, что сменить."}
	}
	var what []string
	if r.Auth {
		w, err := rotateAuth(c, r.Users, r.Links)
		if err != nil {
			return model.Job{}, err
		}
		what = append(what, w...)
	}
	if r.Obfs {
		if !strings.EqualFold(c.Obfs.Type, "salamander") {
			return model.Job{}, &model.FieldError{Field: "obfs", Msg: "В конфиге нет обфускации Salamander: менять нечего."}
		}
		c.Obfs.Salamander.Password = generated()
		what = append(what, "obfs")
	}
	cand := b
	if r.Auth || r.Obfs {
		if cand, err = c.Marshal(); err != nil {
			return model.Job{}, err
		}
	}
	var errs []string
	for _, p := range c.Validate() {
		if !p.Warning {
			errs = append(errs, p.Field+": "+p.Message)
		}
	}
	if len(errs) > 0 {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Конфиг не проходит проверку, сначала исправьте его: " + strings.Join(errs, "; ") + "."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(cand)}
	sec := map[string]string{SecretConfig: string(cand)}
	if r.Cert {
		certPEM, keyPEM, err := a.newCert(ctx, serverID, c, cur.Meta)
		if err != nil {
			return model.Job{}, err
		}
		if p.Pin, err = deploy.Pin(certPEM); err != nil {
			return model.Job{}, err
		}
		sec[SecretCert], sec[SecretKey] = string(certPEM), string(keyPEM)
		what = append(what, "cert")
	}
	p.Rotated = what
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, sec, actor)
}

// rotateAuth gives the auth section new passwords and says which ones;
// all users are those but links.
func rotateAuth(c *hyconfig.Server, users, links []string) ([]string, error) {
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		c.Auth.Password = generated()
		return []string{"auth"}, nil
	case "userpass":
		if len(c.Auth.UserPass) == 0 {
			return nil, &model.FieldError{Field: "users", Msg: "В конфиге нет пользователей."}
		}
		if len(users) == 0 {
			for u := range c.Auth.UserPass {
				if !slices.ContainsFunc(links, func(l string) bool { return strings.EqualFold(l, u) }) {
					users = append(users, u)
				}
			}
			if len(users) == 0 {
				return nil, &model.FieldError{Field: "users", Msg: "В конфиге нет пользователей, кроме связи каскада: её пароль меняет сам каскад."}
			}
		}
		slices.Sort(users)
		users = slices.Compact(users)
		var out []string
		for _, u := range users {
			if _, ok := c.Auth.UserPass[u]; !ok {
				return nil, &model.FieldError{Field: "users", Msg: "В конфиге нет пользователя «" + u + "»."}
			}
			c.Auth.UserPass[u] = generated()
			out = append(out, "user:"+u)
		}
		return out, nil
	}
	return nil, &model.FieldError{Field: "auth", Msg: "Клиентов проверяет внешний сервис (auth " + c.Auth.Type + "): их паролей в конфиге нет, менять их нужно там."}
}

// newCert is a new self-signed certificate for the server: for the name
// of the current one and the server's address, like the deploy makes it.
// Only a self-signed certificate in files is replaced: one from a CA
// would turn into one clients must pin.
func (a *Applier) newCert(ctx context.Context, serverID int64, c *hyconfig.Server, meta model.ConfigMeta) ([]byte, []byte, error) {
	if c.ACME != nil || c.TLS == nil || meta.TLS != "self-signed" {
		return nil, nil, &model.FieldError{Field: "cert", Msg: "Сменить можно только самоподписанный сертификат; этот сервер использует сертификат ACME или от удостоверяющего центра."}
	}
	if !path.IsAbs(c.TLS.Cert) || !path.IsAbs(c.TLS.Key) {
		return nil, nil, &model.FieldError{Field: "cert", Msg: "Пути к сертификату и ключу в конфиге относительные: HyRoute не знает, где файлы."}
	}
	srv, err := a.x.Store.ServerByID(ctx, serverID)
	if err != nil {
		return nil, nil, err
	}
	return deploy.SelfSigned(meta.SNI, srv.Host, a.x.Now())
}
