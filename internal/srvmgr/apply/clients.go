package apply

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// ChangeClients names an apply job of the client manager (P4-04): it
// changes the users of auth.userpass and nothing else of the config.
const ChangeClients = "clients"

// The operations on the client users.
const (
	ClientAdd      = "add"      // a new user with a generated password
	ClientRemove   = "remove"   // the user goes
	ClientPassword = "password" // the user gets a new generated password
)

// ClientOp is a change of one client user.
type ClientOp struct {
	Op   string
	User string
	// Links are the users of the cascade links into the server (the caller
	// names them): they belong to the cascades and are not touched.
	Links []string
}

var (
	// ErrNotUserPass: the server checks its clients by one shared password
	// or an outside service; it has no users to manage.
	ErrNotUserPass = errors.New("the server has no userpass users")
	// ErrLinkUser: the user is a cascade link's.
	ErrLinkUser = errors.New("a user of a cascade link")
	// errNotOnlyUsers: the candidate changes more than auth.userpass (a
	// bug, never a request: the request names one user).
	errNotOnlyUsers = errors.New("the candidate changes more than the client users")
)

// clientName is what a new client may be called: what a share link
// carries as it is, without the colon that ends a userpass name.
var clientName = regexp.MustCompile(`^[\p{L}\p{N}._@+-]{1,64}$`)

// linkPrefix starts the names of cascade link users (cascade.User).
const linkPrefix = "link-"

// Clients queues the apply job that changes one client user of the
// current config (base must still be it). The candidate is the current
// config through the typed model with only auth.userpass changed, and
// this is checked before it is queued. The password of an added user, or
// the new one, is returned to be shown once.
func (a *Applier) Clients(ctx context.Context, serverID int64, base int, op ClientOp, actor int64) (model.Job, string, error) {
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, "", err
	}
	if cur.Revision != base {
		return model.Job{}, "", &StaleError{Current: cur.Revision}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return model.Job{}, "", &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	password, err := changeClient(c, op)
	if err != nil {
		return model.Job{}, "", err
	}
	text, err := c.Marshal()
	if err != nil {
		return model.Job{}, "", err
	}
	ch, cand, err := Build(b, string(text), nil)
	if err == nil {
		err = HideCurrent(&ch, b)
	}
	if err != nil {
		return model.Job{}, "", err
	}
	if err := OnlyUsers(b, cand); err != nil {
		return model.Job{}, "", err
	}
	j, err := a.Queue(ctx, serverID, cur, ch, cand, ChangeClients, actor)
	if err != nil {
		return model.Job{}, "", err
	}
	return j, password, nil
}

// changeClient makes op on the users of c; it returns the generated
// password of add and password.
func changeClient(c *hyconfig.Server, op ClientOp) (string, error) {
	if c.Auth.Kind() != "userpass" {
		return "", ErrNotUserPass
	}
	name := strings.TrimSpace(op.User)
	if slices.ContainsFunc(op.Links, func(l string) bool { return strings.EqualFold(l, name) }) {
		return "", ErrLinkUser
	}
	// The user as the config spells it.
	have := ""
	for u := range c.Auth.UserPass {
		if strings.EqualFold(u, name) {
			have = u
		}
	}
	switch op.Op {
	case ClientAdd:
		if !clientName.MatchString(name) {
			return "", &model.FieldError{Field: "user", Msg: "Имя пользователя: до 64 букв, цифр и знаков . _ @ + -, без пробелов."}
		}
		if strings.HasPrefix(strings.ToLower(name), linkPrefix) {
			return "", &model.FieldError{Field: "user", Msg: "Имена «link-…» заняты связями каскадов: выберите другое."}
		}
		if have != "" {
			return "", &model.FieldError{Field: "user", Msg: "Пользователь «" + have + "» уже есть."}
		}
		if c.Auth.UserPass == nil {
			c.Auth.UserPass = map[string]string{}
		}
		p := generated()
		c.Auth.UserPass[name] = p
		return p, nil
	case ClientRemove, ClientPassword:
		if have == "" {
			return "", &model.FieldError{Field: "user", Msg: "В конфиге нет пользователя «" + name + "»."}
		}
		if op.Op == ClientRemove {
			delete(c.Auth.UserPass, have)
			return "", nil
		}
		p := generated()
		c.Auth.UserPass[have] = p
		return p, nil
	}
	return "", &model.FieldError{Field: "op", Msg: "Действие: add, remove или password."}
}

// OnlyUsers checks that cand is cur with only the users of auth.userpass
// changed: through the typed model, the rest of the two configs is the
// same.
func OnlyUsers(cur, cand []byte) error {
	a, err := hyconfig.ParseServer(cur)
	if err != nil {
		return err
	}
	b, err := hyconfig.ParseServer(cand)
	if err != nil {
		return err
	}
	if a.Auth.Kind() != "userpass" || b.Auth.Kind() != "userpass" {
		return errNotOnlyUsers
	}
	b.Auth.UserPass = a.Auth.UserPass
	x, err := a.Marshal()
	if err != nil {
		return err
	}
	y, err := b.Marshal()
	if err != nil {
		return err
	}
	if !bytes.Equal(x, y) {
		return errNotOnlyUsers
	}
	return nil
}
