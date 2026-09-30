// Package servers is the server inventory: validation of server records
// and their SSH credentials, which are stored sealed and only ever leave
// this package towards the SSH layer (Credentials), never towards the API.
package servers

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what the service needs from storage.
type Store interface {
	store.Servers
	store.HostKeys
	store.Audit
}

// Service manages the inventory.
type Service struct {
	Store Store
	Keys  *secrets.Keyring
	Now   func() time.Time
}

// New returns a service.
func New(st Store, keys *secrets.Keyring) *Service {
	return &Service{Store: st, Keys: keys, Now: time.Now}
}

// Input is a server as the admin enters it. Credentials are pointers: nil
// keeps the stored value on update (and means "none" on create).
type Input struct {
	Name     string
	Tags     []string
	Country  string
	Location string
	Host     string
	SSHPort  int
	SSHUser  string
	AuthType model.AuthType
	Role     model.ServerRole
	Notes    string

	Password      *string
	Key           *string
	KeyPassphrase *string
}

// Info is a server with which credentials it has (never their values) and
// its trusted host key, if any.
type Info struct {
	model.Server
	HasPassword      bool
	HasKey           bool
	HasKeyPassphrase bool
	HostKey          *model.HostKey
}

// Credentials are the opened SSH credentials of a server.
type Credentials struct {
	Password      string
	Key           []byte
	KeyPassphrase string
}

var ErrNoCredentials = errors.New("server has no stored credentials")

func fieldErr(field, msg string) error { return &model.FieldError{Field: field, Msg: msg} }

var (
	sshUserRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
	countryRe  = regexp.MustCompile(`^[A-Z]{2}$`)
)

func printable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// normalize validates in and fills defaults.
func normalize(in *Input) error {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 64 || !printable(in.Name) {
		return fieldErr("name", "Название: от 1 до 64 символов.")
	}
	in.Host = strings.TrimSpace(in.Host)
	in.Host = strings.TrimSuffix(strings.TrimPrefix(in.Host, "["), "]")
	if !validHost(in.Host) {
		return fieldErr("host", "Адрес: доменное имя или IP-адрес, без порта и без http://.")
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.SSHPort < 1 || in.SSHPort > 65535 {
		return fieldErr("sshPort", "Порт SSH: от 1 до 65535.")
	}
	in.SSHUser = strings.TrimSpace(in.SSHUser)
	if in.SSHUser == "" {
		in.SSHUser = "root"
	}
	if !sshUserRe.MatchString(in.SSHUser) {
		return fieldErr("sshUser", "Пользователь SSH: латинские буквы, цифры, точка, дефис и подчёркивание, до 32 символов.")
	}
	in.Country = strings.ToUpper(strings.TrimSpace(in.Country))
	if in.Country != "" && !countryRe.MatchString(in.Country) {
		return fieldErr("country", "Страна: двухбуквенный код, например DE.")
	}
	in.Location = strings.TrimSpace(in.Location)
	if utf8.RuneCountInString(in.Location) > 64 || !printable(in.Location) {
		return fieldErr("location", "Расположение: до 64 символов.")
	}
	if utf8.RuneCountInString(in.Notes) > 4000 {
		return fieldErr("notes", "Заметки: до 4000 символов.")
	}
	if in.Role == "" {
		in.Role = model.RoleStandalone
	}
	if !in.Role.Valid() {
		return fieldErr("role", "Роль: standalone, entry, relay или exit.")
	}
	switch in.AuthType {
	case model.AuthPassword, model.AuthKey:
	default:
		return fieldErr("authType", "Способ входа: пароль или SSH-ключ.")
	}
	seen := map[string]bool{}
	var tags []string
	for _, t := range in.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if utf8.RuneCountInString(t) > 32 || !printable(t) {
			return fieldErr("tags", "Метка: до 32 символов.")
		}
		if k := strings.ToLower(t); !seen[k] {
			seen[k] = true
			tags = append(tags, t)
		}
	}
	if len(tags) > 16 {
		return fieldErr("tags", "Не больше 16 меток.")
	}
	in.Tags = tags
	return nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	return hostnameRe.MatchString(h)
}

// checkKey parses a private key (with its passphrase, if any).
func checkKey(key []byte, passphrase string) error {
	var err error
	if passphrase != "" {
		_, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	} else {
		_, err = ssh.ParsePrivateKey(key)
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &missing):
		return fieldErr("keyPassphrase", "Ключ зашифрован: укажите его пароль.")
	case errors.Is(err, x509.IncorrectPasswordError):
		return fieldErr("keyPassphrase", "Пароль ключа не подходит.")
	}
	return fieldErr("key", "Это не закрытый SSH-ключ (ожидается OpenSSH, PEM RSA/EC/Ed25519).")
}

func (s *Service) seal(creds map[model.CredKind]string) store.SealFunc {
	if len(creds) == 0 {
		return nil
	}
	return func(id int64) ([]model.Credential, error) {
		var out []model.Credential
		for k, v := range creds {
			b, err := s.Keys.SealString(v, model.CredContext(id, k))
			if err != nil {
				return nil, err
			}
			out = append(out, model.Credential{Kind: k, Sealed: b})
		}
		return out, nil
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Create adds a server; its credentials are sealed in the same transaction.
func (s *Service) Create(ctx context.Context, actor int64, in Input) (Info, error) {
	if err := normalize(&in); err != nil {
		return Info{}, err
	}
	creds := map[model.CredKind]string{}
	switch in.AuthType {
	case model.AuthPassword:
		if deref(in.Password) == "" {
			return Info{}, fieldErr("password", "Укажите пароль SSH.")
		}
		creds[model.CredSSHPassword] = *in.Password
	case model.AuthKey:
		key := strings.TrimSpace(deref(in.Key))
		if key == "" {
			return Info{}, fieldErr("key", "Вставьте закрытый SSH-ключ.")
		}
		if err := checkKey([]byte(key), deref(in.KeyPassphrase)); err != nil {
			return Info{}, err
		}
		creds[model.CredSSHKey] = key + "\n"
		if p := deref(in.KeyPassphrase); p != "" {
			creds[model.CredSSHKeyPassphrase] = p
		}
	}
	now := s.Now()
	srv := model.Server{Name: in.Name, Tags: in.Tags, Country: in.Country, Location: in.Location, Host: in.Host, SSHPort: in.SSHPort, SSHUser: in.SSHUser, AuthType: in.AuthType, Role: in.Role, Notes: in.Notes, State: model.StateNew, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreateServer(ctx, &srv, s.seal(creds)); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Info{}, fieldErr("name", "Сервер с таким названием уже есть.")
		}
		return Info{}, err
	}
	s.audit(ctx, actor, "server_created", srv)
	return s.Get(ctx, srv.ID)
}

// Update changes a server. Credentials left nil stay; switching the auth
// type drops the credentials of the old type.
func (s *Service) Update(ctx context.Context, actor, id int64, in Input) (Info, error) {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Info{}, err
	}
	if err := normalize(&in); err != nil {
		return Info{}, err
	}
	creds := map[model.CredKind]string{}
	var drop []model.CredKind
	switch in.AuthType {
	case model.AuthPassword:
		if in.Password != nil {
			if *in.Password == "" {
				return Info{}, fieldErr("password", "Укажите пароль SSH.")
			}
			creds[model.CredSSHPassword] = *in.Password
		} else if !cur.HasPassword {
			return Info{}, fieldErr("password", "Укажите пароль SSH.")
		}
		drop = []model.CredKind{model.CredSSHKey, model.CredSSHKeyPassphrase}
	case model.AuthKey:
		var key []byte
		if in.Key != nil && strings.TrimSpace(*in.Key) != "" {
			key = []byte(strings.TrimSpace(*in.Key) + "\n")
			creds[model.CredSSHKey] = string(key)
		} else if cur.HasKey {
			c, err := s.Credentials(ctx, id)
			if err != nil {
				return Info{}, err
			}
			key = c.Key
			if in.KeyPassphrase == nil {
				in.KeyPassphrase = &c.KeyPassphrase
			}
		} else {
			return Info{}, fieldErr("key", "Вставьте закрытый SSH-ключ.")
		}
		pass := deref(in.KeyPassphrase)
		if err := checkKey(key, pass); err != nil {
			return Info{}, err
		}
		drop = []model.CredKind{model.CredSSHPassword}
		if pass != "" {
			creds[model.CredSSHKeyPassphrase] = pass
		} else {
			drop = append(drop, model.CredSSHKeyPassphrase)
		}
	}
	srv := cur.Server
	srv.Name, srv.Tags, srv.Country, srv.Location = in.Name, in.Tags, in.Country, in.Location
	srv.Host, srv.SSHPort, srv.SSHUser, srv.AuthType = in.Host, in.SSHPort, in.SSHUser, in.AuthType
	srv.Role, srv.Notes, srv.UpdatedAt = in.Role, in.Notes, s.Now()
	if err := s.Store.UpdateServer(ctx, &srv, s.seal(creds), drop); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Info{}, fieldErr("name", "Сервер с таким названием уже есть.")
		}
		return Info{}, err
	}
	// Another address is another machine: its host key must be confirmed
	// again rather than compared with the old one.
	if cur.Host != srv.Host || cur.SSHPort != srv.SSHPort {
		if err := s.Store.DeleteHostKey(ctx, id); err != nil {
			return Info{}, err
		}
	}
	s.audit(ctx, actor, "server_updated", srv)
	return s.Get(ctx, id)
}

// Delete removes a server and its credentials.
func (s *Service) Delete(ctx context.Context, actor, id int64) error {
	srv, err := s.Store.ServerByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Store.DeleteServer(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "server_deleted", srv)
	return nil
}

func (s *Service) info(ctx context.Context, srv model.Server) (Info, error) {
	cs, err := s.Store.ServerCredentials(ctx, srv.ID)
	if err != nil {
		return Info{}, err
	}
	in := Info{Server: srv}
	if hk, err := s.Store.HostKey(ctx, srv.ID); err == nil {
		in.HostKey = &hk
	} else if !errors.Is(err, store.ErrNotFound) {
		return Info{}, err
	}
	for _, c := range cs {
		switch c.Kind {
		case model.CredSSHPassword:
			in.HasPassword = true
		case model.CredSSHKey:
			in.HasKey = true
		case model.CredSSHKeyPassphrase:
			in.HasKeyPassphrase = true
		}
	}
	return in, nil
}

// Get returns a server.
func (s *Service) Get(ctx context.Context, id int64) (Info, error) {
	srv, err := s.Store.ServerByID(ctx, id)
	if err != nil {
		return Info{}, err
	}
	return s.info(ctx, srv)
}

// List returns all servers by name.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	ss, err := s.Store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(ss))
	for _, srv := range ss {
		in, err := s.info(ctx, srv)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, nil
}

// Credentials opens the SSH credentials of a server for the SSH layer.
func (s *Service) Credentials(ctx context.Context, id int64) (Credentials, error) {
	cs, err := s.Store.ServerCredentials(ctx, id)
	if err != nil {
		return Credentials{}, err
	}
	if len(cs) == 0 {
		return Credentials{}, ErrNoCredentials
	}
	var c Credentials
	for _, x := range cs {
		v, err := s.Keys.Open(x.Sealed, model.CredContext(id, x.Kind))
		if err != nil {
			return Credentials{}, fmt.Errorf("%s of server %d: %w", x.Kind, id, err)
		}
		switch x.Kind {
		case model.CredSSHPassword:
			c.Password = string(v)
		case model.CredSSHKey:
			c.Key = v
		case model.CredSSHKeyPassphrase:
			c.KeyPassphrase = string(v)
		}
	}
	return c, nil
}

func (s *Service) audit(ctx context.Context, actor int64, action string, srv model.Server) {
	s.Store.AddAudit(ctx, model.AuditEntry{Time: s.Now(), UserID: actor, Action: action, Target: fmt.Sprintf("server/%d", srv.ID), Details: srv.Name})
}
