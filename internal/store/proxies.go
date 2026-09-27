package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// LocalProxy is a proxy port HyRoute opens for programs that take a proxy
// setting. One port speaks SOCKS5 and HTTP.
type LocalProxy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Profile is the server ID ("" = the main server).
	Profile string `json:"profile"`
	Port    int    `json:"port"`
	// LAN: listen on every interface (other devices of the local network);
	// requires a password.
	LAN      bool   `json:"lan"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type storedProxy struct {
	LocalProxy
	SealedPassword string `json:"sealedPassword,omitempty"`
}

func (s *Store) LoadProxies() ([]LocalProxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path("proxies.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []LocalProxy{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []storedProxy
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("proxies.json: %w", err)
	}
	out := make([]LocalProxy, 0, len(list))
	for _, st := range list {
		if st.SealedPassword != "" {
			raw, err := base64.StdEncoding.DecodeString(st.SealedPassword)
			if err == nil {
				raw, err = unseal(raw)
			}
			if err != nil {
				return nil, fmt.Errorf("прокси %q: пароль не удалось расшифровать (файл от другого пользователя или компьютера?): %w", st.Name, err)
			}
			st.LocalProxy.Password = string(raw)
		}
		out = append(out, st.LocalProxy)
	}
	return out, nil
}

func (s *Store) SaveProxies(list []LocalProxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedProxy, 0, len(list))
	for _, p := range list {
		st := storedProxy{LocalProxy: p}
		if p.Password != "" {
			sealed, err := seal([]byte(p.Password))
			if err != nil {
				return fmt.Errorf("seal proxy password: %w", err)
			}
			st.SealedPassword = base64.StdEncoding.EncodeToString(sealed)
		}
		out = append(out, st)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("proxies.json"), b)
}
