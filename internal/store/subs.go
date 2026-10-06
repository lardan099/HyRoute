package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Subscription is a subscription URL whose profiles HyRoute keeps in sync.
// The URL is a credential: on disk it is sealed like profile secrets.
type Subscription struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"-"`
	Enabled bool   `json:"enabled"`
	// Interval: manual | startup | 6h | 12h | 24h.
	Interval string `json:"interval"`

	LastUpdate  time.Time      `json:"lastUpdate"`  // last successful update
	LastAttempt time.Time      `json:"lastAttempt"` // last try, success or not
	LastError   string         `json:"lastError"`
	Count       int            `json:"count"`    // Hysteria profiles received
	Ignored     map[string]int `json:"ignored"`  // other protocols by scheme
	Warnings    []string       `json:"warnings"` // import warnings of the last update
	// Errors: the first messages of the links the last update could not
	// read (ErrorCount of them in all); their servers were left out.
	Errors      []string `json:"errors,omitempty"`
	ErrorCount  int      `json:"errorCount,omitempty"`
	UserInfo    string   `json:"userInfo"` // Subscription-Userinfo header
	HasPrevious bool     `json:"hasPrevious"`
	// subinfo: UserInfo holds the header's canonical form. InfoAt is when
	// it was reported (zero in files of v1.0.0). Support is the panel's
	// support-url: public, one contact link for the whole panel, stored in
	// plain; the app checks it on every use.
	InfoAt  time.Time `json:"infoAt,omitzero"`
	Support string    `json:"supportUrl,omitempty"`
}

// maxSupportURL bounds Subscription.Support read from the file.
const maxSupportURL = 2048

type storedSub struct {
	Subscription
	SealedURL string `json:"sealedURL"`
}

func (s *Store) LoadSubscriptions() ([]Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path("subscriptions.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []Subscription{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []storedSub
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("subscriptions.json: %w", err)
	}
	out := make([]Subscription, 0, len(list))
	for _, st := range list {
		raw, err := base64.StdEncoding.DecodeString(st.SealedURL)
		if err == nil {
			raw, err = unseal(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("подписка %q: ссылку не удалось расшифровать (файл от другого пользователя или компьютера?): %w", st.Name, err)
		}
		st.Subscription.URL = string(raw)
		if len(st.Support) > maxSupportURL {
			st.Support = "" // a bound only: validity is checked on use
		}
		out = append(out, st.Subscription)
	}
	return out, nil
}

func (s *Store) SaveSubscriptions(list []Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedSub, 0, len(list))
	for _, sub := range list {
		sealed, err := seal([]byte(sub.URL))
		if err != nil {
			return fmt.Errorf("seal subscription URL: %w", err)
		}
		out = append(out, storedSub{Subscription: sub, SealedURL: base64.StdEncoding.EncodeToString(sealed)})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("subscriptions.json"), b)
}

// Snapshots keep the last good body of a subscription ("cur") and the one
// before it ("prev"), sealed: they contain credentials.
func (s *Store) snapPath(id, which string) string {
	return filepath.Join(s.Dir, "subs", id+"."+which)
}

// PushSnapshot stores body as the current snapshot; the old current one
// becomes the previous one. The current body again changes nothing: a
// repeated update must keep the version a rollback returns to. Neither
// does a body that same reports equal to the current one (the same
// servers under other names or in another order, as panels that put the
// traffic left into the names send every time): it replaces the current
// snapshot and the previous one stays.
func (s *Store) PushSnapshot(id string, body []byte, same func(cur []byte) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.snapPath(id, "cur")
	shift := true
	if old, err := os.ReadFile(cur); err == nil {
		if old, err = unseal(old); err == nil {
			if bytes.Equal(old, body) {
				return nil
			}
			shift = same == nil || !same(old)
		}
	}
	if err := os.MkdirAll(filepath.Join(s.Dir, "subs"), 0o700); err != nil {
		return err
	}
	sealed, err := seal(body)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cur); err == nil && shift {
		if err := os.Rename(cur, s.snapPath(id, "prev")); err != nil {
			return err
		}
	}
	return writeAtomic(cur, sealed)
}

// PreviousSnapshot returns the previous snapshot's body, the one a
// rollback applies; SwapSnapshots then makes it current once it is.
func (s *Store) PreviousSnapshot(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed, err := os.ReadFile(s.snapPath(id, "prev"))
	if err != nil {
		return nil, errors.New("предыдущей версии подписки нет")
	}
	return unseal(sealed)
}

// SwapSnapshots makes the previous snapshot current and the current one
// previous (a rollback that has been applied).
func (s *Store) SwapSnapshots(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, cur := s.snapPath(id, "prev"), s.snapPath(id, "cur")
	if _, err := os.Stat(prev); err != nil {
		return errors.New("предыдущей версии подписки нет")
	}
	tmp := s.snapPath(id, "swap")
	if err := os.Rename(cur, tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(prev, cur); err != nil {
		os.Rename(tmp, cur)
		return err
	}
	os.Rename(tmp, prev)
	return nil
}

func (s *Store) DeleteSnapshots(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range []string{"cur", "prev", "swap"} {
		os.Remove(s.snapPath(id, w))
	}
}

// HasPrevious reports whether a rollback snapshot exists.
func (s *Store) HasPrevious(id string) bool {
	_, err := os.Stat(s.snapPath(id, "prev"))
	return err == nil
}
