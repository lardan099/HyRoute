package cascade

import (
	"encoding/json"
	"errors"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// ParseParams reads stored params ({} or empty: the defaults).
func ParseParams(raw json.RawMessage) (Params, error) {
	var p Params
	if len(raw) == 0 {
		return p, nil
	}
	err := json.Unmarshal(raw, &p)
	return p, err
}

// Raw is p as stored.
func (p Params) Raw() json.RawMessage {
	b, _ := json.Marshal(p)
	return b
}

// SealSecrets seals the secrets of link idx of chain chainID: the sealed
// value opens only for that link.
func SealSecrets(keys *secrets.Keyring, chainID int64, idx int, s Secrets) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return keys.Seal(b, model.LinkSecretContext(chainID, idx))
}

// ErrNoSecrets: the link has no secrets yet (never deployed).
var ErrNoSecrets = errors.New("cascade: the link has no secrets")

// OpenSecrets opens what SealSecrets sealed; nil sealed is ErrNoSecrets.
func OpenSecrets(keys *secrets.Keyring, chainID int64, idx int, sealed []byte) (Secrets, error) {
	var s Secrets
	if len(sealed) == 0 {
		return s, ErrNoSecrets
	}
	b, err := keys.Open(sealed, model.LinkSecretContext(chainID, idx))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}
