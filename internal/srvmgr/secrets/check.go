package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// The database remembers its master key: a check value sealed with the
// key sits in the settings table. A missing or another key is refused at
// start, before anything is sealed with it: a controller that started with
// a new key would leave every stored credential and config unreadable,
// and the old key could not be added back next to the new one (both are
// version 1).
const (
	checkSetting = "master_key_check"
	checkContext = "settings/" + checkSetting
	checkText    = "hyroute-server master key check"
)

var (
	// ErrNoKey: there is no master key, and the database already has
	// values sealed with one.
	ErrNoKey = errors.New("мастер-ключ не найден")
	// ErrKeyMismatch: the master key does not open the database's values.
	ErrKeyMismatch = errors.New("мастер-ключ не подходит к базе")
)

// Database is what the master key check needs from the store.
type Database interface {
	// Setting is a value of the settings table (store.ErrNotFound: not
	// set).
	Setting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string, at time.Time) error
	// HasSealed reports whether any row holds a sealed value.
	HasSealed(ctx context.Context) (bool, error)
	// SealedSample is one sealed value and the context it was sealed for
	// (store.ErrNotFound: none).
	SealedSample(ctx context.Context) ([]byte, string, error)
	// SealedVersions are the master key versions of the stored sealed
	// values.
	SealedVersions(ctx context.Context) ([]uint32, error)
}

// Open gives the controller its master key (Load) and checks it against
// the database:
//   - no key: a new key file is created only while the database has no
//     check value and nothing sealed, otherwise ErrNoKey;
//   - the key must open the check value (ErrKeyMismatch); after a
//     rotation the check value moves to the current version;
//   - a database without a check value (new, or from a build before it)
//     gets one, once a sealed value it has opens with the key;
//   - every version the stored values are sealed with must be loaded
//     (ErrKeyMismatch): they keep their version after a rotation, so the
//     old one stays needed although the check value moved on.
func Open(ctx context.Context, getenv func(string) string, file string, db Database) (*Keyring, Source, error) {
	keys, src, err := Load(getenv, file)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return nil, 0, err
	}
	check, err := db.Setting(ctx, checkSetting)
	bound := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, 0, err
	}

	if missing {
		if !bound {
			has, err := db.HasSealed(ctx)
			if err != nil {
				return nil, 0, err
			}
			if !has {
				if keys, err = createKeyFile(file); err != nil {
					return nil, 0, err
				}
				if err := storeCheck(ctx, db, keys); err != nil {
					return nil, 0, err
				}
				return keys, Created, nil
			}
		}
		return nil, 0, fmt.Errorf("%w: нет ни переменной %s, ни файла %s, а в базе уже есть данные, зашифрованные мастер-ключом. "+
			"Новый ключ не создан: с ним не откроются сохранённые пароли, ключи SSH и конфиги. "+
			"Верните файл ключа из резервной копии, укажите путь к нему флагом -master-key-file или передайте ключ в %s. "+
			"Если данные базы не нужны, удалите её, и панель начнёт с чистого листа",
			ErrNoKey, EnvMasterKey, file, EnvMasterKey)
	}

	from := "файла " + file
	if src == FromEnv {
		from = "переменной " + EnvMasterKey
	}
	if bound {
		b, err := base64.StdEncoding.DecodeString(check)
		if err != nil {
			return nil, 0, fmt.Errorf("проверочное значение мастер-ключа в базе (settings, %s) повреждено: %w", checkSetting, err)
		}
		if _, err := keys.Open(b, checkContext); err != nil {
			return nil, 0, mismatch(err, from)
		}
		if err := versionsLoaded(ctx, db, keys, from); err != nil {
			return nil, 0, err
		}
		if keys.NeedsRewrap(b) {
			if err := storeCheck(ctx, db, keys); err != nil {
				return nil, 0, err
			}
		}
		return keys, src, nil
	}

	switch sealed, sctx, err := db.SealedSample(ctx); {
	case err == nil:
		var uv *UnknownVersionError
		if _, err := keys.Open(sealed, sctx); errors.Is(err, ErrWrongKey) || errors.As(err, &uv) {
			return nil, 0, mismatch(err, from)
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, 0, err
	}
	if err := versionsLoaded(ctx, db, keys, from); err != nil {
		return nil, 0, err
	}
	if err := storeCheck(ctx, db, keys); err != nil {
		return nil, 0, err
	}
	return keys, src, nil
}

// versionsLoaded: the keyring has every version the stored values are
// sealed with.
func versionsLoaded(ctx context.Context, db Database, keys *Keyring, from string) error {
	vs, err := db.SealedVersions(ctx)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if _, ok := keys.keys[v]; !ok {
			return mismatch(&UnknownVersionError{v}, from)
		}
	}
	return nil
}

// mismatch explains why the key from `from` does not open the database.
func mismatch(err error, from string) error {
	var uv *UnknownVersionError
	if errors.As(err, &uv) {
		return fmt.Errorf("%w: её данные зашифрованы версией %d мастер-ключа, а в ключе из %s такой версии нет. "+
			"Добавьте строку «%d:<ключ>» из резервной копии рядом с остальными версиями",
			ErrKeyMismatch, uv.Version, from, uv.Version)
	}
	if errors.Is(err, ErrWrongKey) {
		return fmt.Errorf("%w: её данные зашифрованы не ключом из %s, и с ним не откроются сохранённые пароли, ключи SSH и конфиги. "+
			"Укажите ключ, с которым работала база: файл из резервной копии (флаг -master-key-file) или переменную %s. "+
			"Если ключ меняли, оставьте старую версию рядом с новой",
			ErrKeyMismatch, from, EnvMasterKey)
	}
	return fmt.Errorf("проверочное значение мастер-ключа в базе (settings, %s): %w", checkSetting, err)
}

// settingWriter stores a value of the settings table.
type settingWriter interface {
	SetSetting(ctx context.Context, key, value string, at time.Time) error
}

// storeCheck seals the check value with the current key version.
func storeCheck(ctx context.Context, db settingWriter, keys *Keyring) error {
	b, err := keys.SealString(checkText, checkContext)
	if err != nil {
		return err
	}
	return db.SetSetting(ctx, checkSetting, base64.StdEncoding.EncodeToString(b), time.Now())
}
