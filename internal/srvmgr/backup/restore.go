package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// RestoreOptions say what to restore where.
type RestoreOptions struct {
	// File is the copy.
	File string
	// DB is the controller's database file. The caller holds the lock of
	// its directory, so no controller runs on it.
	DB string
	// Passphrase opens an encrypted copy.
	Passphrase string
	// Keys loads the master key the controller will start with, and names
	// where it came from; an error wrapping fs.ErrNotExist: there is none.
	Keys func() (*secrets.Keyring, string, error)
	// Force replaces a database in use (with users or servers): it is
	// moved aside, not deleted.
	Force bool
	Now   func() time.Time
}

// Restored is what a restore did.
type Restored struct {
	// Schema is the schema version of the copy (the controller migrates
	// an older one when it starts).
	Schema int
	// Versions are the master key versions the copy's values use.
	Versions []uint32
	// Previous is where the database that was in place went ("": there
	// was none, or it held nothing and was removed).
	Previous string
	// Unfinished counts the jobs that ran or waited when the copy was
	// made: the controller recovers them at start as after a crash.
	Unfinished int
}

var (
	// ErrNeedPassphrase: the copy is encrypted and no passphrase was given.
	ErrNeedPassphrase = errors.New("копия зашифрована: передайте парольную фразу (переменная HYROUTE_SERVER_BACKUP_PASSPHRASE или флаг -passphrase-file)")
	// ErrInUse: the database in place has users or servers.
	ErrInUse = errors.New("в каталоге данных уже есть база с пользователями или серверами")
)

// Restore puts the copy in place of the database. Everything is checked
// before the database in place is touched: the passphrase, the schema
// version (a copy newer than this controller is refused), the integrity
// of the copy and the master key (it must open the copy's values of every
// key version).
func Restore(ctx context.Context, o RestoreOptions) (r Restored, err error) {
	tmp := o.DB + ".restore"
	removeDB(tmp)
	if err := unpack(o.File, tmp, o.Passphrase); err != nil {
		removeDB(tmp)
		return r, err
	}
	defer func() {
		if err != nil {
			removeDB(tmp)
		}
	}()
	if r, err = check(ctx, tmp, o); err != nil {
		return r, err
	}
	// Whatever SQLite left next to the copy while it was checked goes.
	os.Remove(tmp + "-wal")
	os.Remove(tmp + "-shm")

	if _, err := os.Lstat(o.DB); err == nil {
		used := true
		if cur, err := sqlite.OpenExisting(ctx, o.DB); err == nil {
			used, err = cur.InUse(ctx)
			cur.Close()
			if err != nil {
				used = true
			}
		}
		if used && !o.Force {
			return r, fmt.Errorf("%w (%s). Чтобы заменить её копией, добавьте -force: прежняя база не удаляется, а переносится рядом, в %s.before-restore-<время>", ErrInUse, o.DB, filepath.Base(o.DB))
		}
		if used {
			now := time.Now
			if o.Now != nil {
				now = o.Now
			}
			r.Previous = o.DB + ".before-restore-" + now().UTC().Format(timeLayout)
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := os.Rename(o.DB+suffix, r.Previous+suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return r, fmt.Errorf("move the database in place aside: %w", err)
				}
			}
		} else if err := removeDB(o.DB); err != nil {
			return r, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return r, err
	}
	if err := os.Rename(tmp, o.DB); err != nil {
		return r, err
	}
	return r, datadir.File(o.DB)
}

// removeDB removes a database file with its WAL and shared memory.
func removeDB(path string) error {
	var errs []error
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// unpack writes the database of the copy file to tmp (owner-only),
// decrypting it.
func unpack(file, tmp, passphrase string) (err error) {
	src, err := os.Open(file)
	if err != nil {
		return err
	}
	defer src.Close()
	head := make([]byte, len(cryptMagic))
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	encrypted := Encrypted(head[:n])
	if encrypted && passphrase == "" {
		return ErrNeedPassphrase
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if err := datadir.File(tmp); err != nil {
		return err
	}
	if encrypted {
		err = decrypt(f, src, passphrase)
	} else {
		_, err = io.Copy(f, src)
	}
	if err != nil {
		return err
	}
	return f.Sync()
}

// check opens the unpacked copy without migrating it and checks its
// schema, integrity and master key.
func check(ctx context.Context, path string, o RestoreOptions) (Restored, error) {
	var r Restored
	db, err := sqlite.OpenExisting(ctx, path)
	if sqlite.IsNewerSchema(err) {
		return r, fmt.Errorf("копия сделана более новой версией hyroute-server: %w. Восстановите её той версией, которой она сделана, или новее", err)
	}
	if err != nil {
		return r, fmt.Errorf("копия %s не открывается как база hyroute-server: %w", o.File, err)
	}
	defer db.Close()
	if r.Schema, err = db.SchemaVersion(ctx); err != nil {
		return r, err
	}
	if err := db.IntegrityCheck(ctx); err != nil {
		return r, fmt.Errorf("копия %s повреждена: %w", o.File, err)
	}
	if r.Versions, err = db.SealedVersions(ctx); err != nil {
		return r, err
	}
	if r.Unfinished, err = db.CountUnfinishedJobs(ctx); err != nil {
		return r, err
	}
	keys, from, err := o.Keys()
	if errors.Is(err, fs.ErrNotExist) {
		need, err := secrets.NeedsKey(ctx, db)
		if err != nil {
			return r, err
		}
		if need {
			return r, fmt.Errorf("%w: данные копии зашифрованы мастер-ключом, а ключа нет. Мастер-ключ в копию не кладётся: "+
				"положите копию файла ключа на его место (флаг -master-key-file, права 0600) или передайте ключ переменной %s",
				secrets.ErrNoKey, secrets.EnvMasterKey)
		}
		return r, nil
	}
	if err != nil {
		return r, fmt.Errorf("master key: %w", err)
	}
	if err := secrets.Verify(ctx, keys, db, from); err != nil {
		return r, fmt.Errorf("копия %s: %w", o.File, err)
	}
	return r, nil
}
