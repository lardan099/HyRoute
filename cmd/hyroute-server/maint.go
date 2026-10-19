package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// lockData takes the data directory: the command and a running
// controller must not both change the database.
func lockData(cfg config.Config) (*os.File, error) {
	lock, err := datadir.Lock(cfg.DataDir)
	if errors.Is(err, datadir.ErrLocked) {
		return nil, fmt.Errorf("панель работает с каталогом %s: остановите службу (например, systemctl stop hyroute-server) и повторите", cfg.DataDir)
	}
	if err != nil {
		return nil, fmt.Errorf("data directory %s: %w", cfg.DataDir, err)
	}
	return lock, nil
}

// openDB opens the controller's database as it is, without migrating it.
func openDB(ctx context.Context, cfg config.Config) (*sqlite.DB, error) {
	db, err := sqlite.OpenExisting(ctx, cfg.DBPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("базы %s нет", cfg.DBPath())
	}
	if err != nil {
		return nil, fmt.Errorf("database %s: %w", cfg.DBPath(), err)
	}
	return db, nil
}

// loadKey loads the master key the controller uses and checks it against
// the database without writing to it.
func loadKey(ctx context.Context, env toolEnv, cfg config.Config, db *sqlite.DB) (*secrets.Keyring, secrets.Source, error) {
	keys, src, err := secrets.Load(env.getenv, cfg.MasterKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, fmt.Errorf("%w: нет ни переменной %s, ни файла %s", secrets.ErrNoKey, secrets.EnvMasterKey, cfg.MasterKeyFile)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("master key: %w", err)
	}
	if err := secrets.Verify(ctx, keys, db, keySource(env.getenv, cfg)); err != nil {
		return nil, 0, err
	}
	return keys, src, nil
}

func toolRekey(ctx context.Context, args []string, env toolEnv) error {
	var rotate bool
	cfg, rest, err := config.LoadTool("rekey", args, env.getenv, env.stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&rotate, "rotate", false, "add a new key version to the key file first, then seal everything with it")
	})
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("rekey: unexpected argument %q", rest[0])
	}
	if err := openData(cfg); err != nil {
		return err
	}
	lock, err := lockData(cfg)
	if err != nil {
		return err
	}
	defer lock.Close()
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	if v, err := db.SchemaVersion(ctx); err != nil {
		return err
	} else if v != sqlite.KnownSchema() {
		return fmt.Errorf("схема базы %d, а эта программа знает %d: запустите панель этой версии один раз, чтобы она обновила базу, и повторите", v, sqlite.KnownSchema())
	}
	keys, src, err := loadKey(ctx, env, cfg, db)
	if err != nil {
		return err
	}
	if rotate {
		if src == secrets.FromEnv {
			return fmt.Errorf("ключ задан переменной %s: добавьте в неё строку новой версии («%d:<32 байта в base64>») сами и запустите rekey без -rotate", secrets.EnvMasterKey, keys.Current()+1)
		}
		if keys, err = secrets.AddVersion(cfg.MasterKeyFile, keys); err != nil {
			return fmt.Errorf("add a key version to %s: %w", cfg.MasterKeyFile, err)
		}
		fmt.Fprintf(env.stdout, "В файл %s добавлена версия %d мастер-ключа. Сохраните новую копию файла ключа.\n", cfg.MasterKeyFile, keys.Current())
	}
	n, unused, err := secrets.Rekey(ctx, keys, db)
	if err != nil {
		return fmt.Errorf("перешифровка прервана после %d значений: %w. Повторите hyroute-server rekey (без -rotate): перешифрованное останется, продолжится с остальных", n, err)
	}
	fmt.Fprintf(env.stdout, "Перешифровано значений: %d. Все данные зашифрованы версией %d мастер-ключа.\n", n, keys.Current())
	if len(unused) == 0 {
		fmt.Fprintln(env.stdout, "Других версий в ключе нет.")
		return nil
	}
	fmt.Fprintf(env.stdout, "Версии %s базе больше не нужны: их строки можно удалить из ключа.\n", versionList(unused))
	fmt.Fprintln(env.stdout, "Копии базы, сделанные до перешифровки, зашифрованы и ими: пока такие копии нужны, храните прежний файл ключа вместе с ними.")
	return nil
}

func toolResetPassword(ctx context.Context, args []string, env toolEnv) error {
	var fromStdin bool
	cfg, rest, err := config.LoadTool("reset-password", args, env.getenv, env.stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&fromStdin, "password-stdin", false, "read the new password from the first line of stdin instead of making one")
	})
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("reset-password: name the user: hyroute-server reset-password [-password-stdin] <имя>")
	}
	if err := openData(cfg); err != nil {
		return err
	}
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	password, made := "", false
	if fromStdin {
		line, err := bufio.NewReader(env.stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read the password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		if password, err = auth.GeneratePassword(); err != nil {
			return err
		}
		made = true
	}
	a := auth.New(db)
	u, err := a.ResetPasswordLocal(ctx, rest[0], password)
	if errors.Is(err, auth.ErrNoUser) {
		users, lerr := db.ListUsers(ctx)
		if lerr != nil || len(users) == 0 {
			return err
		}
		names := make([]string, len(users))
		for i, u := range users {
			names[i] = u.Username
		}
		return fmt.Errorf("%w; пользователи панели: %s", err, strings.Join(names, ", "))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(env.stdout, "Пароль пользователя %s сменён, все его сессии завершены.\n", u.Username)
	if made {
		fmt.Fprintf(env.stdout, "Новый пароль (больше он нигде не показывается): %s\n", password)
	}
	return nil
}

// doctorReport prints checks as they go and counts the problems.
type doctorReport struct {
	env           toolEnv
	errors, warns int
}

func (r *doctorReport) ok(format string, a ...any) {
	fmt.Fprintf(r.env.stdout, "  ок      "+format+"\n", a...)
}

func (r *doctorReport) warn(format string, a ...any) {
	r.warns++
	fmt.Fprintf(r.env.stdout, "  важно   "+format+"\n", a...)
}

func (r *doctorReport) fail(format string, a ...any) {
	r.errors++
	fmt.Fprintf(r.env.stdout, "  ОШИБКА  "+format+"\n", a...)
}

// Free space below these is a problem or worth a look.
const (
	doctorFreeFail = 100 << 20
	doctorFreeWarn = 1 << 30
)

func toolDoctor(ctx context.Context, args []string, env toolEnv) error {
	cfg, rest, err := config.LoadTool("doctor", args, env.getenv, env.stderr, nil)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("doctor: unexpected argument %q", rest[0])
	}
	r := &doctorReport{env: env}
	fmt.Fprintf(env.stdout, "hyroute-server %s, каталог данных %s\n", version, cfg.DataDir)
	if err := datadir.Check(cfg.DataDir, true); err != nil {
		r.fail("каталог данных: %v", err)
		return r.result()
	}
	r.ok("каталог данных: доступ только у пользователя панели")

	if lock, err := datadir.Lock(cfg.DataDir); err == nil {
		lock.Close()
		r.ok("служба сейчас не работает с этим каталогом")
	} else if errors.Is(err, datadir.ErrLocked) {
		r.ok("служба работает (проверки только читают)")
	} else {
		r.warn("блокировка каталога: %v", err)
	}

	files := []string{cfg.DBPath(), cfg.DBPath() + "-wal", cfg.DBPath() + "-shm", filepath.Join(cfg.DataDir, "setup-token")}
	if !secrets.KeyInEnv(env.getenv) {
		files = append(files, cfg.MasterKeyFile)
	}
	if cfg.BackupPassphraseFile != "" {
		files = append(files, cfg.BackupPassphraseFile)
	}
	backups, _ := (&backup.Manager{Dir: cfg.BackupDir()}).List()
	for _, b := range backups {
		files = append(files, filepath.Join(cfg.BackupDir(), b.Name))
	}
	bad := 0
	for _, f := range files {
		if _, err := os.Lstat(f); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := datadir.Check(f, false); err != nil {
			r.fail("%v", err)
			bad++
		}
	}
	if _, err := os.Stat(cfg.BackupDir()); err == nil {
		if err := datadir.Check(cfg.BackupDir(), true); err != nil {
			r.fail("%v", err)
			bad++
		}
	}
	if bad == 0 {
		r.ok("файлы базы, ключа и копий: доступ только у пользователя панели")
	}

	if free, err := datadir.FreeSpace(cfg.DataDir); err == nil {
		switch {
		case free < doctorFreeFail:
			r.fail("свободно на диске каталога данных %s: база не сможет расти, а копии — записаться", sizeText(free))
		case free < doctorFreeWarn:
			r.warn("свободно на диске каталога данных всего %s", sizeText(free))
		default:
			r.ok("свободно на диске каталога данных %s", sizeText(free))
		}
	} else if !errors.Is(err, errors.ErrUnsupported) {
		r.warn("свободное место: %v", err)
	}

	db, err := openDB(ctx, cfg)
	if err != nil {
		r.fail("%v", err)
		return r.result()
	}
	defer db.Close()
	v, err := db.SchemaVersion(ctx)
	switch {
	case err != nil:
		r.fail("схема базы: %v", err)
	case v < sqlite.KnownSchema():
		r.ok("схема базы %d: панель этой версии обновит её до %d при запуске", v, sqlite.KnownSchema())
	default:
		r.ok("схема базы %d", v)
	}
	if err := db.IntegrityCheck(ctx); err != nil {
		r.fail("база повреждена: %v. Восстановите её из копии (hyroute-server restore)", err)
	} else {
		r.ok("целостность базы (integrity_check)")
	}

	keys, _, err := loadKey(ctx, env, cfg, db)
	if err != nil {
		r.fail("%v", err)
	} else {
		used, err := db.SealedVersions(ctx)
		if err != nil {
			r.fail("версии ключа в базе: %v", err)
		} else {
			r.ok("мастер-ключ из %s открывает данные базы (версии в данных: %s)", keySource(env.getenv, cfg), versionList(used))
			old := 0
			for _, u := range used {
				if u != keys.Current() {
					old++
				}
			}
			if old > 0 {
				r.warn("часть данных зашифрована не текущей версией %d ключа: hyroute-server rekey перешифрует их", keys.Current())
			}
		}
	}

	switch {
	case len(backups) == 0:
		r.warn("резервных копий в %s нет: hyroute-server backup или -backup-interval", cfg.BackupDir())
	case time.Since(backups[0].At) > 8*24*time.Hour:
		r.warn("последняя резервная копия — %s, ей больше недели", backups[0].At.Local().Format("2006-01-02 15:04"))
	default:
		r.ok("резервных копий: %d, последняя — %s", len(backups), backups[0].At.Local().Format("2006-01-02 15:04"))
	}
	if n, err := db.CountUnfinishedJobs(ctx); err == nil && n > 0 {
		r.ok("незавершённых заданий: %d", n)
	}
	return r.result()
}

func (r *doctorReport) result() error {
	if r.errors > 0 {
		return fmt.Errorf("doctor: проблем — %d, предупреждений — %d", r.errors, r.warns)
	}
	if r.warns > 0 {
		fmt.Fprintf(r.env.stdout, "Проблем нет, предупреждений — %d.\n", r.warns)
		return nil
	}
	fmt.Fprintln(r.env.stdout, "Проблем нет.")
	return nil
}

func sizeText(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%d МБ", b>>20)
	default:
		return fmt.Sprintf("%d КБ", b>>10)
	}
}
