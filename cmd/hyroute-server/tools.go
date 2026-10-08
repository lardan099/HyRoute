package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// toolEnv is what a maintenance command talks to.
type toolEnv struct {
	getenv func(string) string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type tool struct {
	name, args, about string
	run               func(ctx context.Context, args []string, env toolEnv) error
}

// tools are the maintenance commands: hyroute-server <name> [flags] [args].
// They work on the data directory of this machine only.
var tools []tool

func init() {
	tools = []tool{
		{"backup", "[-out файл]", "копия базы в <data-dir>/backups или в файл; служба может работать", toolBackup},
		{"restore", "[-force] файл", "восстановить базу из копии; служба должна быть остановлена", toolRestore},
		{"reset-password", "[-password-stdin] имя", "новый пароль пользователя (создаётся и показывается один раз), его сессии завершаются", toolResetPassword},
		{"rekey", "[-rotate]", "перешифровать данные текущей версией ключа (-rotate: сначала добавить новую); служба должна быть остановлена", toolRekey},
		{"doctor", "", "проверить права файлов, ключ, целостность базы, свободное место и копии; служба может работать", toolDoctor},
		{"diag", "[-out файл] [-jobs N]", "диагностический пакет без секретов, с заменой имён и адресов; служба может работать", toolDiag},
		{"version", "", "версия программы и схемы базы", toolVersion},
		{"help", "", "этот список", toolHelp},
	}
}

func runTool(ctx context.Context, name string, args []string, env toolEnv) error {
	for _, t := range tools {
		if t.name == name {
			return t.run(ctx, args, env)
		}
	}
	return fmt.Errorf("unknown command %q: the commands are listed by hyroute-server help", name)
}

func toolHelp(_ context.Context, _ []string, env toolEnv) error {
	fmt.Fprintln(env.stdout, "hyroute-server [флаги]: запустить панель (флаги: hyroute-server -h).")
	fmt.Fprintln(env.stdout, "Команды обслуживания (флаги каталога данных и ключа те же, что у панели: -data-dir, -master-key-file):")
	w := tabwriter.NewWriter(env.stdout, 0, 4, 2, ' ', 0)
	for _, t := range tools {
		fmt.Fprintf(w, "  hyroute-server %s %s\t%s\n", t.name, t.args, t.about)
	}
	return w.Flush()
}

func toolVersion(_ context.Context, args []string, env toolEnv) error {
	if len(args) > 0 {
		return fmt.Errorf("version: unexpected argument %q", args[0])
	}
	fmt.Fprintf(env.stdout, "hyroute-server %s\nсхема базы: %d\n%s %s/%s\n", version, sqlite.KnownSchema(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// openData checks the data directory the way the controller does: the
// command runs as the controller's user, or the files would be refused.
func openData(cfg config.Config) error {
	if err := datadir.Dir(cfg.DataDir); err != nil {
		return fmt.Errorf("data directory: %w. Run the command as the controller's user", err)
	}
	return nil
}

func keySource(getenv func(string) string, cfg config.Config) string {
	if secrets.KeyInEnv(getenv) {
		return "переменной " + secrets.EnvMasterKey
	}
	return "файла " + cfg.MasterKeyFile
}

func versionList(vs []uint32) string {
	if len(vs) == 0 {
		return "нет зашифрованных значений"
	}
	slices.Sort(vs)
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, ", ")
}

func toolBackup(ctx context.Context, args []string, env toolEnv) error {
	var out string
	cfg, rest, err := config.LoadTool("backup", args, env.getenv, env.stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "write the copy to this file instead of <data-dir>/backups")
	})
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("backup: unexpected argument %q", rest[0])
	}
	if err := openData(cfg); err != nil {
		return err
	}
	pass, err := backup.Passphrase(env.getenv, config.EnvBackupPassphrase, cfg.BackupPassphraseFile)
	if err != nil {
		return err
	}
	db, err := sqlite.OpenExisting(ctx, cfg.DBPath())
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("базы %s нет: копировать нечего", cfg.DBPath())
	}
	if err != nil {
		return fmt.Errorf("database %s: %w", cfg.DBPath(), err)
	}
	defer db.Close()
	schema, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	versions, err := db.SealedVersions(ctx)
	if err != nil {
		return err
	}
	if out == "" {
		m := &backup.Manager{DB: db, Dir: cfg.BackupDir(), Keep: cfg.BackupKeep, Passphrase: pass}
		info, err := m.Make(ctx)
		if err != nil {
			return err
		}
		out = filepath.Join(cfg.BackupDir(), info.Name)
	} else if err := backup.Write(ctx, db, cfg.DataDir, out, pass); err != nil {
		return err
	}
	st, err := os.Stat(out)
	if err != nil {
		return err
	}
	enc := "нет (задайте -backup-passphrase-file или " + config.EnvBackupPassphrase + ", чтобы шифровать)"
	if pass != "" {
		enc = "да, парольной фразой"
	}
	fmt.Fprintf(env.stdout, "Копия: %s (%d байт)\nЗашифрована: %s\nСхема базы: %d\nВерсии мастер-ключа в данных: %s\n", out, st.Size(), enc, schema, versionList(versions))
	fmt.Fprintln(env.stdout, "Мастер-ключа в копии нет: без копии ключа она не восстановится. Храните ключ отдельно от копии.")
	return nil
}

func toolRestore(ctx context.Context, args []string, env toolEnv) error {
	var force bool
	cfg, rest, err := config.LoadTool("restore", args, env.getenv, env.stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&force, "force", false, "replace a database with users or servers (it is moved aside, not deleted)")
	})
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("restore: name the copy: hyroute-server restore [-force] <файл>")
	}
	file := rest[0]
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	if err := openData(cfg); err != nil {
		return err
	}
	lock, err := datadir.Lock(cfg.DataDir)
	if errors.Is(err, datadir.ErrLocked) {
		return fmt.Errorf("панель работает с каталогом %s: остановите службу (например, systemctl stop hyroute-server) и повторите", cfg.DataDir)
	}
	if err != nil {
		return fmt.Errorf("data directory %s: %w", cfg.DataDir, err)
	}
	defer lock.Close()
	pass, err := backup.Passphrase(env.getenv, config.EnvBackupPassphrase, cfg.BackupPassphraseFile)
	if err != nil {
		return err
	}
	r, err := backup.Restore(ctx, backup.RestoreOptions{
		File:       file,
		DB:         cfg.DBPath(),
		Passphrase: pass,
		Force:      force,
		Keys: func() (*secrets.Keyring, string, error) {
			k, _, err := secrets.Load(env.getenv, cfg.MasterKeyFile)
			return k, keySource(env.getenv, cfg), err
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.stdout, "База %s восстановлена из %s.\nСхема базы: %d (эта программа знает до %d)\nВерсии мастер-ключа в данных: %s\n", cfg.DBPath(), file, r.Schema, sqlite.KnownSchema(), versionList(r.Versions))
	if r.Previous != "" {
		fmt.Fprintf(env.stdout, "Прежняя база перенесена в %s: удалите её, когда убедитесь, что всё на месте.\n", r.Previous)
	}
	if r.Unfinished > 0 {
		fmt.Fprintf(env.stdout, "В копии %d незавершённых заданий: при запуске панель проверит фактическое состояние их серверов и продолжит или завершит их, как после сбоя.\n", r.Unfinished)
	}
	fmt.Fprintln(env.stdout, "Запустите службу. Копия — состояние на момент её создания: если позже конфиги серверов менялись, панель увидит это как правку вне HyRoute.")
	return nil
}
