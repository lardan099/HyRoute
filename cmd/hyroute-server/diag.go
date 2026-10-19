package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
)

// toolDiag writes the diagnostic bundle. It only reads, so it works while
// the service runs; the controller's log buffer lives in that process and
// is not in this bundle.
func toolDiag(ctx context.Context, args []string, env toolEnv) error {
	var out string
	var jobs int
	cfg, rest, err := config.LoadTool("diag", args, env.getenv, env.stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "write the bundle to this file (default hyroute-diag-<time>.zip in the current directory)")
		fs.IntVar(&jobs, "jobs", diag.DefaultJobs, fmt.Sprintf("how many of the latest jobs come with their logs (1 to %d)", diag.MaxJobs))
	})
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("diag: unexpected argument %q", rest[0])
	}
	if jobs < 1 || jobs > diag.MaxJobs {
		return fmt.Errorf("diag: -jobs %d: from 1 to %d", jobs, diag.MaxJobs)
	}
	if err := openData(cfg); err != nil {
		return err
	}
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	keys, _, err := loadKey(ctx, env, cfg, db)
	if err != nil {
		return err
	}
	// Whether the copies are encrypted, without reading the passphrase.
	encrypted := cfg.BackupPassphraseFile != "" || env.getenv(config.EnvBackupPassphrase) != ""
	b := &diag.Builder{Store: db, Keys: keys, Geo: &geo.Store{Dir: filepath.Join(cfg.DataDir, "geo")}, Backups: &backup.Manager{Dir: cfg.BackupDir()},
		Version: version, Settings: diag.SettingsOf(cfg, env.getenv, encrypted, false), Jobs: jobs}
	bundle, err := b.Build(ctx)
	if err != nil {
		return err
	}
	if out == "" {
		out = bundle.Name()
	}
	f, err := datadir.Create(out)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("файл %s уже есть: укажите другой -out", out)
	}
	if err != nil {
		return err
	}
	err = bundle.WriteZip(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
		return err
	}
	st, err := os.Stat(out)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.stdout, "Диагностический пакет: %s (%d байт)\n", out, st.Size())
	w := tabwriter.NewWriter(env.stdout, 0, 4, 2, ' ', 0)
	for _, e := range bundle.Entries() {
		fmt.Fprintf(w, "  %s\t%d\t%s\n", e.Name, e.Size, e.About)
	}
	w.Flush()
	fmt.Fprintln(env.stdout, "Пароли, ключи и ссылки в пакет не попадают; названия серверов, адреса, домены и имена пользователей заменены на server-1, host-1, domain-1, user-1. Таблицы замен в пакете нет. Перед отправкой файлы можно открыть и проверить.")
	fmt.Fprintln(env.stdout, "Журнала панели в этом пакете нет: он есть только у работающей службы. Если он нужен, скачайте пакет в панели: «Настройки» → «Диагностический пакет».")
	return nil
}
