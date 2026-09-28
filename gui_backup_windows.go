//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/backup"
	"github.com/lardan099/hyroute/internal/store"
)

// «Резервная копия» (internal/app/backup.go): the dialogs and the user's
// file. HyRoute runs elevated: the file is written and read only through
// store.WriteUserFile / ReadUserFile, as the user could without elevation.

var backupFilters = []runtime.FileFilter{
	{DisplayName: "Резервная копия HyRoute (*.hyroute-backup)", Pattern: "*" + backup.Ext},
}

func (g *GUI) BackupContents(secrets bool) []app.BackupSectionInfo {
	return g.ctl.BackupContents(secrets)
}

// ExportBackup builds the file first (password checks and encryption), then
// asks where to save it; "" = cancelled.
func (g *GUI) ExportBackup(o app.BackupExportOptions) (string, error) {
	b, err := g.ctl.ExportBackup(o)
	if err != nil {
		return "", err
	}
	path, err := runtime.SaveFileDialog(g.context(), runtime.SaveDialogOptions{
		Title:           "Сохранить резервную копию HyRoute",
		DefaultFilename: "HyRoute-" + time.Now().Format("2006-01-02") + backup.Ext,
		Filters:         backupFilters,
	})
	if err != nil || path == "" {
		return "", err
	}
	if !strings.EqualFold(filepath.Ext(path), backup.Ext) {
		// The dialog asked about overwriting the name it returned, not
		// this one: never replace a file it did not ask about.
		path += backup.Ext
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("файл «%s» уже есть: выберите другое имя или сам этот файл", path)
		}
	}
	return path, store.WriteUserFile(path, b)
}

// OpenBackup asks for a file and opens it (HyRoute 1.2.0's .hyroute files
// too); a cancelled dialog is Token "".
func (g *GUI) OpenBackup() (app.BackupOpened, error) {
	path, err := runtime.OpenFileDialog(g.context(), runtime.OpenDialogOptions{
		Title: "Выберите резервную копию HyRoute",
		Filters: []runtime.FileFilter{
			{DisplayName: "Резервная копия HyRoute (*.hyroute-backup, *.hyroute)", Pattern: "*" + backup.Ext + ";*" + backup.LegacyExt},
			{DisplayName: "Все файлы (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return app.BackupOpened{}, err
	}
	b, err := store.ReadUserFile(path, backup.MaxFile)
	if errors.Is(err, store.ErrUserFileTooLarge) {
		err = backup.ErrTooLarge
	}
	if err != nil {
		return app.BackupOpened{}, err
	}
	return g.ctl.OpenBackup(filepath.Base(path), b)
}

func (g *GUI) UnlockBackup(token, password string) (app.BackupPreview, error) {
	return g.ctl.UnlockBackup(token, password)
}

func (g *GUI) PlanBackup(token string, ch app.BackupChoice) (app.BackupPlan, error) {
	return g.ctl.PlanBackup(token, ch)
}

// ApplyBackup restores; the kill switch check follows a kill switch change
// (as SaveEngineOptions).
func (g *GUI) ApplyBackup(token string, ch app.BackupChoice, cur app.BackupAppearance, digest string) (app.BackupApplyResult, error) {
	was, cli := g.killSwitchOn(), g.cliMode()
	res, err := g.ctl.ApplyBackup(token, ch, cur, digest)
	g.afterRestore(was, cli)
	return res, err
}

func (g *GUI) CloseBackup(token string) { g.ctl.CloseBackup(token) }

func (g *GUI) RestoreUndoInfo() app.BackupUndoInfo { return g.ctl.RestoreUndoInfo() }

func (g *GUI) UndoRestore() (app.BackupApplyResult, error) {
	was, cli := g.killSwitchOn(), g.cliMode()
	res, err := g.ctl.UndoRestore()
	g.afterRestore(was, cli)
	return res, err
}

func (g *GUI) ForgetRestoreUndo() error { return g.ctl.ForgetRestoreUndo() }

// afterRestore follows what a restore or its undo changed outside the
// controller: the kill switch check, and hyroutectl's pipe (a restore
// keeps the access mode, but repairs a broken prefs.json; an undo puts the
// old file back).
func (g *GUI) afterRestore(ksWas bool, cliWas string) {
	if g.killSwitchOn() != ksWas {
		go g.syncKillSwitchCheck()
	}
	if m := g.cliMode(); m != cliWas {
		g.applyCLI(m)
	}
}

// cliMode is the effective hyroutectl mode ("off" while prefs.json is
// broken).
func (g *GUI) cliMode() string {
	m, _ := g.ctl.CLIMode()
	return m
}

func (g *GUI) killSwitchOn() bool {
	st := g.ctl.Settings()
	return st.KillSwitchOn()
}
