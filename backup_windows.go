//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/internal/app"
)

// Backup and restore (see internal/app/backup.go).

var backupFilter = []runtime.FileFilter{{DisplayName: "Копия HyRoute (*.hyroute)", Pattern: "*.hyroute"}}

// SaveBackup writes a backup to a file the user chooses: full (with a
// password) or rules only. It returns the path ("" = cancelled).
func (g *GUI) SaveBackup(full bool, password string) (string, error) {
	b, err := g.ctl.Backup(full, password)
	if err != nil {
		return "", err
	}
	kind := "rules"
	if full {
		kind = "full"
	}
	path, err := runtime.SaveFileDialog(g.context(), runtime.SaveDialogOptions{
		Title:           "Сохранить копию HyRoute",
		DefaultFilename: fmt.Sprintf("HyRoute-%s-%s.hyroute", kind, time.Now().Format("2006-01-02")),
		Filters:         backupFilter,
	})
	if err != nil || path == "" {
		return "", err
	}
	if filepath.Ext(path) == "" {
		path += ".hyroute"
	}
	return path, os.WriteFile(path, b, 0o600)
}

// BackupChoice is the file ChooseBackup read.
type BackupChoice struct {
	Name string `json:"name"` // "" = cancelled
	app.BackupInfo
}

// ChooseBackup lets the user pick a backup and describes it; RestoreBackup
// then restores that file.
func (g *GUI) ChooseBackup() (BackupChoice, error) {
	path, err := runtime.OpenFileDialog(g.context(), runtime.OpenDialogOptions{Title: "Выберите копию HyRoute", Filters: backupFilter})
	if err != nil || path == "" {
		return BackupChoice{}, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return BackupChoice{}, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 32<<20 {
		return BackupChoice{}, errors.New("это не копия HyRoute")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return BackupChoice{}, err
	}
	info, err := g.ctl.InspectBackup(b)
	if err != nil {
		return BackupChoice{}, err
	}
	g.backupMu.Lock()
	g.backup = b
	g.backupMu.Unlock()
	return BackupChoice{Name: filepath.Base(path), BackupInfo: info}, nil
}

// RestoreBackup restores the file ChooseBackup read.
func (g *GUI) RestoreBackup(password string) (app.RestoreResult, error) {
	g.backupMu.Lock()
	b := g.backup
	g.backupMu.Unlock()
	if b == nil {
		return app.RestoreResult{}, errors.New("сначала выберите файл копии")
	}
	before := g.ctl.Settings()
	res, err := g.ctl.RestoreBackup(b, password)
	after := g.ctl.Settings()
	if after.KillSwitchOn() != before.KillSwitchOn() {
		go g.syncKillSwitchCheck()
	}
	if err == nil {
		g.backupMu.Lock()
		g.backup = nil
		g.backupMu.Unlock()
	}
	return res, err
}
