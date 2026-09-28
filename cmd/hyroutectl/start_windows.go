//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// taskName is the sign-in task of the user with sid. It must equal
// internal/autostart's kind.taskName for the start task (importing
// autostart would pull go-ole into hyroutectl).
func taskName(sid string) string { return "HyRoute (" + sid + ")" }

// launchError is a message printed as it is (a sentence).
type launchError string

func (e launchError) Error() string { return string(e) }

// launch starts HyRoute (hyroutectl start): through the user's sign-in
// task, which starts it elevated without a UAC prompt, in the tray; else
// HyRoute.exe next to hyroutectl.exe with a UAC prompt.
func launch(stderr io.Writer, sid string) error {
	if sys, err := windows.GetSystemDirectory(); err == nil && sid != "" {
		cmd := exec.Command(filepath.Join(sys, "schtasks.exe"), "/run", "/tn", taskName(sid))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		if cmd.Run() == nil {
			fmt.Fprintln(stderr, "Запускаю HyRoute через задачу автозапуска…")
			return nil
		}
		// No task, disabled or not allowed: HyRoute.exe instead.
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(self)
	exe := filepath.Join(dir, "HyRoute.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("HyRoute.exe не найден рядом с hyroutectl.exe (%s)", dir)
	}
	fmt.Fprintln(stderr, "Запускаю HyRoute (Windows попросит права администратора)…")
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := windows.UTF16PtrFromString(dir)
	if err := windows.ShellExecute(0, verb, file, nil, cwd, windows.SW_SHOWNORMAL); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return launchError("Запуск отменён: права администратора не выданы.")
		}
		return fmt.Errorf("HyRoute не запустился: %v", err)
	}
	return nil
}
