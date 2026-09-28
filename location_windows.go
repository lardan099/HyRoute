package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/store"
)

// A portable copy in Downloads or on the Desktop can be replaced by any
// program the user runs, and the next start runs it as administrator.
// Program Files is writable by administrators only, unless a folder in it
// was opened to users (an installer, a copy that kept its permissions):
// the permissions are checked too.
//
// The system folders come from Windows, not from environment variables:
// the user's own variables (HKCU\Environment) reach this elevated process
// too, and any program the user runs can set them.

func programFiles() []string {
	var out []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

func under(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel)
}

// protectedLocation reports whether dir is inside Program Files and the
// user's programs, which run without elevation, cannot change what HyRoute
// runs from there (see userCanReplace).
func protectedLocation(dir string) bool {
	exe, _ := os.Executable()
	return protectedLocationOf(dir, exe)
}

// protectedLocationOf is protectedLocation for the program exe (checked
// when it is in dir) instead of this one.
func protectedLocationOf(dir, exe string) bool {
	dir = filepath.Clean(dir)
	for _, root := range programFiles() {
		if !under(dir, root) {
			continue
		}
		user, err := store.LimitedToken()
		if err != nil {
			return false
		}
		if user == 0 {
			// Not elevated, or no split UAC token: no program of the user
			// runs with fewer rights than this one, only the path counts.
			return true
		}
		defer user.Close()
		return !userCanReplace(dir, root, exe, user)
	}
	return false
}

// userCanReplace reports whether a program running with user's token could
// put its own code where HyRoute runs from dir: add a file to dir (a DLL
// next to the exe is loaded with it), rewrite exe, or rename dir away and
// make another in its place. So neither dir nor any folder above it, up to
// root, may take new files or folders, let their contents be removed, or
// let their permissions or owner be changed; permissions that cannot be
// read count as granted. DELETE on dir or exe alone replaces nothing:
// the name cannot be taken again without adding to the folder.
func userCanReplace(dir, root, exe string, user windows.Token) bool {
	const (
		fileAddFile         = 0x2
		fileAddSubdirectory = 0x4
		fileDeleteChild     = 0x40
		takeOver            = windows.WRITE_DAC | windows.WRITE_OWNER
		folder              = fileAddFile | fileAddSubdirectory | fileDeleteChild | takeOver
	)
	may := func(path string, rights uint32) bool {
		granted, err := accessOf(path, user)
		return err != nil || granted&rights != 0
	}
	if exe != "" && strings.EqualFold(filepath.Dir(exe), dir) &&
		may(exe, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|takeOver) {
		return true
	}
	for d := dir; ; {
		if may(d, folder) {
			return true
		}
		up := filepath.Dir(d)
		if strings.EqualFold(d, filepath.Clean(root)) || up == d {
			return false
		}
		d = up
	}
}

// accessOf is the access user gets to path (0 for none).
func accessOf(path string, user windows.Token) (uint32, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	return store.Access(sd, user, windows.MAXIMUM_ALLOWED)
}

func moveTarget() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return filepath.Join(p, "HyRoute")
	}
	return `C:\Program Files\HyRoute`
}

// Files of a release folder; the rest of the source folder (it may be
// Downloads) is left alone.
var programFilesList = []string{"HyRoute.exe", "hyroute-updater.exe", "hysteria.exe", "WinDivert.dll", "WinDivert64.sys", "LICENSE.txt", "THIRD-PARTY-NOTICES.txt"}

// runtimeFilesList: files of programFilesList that run from the runtime
// folder (see runtimefiles.Stage), never from the program folder.
var runtimeFilesList = []string{"hysteria.exe", "WinDivert.dll", "WinDivert64.sys"}

// MoveToProgramFiles copies HyRoute into Program Files, adds a Start menu
// shortcut, starts the new copy and exits. As after an update, the new
// copy connects again, and the kill switch keeps the internet closed
// until it does.
func (g *GUI) MoveToProgramFiles() error {
	target := moveTarget()
	if strings.EqualFold(filepath.Clean(g.dllDir), filepath.Clean(target)) {
		// Here only when the permissions of the folder or its files let the
		// user's programs change them, or could not be read.
		return fmt.Errorf("HyRoute уже в %s, но права этой папки или файлов в ней позволяют менять их программам без прав администратора (или их не удалось проверить). Оставьте в свойствах папки и HyRoute.exe (вкладка «Безопасность») запись и изменение только администраторам", target)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	// A new folder takes the permissions of Program Files; one that was
	// there before may let users in, and the copy would be no safer.
	if !protectedLocation(target) {
		return fmt.Errorf("в папку %s могут писать программы без прав администратора: удалите её или оставьте в её свойствах запись только администраторам и повторите", target)
	}
	if err := copyProgram(g.dllDir, self, g.runtimeDir, target); err != nil {
		return err
	}
	exe := filepath.Join(target, "HyRoute.exe")
	if err := startMenuShortcut(exe); err != nil {
		g.ctl.Log.Warn("start menu shortcut not created", "err", err)
	}
	args := []string{"--wait-pid", fmt.Sprint(os.Getpid()), "--moved-from", g.dllDir}
	if routingOn(g.ctl.Status()) {
		args = append(args, "--reconnect")
	}
	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("новая копия не запустилась: %w", err)
	}
	g.ctl.Log.Info("moving to Program Files: this copy exits", "to", target)
	// Not the user's Disconnect: the block stays over the exit, and the new
	// copy lets itself through when it connects.
	g.ctl.HoldKillSwitch()
	g.ctl.Disconnect()
	go func() {
		time.Sleep(200 * time.Millisecond)
		g.quit()
	}()
	return nil
}

// copyProgram copies the files of programFilesList from dir into target;
// HyRoute.exe from self, the running file (a repeated download is
// "HyRoute (1).exe", maybe next to an older HyRoute.exe). Only HyRoute.exe
// is needed: hysteria.exe and WinDivert are taken from runtimeDir, where
// their verified copies are (the new copy checks them again, and
// downloads what it lacks), and an update brings its own updater.
func copyProgram(dir, self, runtimeDir, target string) error {
	for _, name := range programFilesList {
		src := filepath.Join(dir, name)
		switch {
		case name == "HyRoute.exe":
			src = self
		case slices.Contains(runtimeFilesList, name):
			src = filepath.Join(runtimeDir, name)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			if name != "HyRoute.exe" {
				continue
			}
			return fmt.Errorf("не удалось прочитать %s: %w", src, err)
		}
		// A new file, not one written over: a new file takes the folder's
		// permissions, one already there keeps its own (maybe open to users).
		dst := filepath.Join(target, name)
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("не удалось заменить %s: %w", dst, err)
		}
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			return fmt.Errorf("не удалось записать %s: %w", dst, err)
		}
	}
	return nil
}

// startMenuShortcut creates "HyRoute" in the Start menu for all users.
func startMenuShortcut(exe string) error {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return err
	}
	return createShortcut(filepath.Join(programs, "HyRoute.lnk"), exe)
}

// createShortcut makes lnk start exe, through the shell's COM object in
// this process. Not through PowerShell: an elevated powershell.exe loads
// modules from folders the user's variables name, and the paths would
// have to be quoted into a script (PowerShell takes ‘ ’ for quotes too).
func createShortcut(lnk, exe string) error {
	return inSTA(func() error {
		unk, err := oleutil.CreateObject("WScript.Shell")
		if err != nil {
			return err
		}
		defer unk.Release()
		shell, err := unk.QueryInterface(ole.IID_IDispatch)
		if err != nil {
			return err
		}
		defer shell.Release()
		v, err := oleutil.CallMethod(shell, "CreateShortcut", lnk)
		if err != nil {
			return err
		}
		sc := v.ToIDispatch()
		if sc == nil {
			return errors.New("no shortcut object")
		}
		defer sc.Release()
		if _, err := oleutil.PutProperty(sc, "TargetPath", exe); err != nil {
			return err
		}
		if _, err := oleutil.PutProperty(sc, "WorkingDirectory", filepath.Dir(exe)); err != nil {
			return err
		}
		_, err = oleutil.CallMethod(sc, "Save")
		return err
	})
}
