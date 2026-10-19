//go:build windows

// hyroute-updater replaces HyRoute's files after HyRoute has exited and
// starts the new version. The plan is written to a journal first, so an
// interrupted update (power loss, kill) is undone on the next HyRoute
// start. The new version reports "healthy" once its window is up and, if
// HyRoute was connected before the update, once it has reconnected with
// the filters in place; otherwise (or if it exits) the old files are
// restored and the old version is started again. HyRoute starts this
// program from the staging directory, never from the program directory it
// replaces.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/update"
)

func main() {
	pid := flag.Int("pid", 0, "HyRoute process to wait for")
	staging := flag.String("staging", "", "verified package directory")
	target := flag.String("target", "", "program directory")
	exe := flag.String("exe", update.MainExe, "HyRoute's executable in the program directory (the user may have renamed it)")
	event := flag.String("event", "", "event the new HyRoute signals when it is up")
	from := flag.String("from", "", "version being replaced")
	reconnect := flag.Bool("reconnect", false, "HyRoute was connected: the new version reconnects before it reports healthy")
	flag.Parse()
	if *pid == 0 || *staging == "" || *target == "" || *event == "" {
		fail("hyroute-updater запускается только из HyRoute")
	}
	logf, _ := os.OpenFile(filepath.Join(filepath.Dir(*staging), "updater.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	log := func(format string, a ...any) {
		if logf != nil {
			fmt.Fprintf(logf, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", a...)
		}
	}
	log("start: pid=%d staging=%s target=%s exe=%s from=%s", *pid, *staging, *target, *exe, *from)
	mainExe := filepath.Join(*target, *exe)
	// to is the version that failed to install, for --update-failed: the
	// staging directory is updates\<version>\files (update.Stage) until
	// the verified manifest names it.
	to := filepath.Base(filepath.Dir(*staging))
	// restartOld starts the previous version again, connected if it was.
	// If it does not start, nothing runs and with the kill switch on the
	// internet stays closed: the user is told.
	restartOld := func(reason string) {
		args := []string{"--update-failed", to, "--update-error", reason}
		if *reconnect {
			args = append(args, "--reconnect")
		}
		if err := exec.Command(mainExe, args...).Start(); err != nil {
			log("start old: %v", err)
			fail("Обновление не установлено (" + reason + "), и прежняя версия HyRoute не запустилась: " + err.Error() +
				". Запустите HyRoute вручную: если был включён kill switch, интернет закрыт, пока HyRoute не подключится.")
		}
	}

	// HyRoute stops routing before it exits, which may take minutes (local
	// proxies wait for their connections). It exits in any case, so the
	// wait has no limit: giving up would leave no HyRoute running.
	if err := waitExit(uint32(*pid)); err != nil {
		log("HyRoute did not exit: %v", err)
		fail("HyRoute не завершился, обновление отменено. Файлы не изменены.")
	}
	sw, err := update.ApplyJournaled(*staging, *target, *exe, core.DefaultDir(update.JournalName), *from, "", *reconnect)
	if err != nil {
		log("apply failed: %v", err)
		restartOld("не удалось заменить файлы: " + err.Error())
		return
	}
	to = sw.To
	log("files replaced: %v added: %v", sw.Replaced, sw.Added)

	name, _ := windows.UTF16PtrFromString(*event)
	ev, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil {
		log("event: %v", err)
		sw.Undo()
		restartOld("внутренняя ошибка обновления")
		return
	}
	defer windows.CloseHandle(ev)
	args := []string{"--update-event", *event, "--updated-from", *from}
	if *reconnect {
		args = append(args, "--reconnect")
	}
	cmd := exec.Command(mainExe, args...)
	if err := cmd.Start(); err != nil {
		log("start new: %v", err)
		sw.Undo()
		restartOld("новая версия не запускается: " + err.Error())
		return
	}
	ph, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		log("open new process: %v", err)
	}
	handles := []windows.Handle{ev}
	if ph != 0 {
		handles = append(handles, ph)
		defer windows.CloseHandle(ph)
	}
	// Up to 3 minutes: the window, then (after --reconnect) the driver and
	// the first Hysteria start.
	r, _ := windows.WaitForMultipleObjects(handles, false, 180*1000)
	if r == windows.WAIT_OBJECT_0 {
		log("new version is up; removing backups")
		sw.Commit()
		return
	}
	log("new version did not report healthy (wait=%d); rolling back", r)
	if ph != 0 {
		windows.TerminateProcess(ph, 1)
		windows.WaitForSingleObject(ph, 10*1000)
	}
	if err := sw.Undo(); err != nil {
		log("undo: %v", err)
		fail("Обновление не удалось, и старые файлы не восстановились полностью: " + err.Error() + ". Переустановите HyRoute.")
	}
	restartOld("новая версия не запустилась, возвращена прежняя")
}

func waitExit(pid uint32) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil // already gone
	}
	defer windows.CloseHandle(h)
	// HyRoute started the updater, so it was created before it: a process
	// created later only took the number of a HyRoute that has exited.
	if startedAfter(h, windows.CurrentProcess()) {
		return nil
	}
	r, err := windows.WaitForSingleObject(h, windows.INFINITE)
	if err != nil {
		return err
	}
	if r != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("wait result %d", r)
	}
	// Give Windows a moment to release the image file.
	time.Sleep(500 * time.Millisecond)
	return nil
}

// startedAfter reports whether process a was created after process b (as
// cmd/hyroute's).
func startedAfter(a, b windows.Handle) bool {
	var ca, cb, x, k, u windows.Filetime
	if windows.GetProcessTimes(a, &ca, &x, &k, &u) != nil || windows.GetProcessTimes(b, &cb, &x, &k, &u) != nil {
		return false
	}
	return ca.Nanoseconds() > cb.Nanoseconds()
}

func fail(msg string) {
	t, _ := windows.UTF16PtrFromString("HyRoute: обновление")
	m, _ := windows.UTF16PtrFromString(msg)
	windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONERROR)
	os.Exit(1)
}
