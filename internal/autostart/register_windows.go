//go:build windows

package autostart

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// registerTask registers (or updates) the task named name from the XML
// definition xml, passed to the Task Scheduler in memory. schtasks reads
// its /XML definition from a file, which another program of the user
// could swap between being written and being read; the COM service takes
// the string directly, so there is no file to tamper with. COM runs on a
// dedicated OS thread with a single-threaded apartment, as in shellopen.
func registerTask(name, xml string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("планировщик задач (COM): %v", r)
			}
		}()
		done <- registerTaskSTA(name, xml)
	}()
	return <-done
}

func registerTaskSTA(name, xml string) error {
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		var oe *ole.OleError
		// S_FALSE: this thread already had COM initialized.
		if !errors.As(err, &oe) || oe.Code() != 1 {
			return err
		}
	}
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return err
	}
	defer unk.Release()
	svc, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer svc.Release()
	if _, err := oleutil.CallMethod(svc, "Connect"); err != nil {
		return err
	}
	fv, err := oleutil.CallMethod(svc, "GetFolder", `\`)
	if err != nil {
		return err
	}
	folder := fv.ToIDispatch()
	if folder == nil {
		return errors.New("планировщик задач: нет корневой папки")
	}
	defer folder.Release()

	// ITaskFolder::RegisterTask(path, xmlText, flags, userId, password,
	// logonType, sddl). The principal (user, logon type) is in the XML, so
	// userId/password/sddl are left empty; TASK_CREATE_OR_UPDATE replaces
	// an existing task like schtasks /F did.
	const (
		taskCreateOrUpdate        = 6
		taskLogonInteractiveToken = 3
	)
	rt, err := oleutil.CallMethod(folder, "RegisterTask", name, xml, int32(taskCreateOrUpdate),
		nil, nil, int32(taskLogonInteractiveToken), nil)
	if err != nil {
		return fmt.Errorf("планировщик задач: %w", err)
	}
	if d := rt.ToIDispatch(); d != nil {
		d.Release()
	}
	return nil
}
