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
// the string directly, so there is no file to tamper with.
func registerTask(name, xml string) error {
	return withTaskFolder(func(folder *ole.IDispatch) error {
		// ITaskFolder::RegisterTask(path, xmlText, flags, userId,
		// password, logonType, sddl). The principal (user, logon type) is
		// in the XML, so userId/password/sddl are left empty;
		// TASK_CREATE_OR_UPDATE replaces an existing task like schtasks /F
		// did.
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
	})
}

// taskDefinition returns the XML definition of the task named name
// (ErrNoTask: there is none). COM hands it over as UTF-16, so a path
// outside the console code page (schtasks /Query /XML prints in it) comes
// back intact.
func taskDefinition(name string) (string, error) {
	var def string
	err := withTaskFolder(func(folder *ole.IDispatch) error {
		tv, err := oleutil.CallMethod(folder, "GetTask", name)
		if taskNotFound(err) {
			return ErrNoTask
		}
		if err != nil {
			return err
		}
		t := tv.ToIDispatch()
		if t == nil {
			return errors.New("GetTask не вернул задачу")
		}
		defer t.Release()
		xv, err := oleutil.GetProperty(t, "Xml")
		if err != nil {
			return err
		}
		defer xv.Clear()
		def = xv.ToString()
		return nil
	})
	if err != nil {
		// Only a missing task is ErrNoTask: on any other failure the task
		// may exist, so Disable still tries to delete it.
		if !errors.Is(err, ErrNoTask) {
			err = fmt.Errorf("планировщик задач: %w", err)
		}
		return "", err
	}
	return def, nil
}

// taskNotFound reports whether err from ITaskFolder::GetTask means there
// is no such task: HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND or
// ERROR_PATH_NOT_FOUND), returned by Invoke itself or, with
// DISP_E_EXCEPTION, in its EXCEPINFO.
func taskNotFound(err error) bool {
	var oe *ole.OleError
	if !errors.As(err, &oe) {
		return false
	}
	code := uint32(oe.Code())
	if ei, ok := oe.SubError().(ole.EXCEPINFO); ok && code == dispEException {
		code = ei.SCODE()
	}
	return code == hresultFileNotFound || code == hresultPathNotFound
}

const (
	dispEException      = 0x80020009
	hresultFileNotFound = 0x80070002
	hresultPathNotFound = 0x80070003
)

// withTaskFolder calls f with the Task Scheduler's root folder. COM runs
// on a dedicated OS thread with a single-threaded apartment, as in
// shellopen.
func withTaskFolder(f func(folder *ole.IDispatch) error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("планировщик задач (COM): %v", r)
			}
		}()
		done <- withTaskFolderSTA(f)
	}()
	return <-done
}

func withTaskFolderSTA(f func(folder *ole.IDispatch) error) error {
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
	return f(folder)
}
