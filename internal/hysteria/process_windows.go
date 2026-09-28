//go:build windows

package hysteria

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The child is created suspended, put into a KILL_ON_JOB_CLOSE job and only
// then resumed, so it can never outlive HyRoute, even if HyRoute crashes
// between CreateProcess and the job assignment.

var (
	jobOnce sync.Once
	job     windows.Handle
	jobErr  error
)

// killOnCloseJob returns a process-wide job. The handle is intentionally
// never closed: the kernel closes it when HyRoute exits, killing the child.
func killOnCloseJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			jobErr = err
			return
		}
		job = h
	})
	return job, jobErr
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error { return p.cmd.Wait() }
func (p execProcess) Kill() error { return p.cmd.Process.Kill() }

func startProcess(exe string, args, env []string, out io.Writer) (process, error) {
	j, err := killOnCloseJob()
	if err != nil {
		return nil, fmt.Errorf("job object: %w", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	fail := func(err error) (process, error) {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	pid := uint32(cmd.Process.Pid)
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fail(fmt.Errorf("open process: %w", err))
	}
	err = windows.AssignProcessToJobObject(j, ph)
	windows.CloseHandle(ph)
	if err != nil {
		return fail(fmt.Errorf("assign to job: %w", err))
	}
	if err := resumeProcess(pid); err != nil {
		return fail(fmt.Errorf("resume: %w", err))
	}
	return execProcess{cmd}, nil
}

// resumeProcess resumes every thread of a CREATE_SUSPENDED process
// (os/exec does not expose the primary thread handle).
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return err
		}
		_, err = windows.ResumeThread(th)
		windows.CloseHandle(th)
		if err != nil {
			return err
		}
		resumed++
	}
	if resumed == 0 {
		return fmt.Errorf("no threads found for pid %d", pid)
	}
	return nil
}

// writeSecretFile creates the file with a protected DACL (the config holds
// auth and obfs passwords) and returns it still open; the caller closes it
// once Hysteria has read the config. RunDir is in the user's profile, where
// the user's non-elevated programs may delete any file, and Hysteria runs
// with HyRoute's elevated token: until then the handle, shared for reading
// only, keeps the file from being written, deleted or renamed. An elevated
// HyRoute leaves the user out of the DACL (its Hysteria reads the file as
// Administrators); a non-elevated one, whose Hysteria has no more rights
// than the user's other programs, keeps the user in.
func writeSecretFile(path string, data []byte) (release func(), err error) {
	dacl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if !windows.GetCurrentProcessToken().IsElevated() {
		tu, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		dacl += "(A;;FA;;;" + tu.User.Sid.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(dacl)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Hysteria (Go's os.Open) shares read and write, so it can open the
	// file while this handle is held for writing.
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	var n uint32
	if err := windows.WriteFile(h, data, &n, nil); err != nil {
		windows.CloseHandle(h)
		windows.DeleteFile(p)
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
}
