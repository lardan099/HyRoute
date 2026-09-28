//go:build windows

// Package autostart starts HyRoute when the user signs in to Windows.
// HyRoute needs administrator rights, and an entry under Run would ask
// for them (UAC) at every sign-in, so a Task Scheduler task starts it
// with the highest privileges of the user instead. The task runs the
// exe from its path: callers allow it only for a folder ordinary
// programs cannot write to.
//
// A second task, the kill switch check, starts HyRoute at sign-in only to
// show a kill switch block left from before (CheckFlag); without one
// HyRoute exits at once.
package autostart

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TaskName is what the user sees in Task Scheduler. Every user of the
// computer has a task of their own, TaskName followed by the user's SID
// (taskName). Earlier versions made one task named TaskName for whoever
// turned autostart on last; it still counts for its user and is replaced
// by the per-user task on the next change.
const TaskName = "HyRoute"

// taskName is the task of the user with sid.
func taskName(sid string) string { return startTask.taskName(sid) }

// Flag is passed to HyRoute when the task starts it.
const Flag = "--autostart"

// CheckTaskName and CheckFlag are those of the kill switch check: the
// user's task is CheckTaskName followed by the user's SID.
const (
	CheckTaskName = "HyRoute kill switch"
	CheckFlag     = "--killswitch-check"
)

// kind is one of HyRoute's sign-in tasks.
type kind struct {
	name        string // the task's name without the user's SID
	args        string
	description string
}

var (
	startTask = kind{TaskName, Flag, "Starts HyRoute when you sign in (HyRoute: Settings, Startup)."}
	checkTask = kind{CheckTaskName, CheckFlag,
		"Shows HyRoute when you sign in while its kill switch still blocks the internet; otherwise HyRoute exits at once (HyRoute: Settings, Kill switch)."}
)

// taskName is the task of kind k of the user with sid. cmd/hyroutectl
// (taskName, for "hyroutectl start") names the start task the same way.
func (k kind) taskName(sid string) string { return k.name + " (" + sid + ")" }

// AtLogon is called at startup when the sign-in task started HyRoute
// (Flag), before the packet engine and hysteria.exe start; exe is this
// program. A task registered by an earlier version starts it with Task
// Scheduler's background priority (see raisePriority) and is shared by
// all users of the computer (see TaskName): AtLogon lifts the priority and,
// in the background, moves such a task of the user's to the user's own one.
func AtLogon(exe string) {
	raisePriority()
	go migrateLegacy(exe)
}

// raisePriority lifts this process to normal CPU, I/O and memory priority
// where it runs lower. New tasks ask for normal priority (taskXML,
// Priority 4), but Task Scheduler's default (7), which earlier versions
// used, is the below-normal class with lowered I/O and memory priority; a
// process started that way would run the packet loop, through which all
// of the machine's traffic passes, below other work and could stall its
// watchdog. Children spawned later (hysteria.exe) start from the raised
// priority.
func raisePriority() {
	proc := windows.CurrentProcess()
	if c, err := windows.GetPriorityClass(proc); err == nil &&
		(c == windows.BELOW_NORMAL_PRIORITY_CLASS || c == windows.IDLE_PRIORITY_CLASS) {
		windows.SetPriorityClass(proc, windows.NORMAL_PRIORITY_CLASS)
	}
	const (
		ioPriorityNormal     = 2 // IO_PRIORITY_HINT IoPriorityNormal
		memoryPriorityNormal = 5 // MEMORY_PRIORITY_NORMAL
	)
	for _, p := range []struct {
		class  int32
		normal uint32
	}{{windows.ProcessIoPriority, ioPriorityNormal}, {windows.ProcessPagePriority, memoryPriorityNormal}} {
		var v, n uint32
		if windows.NtQueryInformationProcess(proc, p.class, unsafe.Pointer(&v), 4, &n) == nil && v < p.normal {
			v = p.normal
			windows.NtSetInformationProcess(proc, p.class, unsafe.Pointer(&v), 4)
		}
	}
}

// migrateLegacy replaces the user's task of an earlier version with the
// user's own task when it starts exe: the same program at the same path,
// so nothing the user once allowed changes (a task for another copy is
// left for the user to decide in Settings).
func migrateLegacy(exe string) error {
	sid, err := userSID()
	if err != nil {
		return err
	}
	t, err := queryTask(TaskName)
	if err != nil || !isUser(t.user, sid) || !strings.EqualFold(filepath.Clean(t.command), filepath.Clean(exe)) {
		return nil
	}
	return Enable(exe)
}

const createNoWindow = 0x08000000

func schtasks(args ...string) ([]byte, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(filepath.Join(sys, "schtasks.exe"), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.CombinedOutput()
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// taskXML is the definition of the task of kind k of the user sid that
// starts exe. Priority 4 is the normal priority class: Task Scheduler's
// default (7) is below normal with low I/O priority, and all the traffic
// HyRoute routes goes through its packet loop.
func taskXML(k kind, exe, sid string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>` + xmlEscape(k.description) + `</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + sid + `</UserId>
      <Delay>PT3S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + sid + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"` + xmlEscape(exe) + `"</Command>
      <Arguments>` + k.args + `</Arguments>
      <WorkingDirectory>` + xmlEscape(filepath.Dir(exe)) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
}

// Enable creates (or replaces) the user's task that starts exe at sign-in.
func Enable(exe string) error {
	sid, err := userSID()
	if err != nil {
		return err
	}
	// The definition is handed to the Task Scheduler in memory, never
	// through a file: a file in a shared folder could be swapped by
	// another program of the user between being written and being read,
	// turning the sign-in task into a command of its own that runs with
	// administrator rights (see registerTask).
	if err := registerTask(taskName(sid.String()), taskXML(startTask, exe, sid.String())); err != nil {
		return err
	}
	if err := deleteLegacy(sid); err != nil {
		// The user's task is in place and works; the old one only starts
		// a second copy, which hands over to the first and exits.
		return fmt.Errorf("автозапуск включён, но задачу прежней версии «%s» удалить не удалось (удалите её в Планировщике заданий): %w", TaskName, err)
	}
	return nil
}

// Disable removes the user's task (no task is not an error).
func Disable() error {
	sid, err := userSID()
	if err != nil {
		return err
	}
	name := taskName(sid.String())
	if _, err := queryTask(name); !errors.Is(err, ErrNoTask) {
		if err := run("/Delete", "/TN", name, "/F"); err != nil {
			return err
		}
	}
	return deleteLegacy(sid)
}

// EnableCheck creates (or replaces) the user's kill switch check: a task
// that starts exe with CheckFlag at sign-in. Like the autostart task it
// runs with administrator rights, so callers allow it only for a folder
// ordinary programs cannot write to.
func EnableCheck(exe string) error {
	sid, err := userSID()
	if err != nil {
		return err
	}
	return registerTask(checkTask.taskName(sid.String()), taskXML(checkTask, exe, sid.String()))
}

// DisableCheck removes the user's kill switch check (no task is not an
// error).
func DisableCheck() error {
	sid, err := userSID()
	if err != nil {
		return err
	}
	name := checkTask.taskName(sid.String())
	if _, err := queryTask(name); errors.Is(err, ErrNoTask) {
		return nil
	}
	return run("/Delete", "/TN", name, "/F")
}

// CheckCommand returns the program the user's kill switch check starts
// (ErrNoTask: there is none).
func CheckCommand() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	t, err := queryTask(checkTask.taskName(sid.String()))
	if err != nil {
		return "", err
	}
	return t.command, nil
}

// deleteLegacy removes the task of an earlier version if it is the user's
// (another user's one is left alone).
func deleteLegacy(sid *windows.SID) error {
	if t, err := queryTask(TaskName); err == nil && isUser(t.user, sid) {
		return run("/Delete", "/TN", TaskName, "/F")
	}
	return nil
}

func run(args ...string) error {
	if out, err := schtasks(args...); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(decode(out)))
	}
	return nil
}

// ErrNoTask: autostart is off (or there is no kill switch check).
var ErrNoTask = errors.New("no autostart task")

// Command returns the program the user's task starts.
func Command() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	t, err := queryTask(taskName(sid.String()))
	if errors.Is(err, ErrNoTask) {
		// An earlier version's task counts only if it is the user's.
		t, err = queryTask(TaskName)
		if err == nil && !isUser(t.user, sid) {
			err = ErrNoTask
		}
	}
	if err != nil {
		return "", err
	}
	return t.command, nil
}

func userSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}

// task is what HyRoute reads back from a registered task.
type task struct {
	command string
	user    string // the principal: a SID or an account name
}

// queryTask reads the task named name through COM (taskDefinition), not
// schtasks /Query /XML: that prints in the console code page, and a path
// outside ASCII would not come back as valid XML.
func queryTask(name string) (task, error) {
	def, err := taskDefinition(name)
	if err != nil {
		return task{}, err
	}
	return parseTask(name, def)
}

func parseTask(name, s string) (task, error) {
	var t struct {
		Principals struct {
			Principal []struct {
				UserID string `xml:"UserId"`
			} `xml:"Principal"`
		} `xml:"Principals"`
		Actions struct {
			Exec []struct {
				Command string `xml:"Command"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	// The XML declares UTF-16 but arrives as a Go string; the declaration
	// is dropped before parsing.
	if i := strings.Index(s, "?>"); i >= 0 && strings.HasPrefix(strings.TrimSpace(s), "<?xml") {
		s = s[i+2:]
	}
	if err := xml.Unmarshal([]byte(s), &t); err != nil || len(t.Actions.Exec) == 0 {
		return task{}, fmt.Errorf("задача %s не разобрана: %v", name, err)
	}
	out := task{command: strings.Trim(t.Actions.Exec[0].Command, `" `)}
	if len(t.Principals.Principal) > 0 {
		out.user = strings.TrimSpace(t.Principals.Principal[0].UserID)
	}
	return out, nil
}

// isUser reports whether a task's UserId (a SID, or an account name as
// Task Scheduler may show it) is the account sid.
func isUser(id string, sid *windows.SID) bool {
	if id == "" {
		return false
	}
	if s, err := windows.StringToSid(id); err == nil {
		return s.Equals(sid)
	}
	if s, _, _, err := windows.LookupSID("", id); err == nil {
		return s.Equals(sid)
	}
	return false
}

// decode turns schtasks output into a string (it may be UTF-16).
func decode(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}
