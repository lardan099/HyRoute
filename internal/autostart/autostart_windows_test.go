//go:build windows

package autostart

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

func TestXMLEscapesPath(t *testing.T) {
	x := taskXML(startTask, `C:\Program Files\R&D <x>\HyRoute.exe`, "S-1-5-21-1")
	if !strings.Contains(x, `"C:\Program Files\R&amp;D &lt;x&gt;\HyRoute.exe"`) || !strings.Contains(x, "<RunLevel>HighestAvailable</RunLevel>") ||
		!strings.Contains(x, "<Priority>4</Priority>") {
		t.Fatal(x)
	}
	// decode reads schtasks output (errors), which may be UTF-16 with a BOM.
	if s := decode([]byte{0xff, 0xfe, 'a', 0, 'b', 0}); s != "ab" {
		t.Fatalf("decode UTF-16: %q", s)
	}
	if s := decode([]byte("ascii")); s != "ascii" {
		t.Fatalf("decode bytes: %q", s)
	}
}

// TestParseTask reads back the definition of a task made from taskXML, as
// Task Scheduler returns it (taskDefinition), a path outside ASCII too.
func TestParseTask(t *testing.T) {
	for _, exe := range []string{`C:\Program Files\HyRoute\HyRoute.exe`, `C:\Program Files\Утилиты\HyRoute\HyRoute.exe`} {
		got, err := parseTask("HyRoute", taskXML(startTask, exe, "S-1-5-21-1-2-3-1001"))
		if err != nil || got.command != exe || got.user != "S-1-5-21-1-2-3-1001" {
			t.Fatalf("%+v %v", got, err)
		}
	}
	if _, err := parseTask("HyRoute", "not xml"); err == nil {
		t.Fatal("garbage parsed")
	}
}

// TestCheckTaskXML: the kill switch check starts HyRoute like the
// autostart task (the user's own, elevated, normal priority) but with
// CheckFlag, under a name of its own.
// TestTaskNotFound: only a missing task reads as no task; access denied
// or a broken COM call must not make Disable skip deleting it.
func TestTaskNotFound(t *testing.T) {
	exc := func(scode uint32) error {
		var ei ole.EXCEPINFO
		f, _ := reflect.TypeOf(ei).FieldByName("scode")
		*(*uint32)(unsafe.Add(unsafe.Pointer(&ei), f.Offset)) = scode
		return ole.NewErrorWithSubError(dispEException, "", ei)
	}
	for err, want := range map[error]bool{
		ole.NewError(hresultFileNotFound):             true,
		ole.NewError(hresultPathNotFound):             true,
		exc(hresultFileNotFound):                      true,
		fmt.Errorf("x: %w", exc(hresultPathNotFound)): true,
		ole.NewError(0x80070005):                      false, // access denied
		exc(0x80070005):                               false,
		ole.NewError(dispEException):                  false,
		errors.New("0x80070002"):                      false,
		nil:                                           false,
	} {
		if got := taskNotFound(err); got != want {
			t.Errorf("%v: %v, want %v", err, got, want)
		}
	}
}

func TestCheckTaskXML(t *testing.T) {
	const exe, sid = `C:\Program Files\HyRoute\HyRoute.exe`, "S-1-5-21-1-2-3-1001"
	x := taskXML(checkTask, exe, sid)
	for _, want := range []string{
		"<Arguments>--killswitch-check</Arguments>",
		"<UserId>" + sid + "</UserId>\n      <Delay>PT3S</Delay>",
		"<RunLevel>HighestAvailable</RunLevel>",
		"<Priority>4</Priority>",
		"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
		"<Description>Shows HyRoute when you sign in while its kill switch still blocks the internet",
		`<WorkingDirectory>C:\Program Files\HyRoute</WorkingDirectory>`,
	} {
		if !strings.Contains(x, want) {
			t.Fatalf("no %q in\n%s", want, x)
		}
	}
	if strings.Contains(x, Flag) {
		t.Fatal("the check starts HyRoute as the autostart task does")
	}
	if a := taskXML(startTask, exe, sid); !strings.Contains(a, "<Arguments>--autostart</Arguments>") || strings.Contains(a, CheckFlag) {
		t.Fatal(a)
	}
	got, err := parseTask(CheckTaskName, x)
	if err != nil || got.command != exe || got.user != sid {
		t.Fatalf("%+v %v", got, err)
	}
	// Neither the autostart task nor the one of earlier versions.
	if n := checkTask.taskName(sid); n != "HyRoute kill switch ("+sid+")" || n == taskName(sid) || n == TaskName {
		t.Fatal(n)
	}
}

// TestTaskPerUser: every user has a task of their own, and only the
// user's own task of an earlier version counts as theirs.
func TestTaskPerUser(t *testing.T) {
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	if n := taskName(sid.String()); n == TaskName || !strings.Contains(n, sid.String()) {
		t.Fatal(n)
	}
	if !isUser(sid.String(), sid) || isUser("S-1-5-18", sid) || isUser("", sid) {
		t.Fatal("by SID")
	}
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if !isUser(domain+`\`+account, sid) {
			t.Fatalf(`by name %s\%s`, domain, account)
		}
	}
}

// TestRaisePriority: a process started at Task Scheduler's background
// priority (below-normal class, low I/O and memory priority) is lifted to
// normal; one already at normal is left as it is.
func TestRaisePriority(t *testing.T) {
	proc := windows.CurrentProcess()
	get := func(class int32) uint32 {
		var v, n uint32
		if err := windows.NtQueryInformationProcess(proc, class, unsafe.Pointer(&v), 4, &n); err != nil {
			t.Fatal(err)
		}
		return v
	}
	set := func(class int32, v uint32) {
		if err := windows.NtSetInformationProcess(proc, class, unsafe.Pointer(&v), 4); err != nil {
			t.Fatal(err)
		}
	}
	prevClass, err := windows.GetPriorityClass(proc)
	if err != nil {
		t.Fatal(err)
	}
	prevIO, prevPage := get(windows.ProcessIoPriority), get(windows.ProcessPagePriority)
	t.Cleanup(func() {
		windows.SetPriorityClass(proc, prevClass)
		set(windows.ProcessIoPriority, prevIO)
		set(windows.ProcessPagePriority, prevPage)
	})
	if err := windows.SetPriorityClass(proc, windows.BELOW_NORMAL_PRIORITY_CLASS); err != nil {
		t.Fatal(err)
	}
	set(windows.ProcessIoPriority, 1)   // low
	set(windows.ProcessPagePriority, 2) // low
	raisePriority()
	if c, _ := windows.GetPriorityClass(proc); c != windows.NORMAL_PRIORITY_CLASS {
		t.Fatalf("class %#x", c)
	}
	if io, page := get(windows.ProcessIoPriority), get(windows.ProcessPagePriority); io != 2 || page != 5 {
		t.Fatalf("I/O %d, memory %d", io, page)
	}
	raisePriority()
	if c, _ := windows.GetPriorityClass(proc); c != windows.NORMAL_PRIORITY_CLASS {
		t.Fatalf("class %#x after a second call", c)
	}
}

// TestTask creates the real task (CI runners are elevated).
func TestTask(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	if _, err := Command(); !errors.Is(err, ErrNoTask) {
		t.Skip("a HyRoute task already exists on this machine")
	}
	exe, _ := os.Executable()
	if err := Enable(exe); err != nil {
		t.Fatal(err)
	}
	defer Disable()
	got, err := Command()
	if err != nil || !strings.EqualFold(got, exe) {
		t.Fatalf("%q %v, want %q", got, err, exe)
	}
	if err := Enable(exe); err != nil { // replacing works
		t.Fatal(err)
	}
	if err := Disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := Command(); !errors.Is(err, ErrNoTask) {
		t.Fatalf("task still there: %v", err)
	}
	if err := Disable(); err != nil {
		t.Fatal("disabling twice:", err)
	}
	// The user's task of an earlier version (shared name) moves to the
	// user's own task when it starts this program.
	if _, err := queryTask(TaskName); errors.Is(err, ErrNoTask) {
		sid, err := userSID()
		if err != nil {
			t.Fatal(err)
		}
		if err := registerTask(TaskName, taskXML(startTask, exe, sid.String())); err != nil {
			t.Fatal(err)
		}
		if err := migrateLegacy(exe); err != nil {
			run("/Delete", "/TN", TaskName, "/F")
			t.Fatal(err)
		}
		if _, err := queryTask(TaskName); !errors.Is(err, ErrNoTask) {
			run("/Delete", "/TN", TaskName, "/F")
			t.Fatal("task of an earlier version left")
		}
		if got, err := Command(); err != nil || !strings.EqualFold(got, exe) {
			t.Fatalf("after migration: %q %v", got, err)
		}
	}
}

// TestCheckTask creates the real kill switch check (CI runners are
// elevated).
func TestCheckTask(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	if _, err := CheckCommand(); !errors.Is(err, ErrNoTask) {
		t.Skip("a kill switch check already exists on this machine")
	}
	auto, autoErr := Command()
	exe, _ := os.Executable()
	if err := EnableCheck(exe); err != nil {
		t.Fatal(err)
	}
	defer DisableCheck()
	if got, err := CheckCommand(); err != nil || !strings.EqualFold(got, exe) {
		t.Fatalf("%q %v, want %q", got, err, exe)
	}
	if got, err := Command(); got != auto || (err == nil) != (autoErr == nil) {
		t.Fatalf("the autostart task changed: %q %v", got, err)
	}
	if err := EnableCheck(exe); err != nil { // replacing works
		t.Fatal(err)
	}
	if err := DisableCheck(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCommand(); !errors.Is(err, ErrNoTask) {
		t.Fatalf("task still there: %v", err)
	}
	if err := DisableCheck(); err != nil {
		t.Fatal("disabling twice:", err)
	}
}
