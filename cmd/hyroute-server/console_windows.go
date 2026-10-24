package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procSetConsoleTitleW      = kernel32.NewProc("SetConsoleTitleW")
)

// ownConsole: the console window is this process's alone (a double click,
// HyRoute's «Открыть панель»), not a shell's or a service's: it closes
// when the panel exits.
func ownConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

func setConsoleTitle(title string) {
	if p, err := windows.UTF16PtrFromString(title); err == nil {
		procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(p)))
	}
}

// waitEnter keeps the window, and the error above, until Enter.
func waitEnter() {
	fmt.Fprint(os.Stderr, "\nНажмите Enter, чтобы закрыть окно.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
