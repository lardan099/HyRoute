//go:build !windows

package main

// A console window of its own is a Windows thing (console_windows.go).
func ownConsole() bool { return false }

func setConsoleTitle(string) {}

func waitEnter() {}
