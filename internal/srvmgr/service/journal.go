package service

import (
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Entry is a journal record ready to show: redacted, with Hysteria's own
// level when the line has one.
type Entry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // debug, info, warn, error
	Message string    `json:"message"`
}

var hysteriaLevels = map[string]string{
	"DEBUG": "debug", "INFO": "info", "WARN": "warn", "ERROR": "error", "DPANIC": "error", "PANIC": "error", "FATAL": "error",
}

// MakeEntry redacts a record. Hysteria writes "time<TAB>LEVEL<TAB>message
// <TAB>{fields}"; the time is dropped (the journal has it) and the level
// read from the line.
func MakeEntry(e remote.JournalEntry, r *redact.Redactor) Entry {
	out := Entry{Time: e.Time, Message: e.Message}
	switch {
	case e.Priority <= 3:
		out.Level = "error"
	case e.Priority == 4:
		out.Level = "warn"
	case e.Priority >= 7:
		out.Level = "debug"
	default:
		out.Level = "info"
	}
	if f := strings.SplitN(e.Message, "\t", 3); len(f) == 3 {
		if l, ok := hysteriaLevels[f[1]]; ok {
			out.Level, out.Message = l, strings.ReplaceAll(f[2], "\t", "  ")
		}
	}
	out.Message = r.String(out.Message)
	return out
}
