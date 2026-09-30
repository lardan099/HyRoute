package remote

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// JournalEntry is one journald record of a unit.
type JournalEntry struct {
	Time     time.Time
	Priority int // syslog priority: 3 error, 4 warning, 6 info, 7 debug
	Message  string
}

// journalFields are the fields asked for; the cursor and timestamps come
// with every record anyway.
const journalFields = "--output-fields=MESSAGE,PRIORITY"

func journalArgs(unit string, lines int, follow bool) ([]string, error) {
	if err := CheckUnitName(unit); err != nil {
		return nil, err
	}
	if lines < 0 || lines > 5000 {
		return nil, errors.New("bad line count")
	}
	args := []string{"journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager", "-o", "json", journalFields}
	if follow {
		args = append(args, "-f")
	}
	return args, nil
}

// JournalEntries is the last records of a unit. The caller redacts the
// messages before showing them.
func JournalEntries(ctx context.Context, ex Executor, unit string, lines int, sudo bool) ([]JournalEntry, error) {
	args, err := journalArgs(unit, lines, false)
	if err != nil {
		return nil, err
	}
	out, err := run(ctx, ex, "journalctl", Cmd{Args: args, Sudo: sudo})
	if err != nil {
		return nil, err
	}
	var es []JournalEntry
	for _, l := range strings.Split(out, "\n") {
		if e, ok := ParseJournalJSON(l); ok {
			es = append(es, e)
		}
	}
	return es, nil
}

// JournalFollow sends the last records of a unit and then new ones as
// they come, until ctx ends (that is not an error).
func JournalFollow(ctx context.Context, ex Executor, unit string, lines int, sudo bool, fn func(JournalEntry)) error {
	args, err := journalArgs(unit, lines, true)
	if err != nil {
		return err
	}
	return ex.Stream(ctx, Cmd{Args: args, Sudo: sudo}, func(l string) {
		if e, ok := ParseJournalJSON(l); ok {
			fn(e)
		}
	})
}

// ParseJournalJSON reads one line of journalctl -o json. A MESSAGE that
// is not UTF-8 comes as an array of bytes.
func ParseJournalJSON(line string) (JournalEntry, bool) {
	var r struct {
		Message  json.RawMessage `json:"MESSAGE"`
		Priority string          `json:"PRIORITY"`
		Realtime string          `json:"__REALTIME_TIMESTAMP"`
	}
	if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &r) != nil || len(r.Message) == 0 {
		return JournalEntry{}, false
	}
	var e JournalEntry
	var s string
	var bs []byte
	switch {
	case json.Unmarshal(r.Message, &s) == nil:
		e.Message = s
	case json.Unmarshal(r.Message, &bs) == nil:
		e.Message = strings.ToValidUTF8(string(bs), "�")
	default:
		return JournalEntry{}, false
	}
	e.Priority = 6
	if p, err := strconv.Atoi(r.Priority); err == nil {
		e.Priority = p
	}
	if us, err := strconv.ParseInt(r.Realtime, 10, 64); err == nil {
		e.Time = time.UnixMicro(us).UTC()
	}
	return e, true
}
