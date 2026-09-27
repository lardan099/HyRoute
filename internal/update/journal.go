package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The journal makes a file swap recoverable: the plan (which files get
// replaced, which get added) is written and flushed before the first file
// is touched and removed only after the new version reported healthy (or
// the swap was undone). If the updater dies in between (power loss, kill),
// the next HyRoute start finds the journal and restores the old files, so
// a half-applied mix of two versions never runs.

// JournalName is the journal's file name in %ProgramData%\HyRoute.
const JournalName = "update-journal.json"

// Journal is the on-disk record of an unfinished swap.
type Journal struct {
	Target string `json:"target"`
	// Exe is HyRoute's executable in Target: MainExe unless the user
	// renamed it (older updaters leave it empty).
	Exe        string    `json:"exe,omitempty"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Replaced   []string  `json:"replaced"` // have (or will have) <name>.old
	Added      []string  `json:"added"`
	UpdaterPID int       `json:"updaterPID"`
	Started    time.Time `json:"started"`
}

func writeJournal(path string, j *Journal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadJournal returns the unfinished swap recorded at path, or nil.
func ReadJournal(path string) (*Journal, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("журнал обновления повреждён: %w", err)
	}
	if j.Target == "" || !filepath.IsAbs(j.Target) {
		return nil, errors.New("журнал обновления без папки программы")
	}
	// Recovery runs elevated: the journal may name files in Target only.
	for _, n := range append(append([]string{j.ExeName()}, j.Replaced...), j.Added...) {
		if !plainName(n) {
			return nil, fmt.Errorf("журнал обновления повреждён: недопустимое имя %q", n)
		}
	}
	return &j, nil
}

// ExeName is the executable to start after a recovery.
func (j *Journal) ExeName() string {
	if j.Exe == "" {
		return MainExe
	}
	return j.Exe
}

// For reports whether the journal is about the program in dir.
func (j *Journal) For(dir string) bool {
	return strings.EqualFold(filepath.Clean(j.Target), filepath.Clean(dir))
}

// plainName is a file name without any directory part.
func plainName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, `\/:`)
}

// ApplyJournaled is Apply with a journal at journalPath: the plan is on
// disk before any file changes. exe is the name HyRoute's executable has
// in target ("" = MainExe): the package's MainExe replaces that file, so
// a renamed copy is updated in place.
func ApplyJournaled(staging, target, exe, journalPath, from, to string) (*Swap, error) {
	m, err := Verify(staging)
	if err != nil {
		return nil, err
	}
	if to == "" {
		to = m.Version
	}
	if exe == "" {
		exe = MainExe
	}
	if !plainName(exe) {
		return nil, fmt.Errorf("недопустимое имя программы %q", exe)
	}
	for name := range m.Files {
		if name != MainExe && strings.EqualFold(name, exe) {
			return nil, fmt.Errorf("программа названа как файл пакета %s", name)
		}
	}
	j := &Journal{Target: target, Exe: exe, From: from, To: to, UpdaterPID: os.Getpid(), Started: time.Now()}
	type step struct{ src, dst string }
	var todo []step
	for name, sum := range m.Files {
		dstName := name
		if name == MainExe {
			dstName = exe
		}
		dst := filepath.Join(target, dstName)
		if cur, err := FileSHA256(dst); err == nil && strings.EqualFold(cur, sum) {
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			j.Replaced = append(j.Replaced, dstName)
		} else {
			j.Added = append(j.Added, dstName)
		}
		todo = append(todo, step{name, dstName})
	}
	if err := writeJournal(journalPath, j); err != nil {
		return nil, fmt.Errorf("журнал обновления: %w", err)
	}
	sw := &Swap{Target: target, journal: journalPath}
	for _, s := range todo {
		if err := sw.put(filepath.Join(staging, s.src), filepath.Join(target, s.dst), s.dst); err != nil {
			sw.Undo()
			return nil, fmt.Errorf("%s: %w", s.dst, err)
		}
	}
	return sw, nil
}

// Recover undoes the swap recorded in the journal and removes it.
func Recover(journalPath string) (*Journal, error) {
	j, err := ReadJournal(journalPath)
	if err != nil || j == nil {
		return j, err
	}
	return j, j.Undo(journalPath)
}

// Undo undoes the swap j records (read from journalPath) and removes the
// journal.
func (j *Journal) Undo(journalPath string) error {
	sw := &Swap{Target: j.Target, journal: journalPath}
	// Only what was actually done is undone: a planned replacement
	// without .old was not reached; a planned addition may not exist yet.
	for _, n := range j.Replaced {
		if _, err := os.Stat(filepath.Join(j.Target, n+".old")); err == nil {
			sw.Replaced = append(sw.Replaced, n)
		}
		os.Remove(filepath.Join(j.Target, n+".new"))
	}
	for _, n := range j.Added {
		sw.Added = append(sw.Added, n)
		os.Remove(filepath.Join(j.Target, n+".new"))
	}
	return sw.Undo()
}

// removeOrSetAside deletes a file; a running executable cannot be deleted
// on Windows but can be renamed, so it is moved aside as <name>.bad
// (CleanAside removes those later).
func removeOrSetAside(p string) error {
	err := os.Remove(p)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	aside := fmt.Sprintf("%s.%d.bad", p, time.Now().UnixNano())
	if rerr := os.Rename(p, aside); rerr != nil {
		return err
	}
	return nil
}

// CleanAside removes files set aside by an undo in dir.
func CleanAside(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".bad") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
