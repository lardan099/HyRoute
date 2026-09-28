package logx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RotatingFile appends to Path and, past MaxBytes, renames it to Path.1
// (Path.1 to Path.2 …), keeping Keep old files. Writes never fail loudly:
// a log file must not break the program.
type RotatingFile struct {
	Path     string
	MaxBytes int64
	Keep     int
	// Header is written at the top of every new file.
	Header string

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
	// retry: rotation failed (Path is held open elsewhere), not tried
	// again before this time.
	retry time.Time
}

// rotateRetry is how long a file that could not be rotated keeps growing
// before the next attempt.
const rotateRetry = time.Minute

func (r *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return err
	}
	f, err := OpenAppend(r.Path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	if r.size == 0 && r.Header != "" {
		n, _ := io.WriteString(f, r.Header+"\n")
		r.size += int64(n)
	}
	return nil
}

// rotate closes the file and moves Path to Path.1 (Path.1 to Path.2 …).
// It reports false when Path stays where it is: another program holds it
// or one of the copies open (Windows cannot rename it then), and the old
// copies are left as they were instead of being shifted out one by one.
func (r *RotatingFile) rotate() bool {
	r.f.Close()
	r.f = nil
	keep := max(r.Keep, 0)
	if keep == 0 {
		if os.Remove(r.Path) != nil {
			return false
		}
		r.removeCopies(0)
		return true
	}
	aside := r.Path + ".rotating"
	if err := os.Rename(r.Path, aside); err != nil {
		return false
	}
	// Every copy moves up one place (the current file, now aside, to
	// Path.1), the oldest to Path.<keep+1>, which is deleted only once
	// all have moved: a copy that cannot be renamed undoes the moves
	// made so far, so none is lost.
	name := func(i int) string {
		if i == 0 {
			return aside
		}
		return fmt.Sprintf("%s.%d", r.Path, i)
	}
	os.Remove(name(keep + 1))
	for i := keep; i >= 0; i-- {
		if err := os.Rename(name(i), name(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			for j := i + 1; j <= keep; j++ {
				os.Rename(name(j+1), name(j))
			}
			os.Rename(aside, r.Path)
			return false
		}
	}
	r.removeCopies(keep)
	return true
}

// removeCopies deletes the rotated copies numbered past keep: Path.<keep+1>
// shifted out just now and those left from when Keep was larger.
func (r *RotatingFile) removeCopies(keep int) {
	dir, base := filepath.Split(r.Path)
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		n, ok := strings.CutPrefix(e.Name(), base+".")
		if !ok {
			continue
		}
		if i, err := strconv.Atoi(n); err == nil && i > keep && n == strconv.Itoa(i) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// SetLimits changes MaxBytes and Keep of a file that may be in use. The
// copies past a lowered Keep go at once, not at the next rotation.
func (r *RotatingFile) SetLimits(maxBytes int64, keep int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if keep < r.Keep {
		r.removeCopies(max(keep, 0))
	}
	r.MaxBytes, r.Keep = maxBytes, keep
}

func (r *RotatingFile) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		// A writer that got this file just before it was closed (logs
		// cleared or kept in memory only) must not open it again.
		return len(b), nil
	}
	if r.f == nil {
		if err := r.open(); err != nil {
			return len(b), nil
		}
	}
	if r.MaxBytes > 0 && r.size+int64(len(b)) > r.MaxBytes && r.size > 0 && !time.Now().Before(r.retry) {
		if !r.rotate() {
			r.retry = time.Now().Add(rotateRetry)
		}
		if err := r.open(); err != nil {
			return len(b), nil
		}
	}
	n, _ := r.f.Write(b)
	r.size += int64(n)
	return len(b), nil
}

// Close closes the file for good: later writes are dropped.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
	return nil
}

// Files lists Path and its rotated copies that exist.
func (r *RotatingFile) Files() []string {
	var out []string
	matches, _ := filepath.Glob(r.Path + "*")
	for _, m := range matches {
		if m == r.Path || strings.HasPrefix(m, r.Path+".") {
			out = append(out, m)
		}
	}
	return out
}

// Switch forwards writes to W, or drops them when W is nil.
type Switch struct {
	mu sync.RWMutex
	W  io.Writer
}

func (s *Switch) Set(w io.Writer) {
	s.mu.Lock()
	s.W = w
	s.mu.Unlock()
}

func (s *Switch) Write(b []byte) (int, error) {
	s.mu.RLock()
	w := s.W
	s.mu.RUnlock()
	if w == nil {
		return len(b), nil
	}
	return w.Write(b)
}
