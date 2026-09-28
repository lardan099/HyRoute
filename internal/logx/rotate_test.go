package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	r := &RotatingFile{Path: filepath.Join(dir, "a.log"), MaxBytes: 100, Keep: 2, Header: "# a"}
	line := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 12; i++ {
		r.Write([]byte(line))
	}
	r.Close()
	files := r.Files()
	if len(files) != 3 {
		t.Fatalf("%v", files)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if len(b) > 100 || !strings.HasPrefix(string(b), "# a\n") {
			t.Fatalf("%s: %d bytes %q", f, len(b), b[:10])
		}
	}
	if _, err := os.Stat(r.Path + ".3"); err == nil {
		t.Fatal("kept too many")
	}
}

// TestRotationAfterKeepLowered: copies numbered past a Keep that was
// lowered (left by an earlier run) go at the next rotation, not only the
// one shifted out. Other files sharing the name's prefix stay.
func TestRotationAfterKeepLowered(t *testing.T) {
	dir := t.TempDir()
	r := &RotatingFile{Path: filepath.Join(dir, "a.log"), MaxBytes: 100, Keep: 1}
	for i := 1; i <= 5; i++ {
		os.WriteFile(fmt.Sprintf("%s.%d", r.Path, i), []byte("old"), 0o600)
	}
	others := []string{r.Path + ".rotating.x", r.Path + ".07", filepath.Join(dir, "b.log.9")}
	for _, o := range others {
		os.WriteFile(o, []byte("other"), 0o600)
	}
	os.WriteFile(r.Path, []byte(strings.Repeat("c", 90)), 0o600)
	r.Write([]byte(strings.Repeat("x", 29) + "\n"))
	r.Close()
	for i := 2; i <= 6; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", r.Path, i)); err == nil {
			t.Fatalf(".%d kept with Keep 1", i)
		}
	}
	if b, _ := os.ReadFile(r.Path + ".1"); string(b) != strings.Repeat("c", 90) {
		t.Fatalf(".1 = %q", b)
	}
	for _, o := range others {
		if _, err := os.Stat(o); err != nil {
			t.Fatalf("%s: %v", o, err)
		}
	}
}

// TestSetLimitsLowersKeep: lowering Keep deletes the surplus copies at
// once; raising it deletes nothing.
func TestSetLimitsLowersKeep(t *testing.T) {
	dir := t.TempDir()
	r := &RotatingFile{Path: filepath.Join(dir, "a.log"), MaxBytes: 100, Keep: 5}
	for i := 1; i <= 5; i++ {
		os.WriteFile(fmt.Sprintf("%s.%d", r.Path, i), []byte("old"), 0o600)
	}
	count := func() int { return len(r.Files()) }
	r.SetLimits(1000, 7)
	if n := count(); n != 5 {
		t.Fatalf("raised Keep: %d files", n)
	}
	r.SetLimits(1000, 2)
	if n := count(); n != 2 {
		t.Fatalf("Keep 2: %d files %v", n, r.Files())
	}
	r.SetLimits(1000, 0)
	if n := count(); n != 0 {
		t.Fatalf("Keep 0: %v", r.Files())
	}
}

func TestRotatingFileClosedDropsWrites(t *testing.T) {
	dir := t.TempDir()
	r := &RotatingFile{Path: filepath.Join(dir, "a.log")}
	r.Write([]byte("one\n"))
	r.Close()
	os.Remove(r.Path)
	r.Write([]byte("late\n"))
	if _, err := os.Stat(r.Path); !os.IsNotExist(err) {
		t.Fatalf("closed file reopened: %v", err)
	}
}

// TestRotationWhileHeldOpen: Windows cannot rename a file another handle
// holds without FILE_SHARE_DELETE (as os.Open does). Rotation must then
// leave the old copies alone and try again later, not shift them out.
func TestRotationWhileHeldOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("open files can be renamed here")
	}
	dir := t.TempDir()
	r := &RotatingFile{Path: filepath.Join(dir, "a.log"), MaxBytes: 100, Keep: 3}
	for i, s := range []string{"one", "two", "three"} {
		os.WriteFile(fmt.Sprintf("%s.%d", r.Path, i+1), []byte(s), 0o600)
	}
	os.WriteFile(r.Path, []byte(strings.Repeat("c", 90)), 0o600)
	held, err := os.Open(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 29) + "\n"
	for range 5 {
		r.Write([]byte(line))
	}
	for i, want := range []string{"one", "two", "three"} {
		if b, err := os.ReadFile(fmt.Sprintf("%s.%d", r.Path, i+1)); err != nil || string(b) != want {
			t.Fatalf(".%d: %q %v", i+1, b, err)
		}
	}
	held.Close()
	r.Write([]byte(line)) // still waiting for the retry time
	if b, _ := os.ReadFile(r.Path + ".1"); string(b) != "one" {
		t.Fatalf("rotated before the retry time: .1 = %q", b)
	}
	r.mu.Lock()
	r.retry = time.Time{}
	r.mu.Unlock()
	r.Write([]byte(line))
	r.Close()
	if b, _ := os.ReadFile(r.Path + ".2"); string(b) != "one" {
		t.Fatalf(".2 = %q", b)
	}
	if b, _ := os.ReadFile(r.Path + ".1"); !strings.HasPrefix(string(b), strings.Repeat("c", 90)) {
		t.Fatalf(".1 = %q", b)
	}
	if b, _ := os.ReadFile(r.Path); string(b) != line {
		t.Fatalf("current = %q", b)
	}
}

// TestRotationWhileCopyHeldOpen: an old copy held open cannot be renamed
// either. The copies already shifted go back, so none is lost, and the
// current file keeps the lines.
func TestRotationWhileCopyHeldOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("open files can be renamed here")
	}
	for _, heldCopy := range []int{1, 2, 3} {
		dir := t.TempDir()
		r := &RotatingFile{Path: filepath.Join(dir, "a.log"), MaxBytes: 100, Keep: 3}
		for i, s := range []string{"one", "two", "three"} {
			os.WriteFile(fmt.Sprintf("%s.%d", r.Path, i+1), []byte(s), 0o600)
		}
		cur := strings.Repeat("c", 90)
		os.WriteFile(r.Path, []byte(cur), 0o600)
		held, err := os.Open(fmt.Sprintf("%s.%d", r.Path, heldCopy))
		if err != nil {
			t.Fatal(err)
		}
		line := strings.Repeat("x", 29) + "\n"
		r.Write([]byte(line))
		r.Close()
		held.Close()
		for i, want := range []string{"one", "two", "three"} {
			if b, err := os.ReadFile(fmt.Sprintf("%s.%d", r.Path, i+1)); err != nil || string(b) != want {
				t.Fatalf("held .%d: .%d = %q %v", heldCopy, i+1, b, err)
			}
		}
		if b, _ := os.ReadFile(r.Path); string(b) != cur+line {
			t.Fatalf("held .%d: current = %q", heldCopy, b)
		}
		if m, _ := filepath.Glob(filepath.Join(dir, "*")); len(m) != 4 {
			t.Fatalf("held .%d: files %v", heldCopy, m)
		}
	}
}
