package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestTrayIcons(t *testing.T) {
	on, off := trayIcons()
	for name, ico := range map[string][]byte{"on": on, "off": off} {
		if len(ico) < 22 {
			t.Fatalf("%s: %d bytes", name, len(ico))
		}
		var hdr [3]uint16
		binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr)
		size := binary.LittleEndian.Uint32(ico[14:])
		off := binary.LittleEndian.Uint32(ico[18:])
		if hdr != [3]uint16{0, 1, 1} || ico[6] != 32 || ico[7] != 32 || int(off+size) != len(ico) {
			t.Fatalf("%s: bad header %v %d %d/%d", name, hdr, off, size, len(ico))
		}
		img, err := png.Decode(bytes.NewReader(ico[off:]))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if bytes.Equal(on, off) {
		t.Fatal("on and off icons are the same")
	}
}

// The icons are files in the given (administrators-only) folder, named
// after their content; a file there that holds something else is replaced.
func TestWriteIcon(t *testing.T) {
	dir := t.TempDir()
	on, off := trayIcons()
	pOn, err := writeIcon(dir, on)
	if err != nil {
		t.Fatal(err)
	}
	pOff, err := writeIcon(dir, off)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(pOn) != dir || filepath.Dir(pOff) != dir || pOn == pOff {
		t.Fatalf("icons at %s and %s, want two files in %s", pOn, pOff, dir)
	}
	if err := os.WriteFile(pOn, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := writeIcon(dir, on); err != nil || p != pOn {
		t.Fatalf("%s (%v), want %s", p, err, pOn)
	}
	if b, _ := os.ReadFile(pOn); !bytes.Equal(b, on) {
		t.Fatal("a file with other content kept")
	}
	if _, err := writeIcon("", on); err == nil {
		t.Fatal("an icon written without a folder")
	}
}
