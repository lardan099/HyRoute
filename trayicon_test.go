package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
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
