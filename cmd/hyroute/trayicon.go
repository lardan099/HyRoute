package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sync"

	buildfiles "github.com/lardan099/hyroute/build"
)

// The tray icon: the app icon while routing is on, a grey one otherwise.
var trayIcons = sync.OnceValues(func() ([]byte, []byte) {
	src, err := png.Decode(bytes.NewReader(buildfiles.Icon))
	if err != nil {
		return nil, nil
	}
	on := scale(src, 32, false)
	off := scale(src, 32, true)
	return icoFromPNG(on), icoFromPNG(off)
})

// scale shrinks src to n×n by averaging (box filter); grey drops colour.
func scale(src image.Image, n int, grey bool) []byte {
	b := src.Bounds()
	dst := image.NewNRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			x0, x1 := b.Min.X+x*b.Dx()/n, b.Min.X+(x+1)*b.Dx()/n
			y0, y1 := b.Min.Y+y*b.Dy()/n, b.Min.Y+(y+1)*b.Dy()/n
			var r, g, bl, a, cnt uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					c := color.NRGBAModel.Convert(src.At(sx, sy)).(color.NRGBA)
					w := uint64(c.A)
					r, g, bl, a = r+uint64(c.R)*w, g+uint64(c.G)*w, bl+uint64(c.B)*w, a+w
					cnt++
				}
			}
			if cnt == 0 || a == 0 {
				continue
			}
			c := color.NRGBA{uint8(r / a), uint8(g / a), uint8(bl / a), uint8(a / cnt)}
			if grey {
				l := uint8((uint32(c.R)*30 + uint32(c.G)*59 + uint32(c.B)*11) / 100)
				c.R, c.G, c.B, c.A = l, l, l, uint8(uint32(c.A)*3/4)
			}
			dst.SetNRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, dst)
	return buf.Bytes()
}

// icoFromPNG wraps one PNG image into an .ico file (Windows Vista+ reads
// PNG entries).
func icoFromPNG(p []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, 1}) // reserved, type icon, 1 image
	cfg, _ := png.DecodeConfig(bytes.NewReader(p))
	w, h := byte(cfg.Width), byte(cfg.Height)
	b.Write([]byte{w, h, 0, 0})
	binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32}) // planes, bits per pixel
	binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(p)), 6 + 16})
	b.Write(p)
	return b.Bytes()
}

// writeIcon puts ico into dir as a file named after its content (copies
// of HyRoute of other versions may share dir) and returns its path. A file
// there already is kept only if it holds exactly ico.
func writeIcon(dir string, ico []byte) (string, error) {
	if dir == "" || len(ico) == 0 {
		return "", errors.New("no icon, or no folder for it")
	}
	sum := sha256.Sum256(ico)
	path := filepath.Join(dir, "tray-"+hex.EncodeToString(sum[:8])+".ico")
	if b, err := os.ReadFile(path); err == nil && bytes.Equal(b, ico) {
		return path, nil
	}
	tmp := fmt.Sprintf("%s.%d.new", path, os.Getpid())
	if err := os.WriteFile(tmp, ico, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, nil
}
