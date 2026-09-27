// genicon draws HyRoute's icons (a route that forks in two) without any
// image editor, so the assets are reproducible:
//
//	go run ./tools/genicon            -> build/windows/icon.png (256x256)
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

type shape func(x, y float64) (color.NRGBA, bool)

// render supersamples 4x4 per pixel for smooth edges.
func render(size int, layers []shape) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					var cr, cg, cb, ca float64
					for _, l := range layers {
						if c, ok := l(x, y); ok {
							al := float64(c.A) / 255
							cr = cr*(1-al) + float64(c.R)*al
							cg = cg*(1-al) + float64(c.G)*al
							cb = cb*(1-al) + float64(c.B)*al
							ca = ca*(1-al) + al
						}
					}
					r, g, b, a = r+cr, g+cg, b+cb, a+ca
				}
			}
			n := float64(ss * ss)
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(255 * a / n)})
			}
		}
	}
	return img
}

func roundedRect(x0, y0, x1, y1, rad float64, c func(x, y float64) color.NRGBA) shape {
	return func(x, y float64) (color.NRGBA, bool) {
		cx := math.Max(x0+rad, math.Min(x, x1-rad))
		cy := math.Max(y0+rad, math.Min(y, y1-rad))
		if math.Hypot(x-cx, y-cy) <= rad && x >= x0 && x <= x1 && y >= y0 && y <= y1 {
			return c(x, y), true
		}
		return color.NRGBA{}, false
	}
}

// segment is a thick line with round caps.
func segment(ax, ay, bx, by, w float64, c color.NRGBA) shape {
	return func(x, y float64) (color.NRGBA, bool) {
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
		if math.Hypot(x-(ax+t*dx), y-(ay+t*dy)) <= w/2 {
			return c, true
		}
		return color.NRGBA{}, false
	}
}

func disc(cx, cy, r float64, c color.NRGBA) shape {
	return func(x, y float64) (color.NRGBA, bool) {
		if math.Hypot(x-cx, y-cy) <= r {
			return c, true
		}
		return color.NRGBA{}, false
	}
}

// Layers of the app icon; also used by the tray icons.
func glyph() []shape {
	bg := func(x, y float64) color.NRGBA {
		// diagonal gradient #3b6cf0 -> #7c4dff
		t := (x + y) / 2
		return color.NRGBA{uint8(59 + t*(124-59)), uint8(108 + t*(77-108)), uint8(240 + t*(255-240)), 255}
	}
	white := color.NRGBA{255, 255, 255, 255}
	soft := color.NRGBA{190, 205, 255, 255}
	return []shape{
		roundedRect(0.04, 0.04, 0.96, 0.96, 0.2, bg),
		segment(0.5, 0.82, 0.5, 0.52, 0.1, white),
		segment(0.5, 0.52, 0.27, 0.27, 0.1, white),
		segment(0.5, 0.52, 0.73, 0.27, 0.1, soft),
		disc(0.27, 0.24, 0.085, white),
		disc(0.73, 0.24, 0.085, soft),
	}
}

func main() {
	out := filepath.Join("build", "windows", "icon.png")
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, render(256, glyph())); err != nil {
		log.Fatal(err)
	}
	log.Println("wrote", out)
}
