package apply

import "strings"

// Line is a line of a diff: Op is " " (same), "-" (removed) or "+"
// (added).
type Line struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// maxDiffCells bounds the table of the longest common subsequence, the
// product of the changed lines of both texts (16 MB). A larger change, of
// a config with a big inline ACL, is shown as its old lines removed and
// its new lines added.
const maxDiffCells = 1 << 22

// Diff is the line diff of two texts: the common start and end as they
// are (an edit of a large config is usually local), the lines in between
// by their longest common subsequence.
func Diff(a, b string) []Line {
	x, y := lines(a), lines(b)
	p := 0
	for p < len(x) && p < len(y) && x[p] == y[p] {
		p++
	}
	s := 0
	for s < len(x)-p && s < len(y)-p && x[len(x)-1-s] == y[len(y)-1-s] {
		s++
	}
	out := []Line{}
	for _, l := range x[:p] {
		out = append(out, Line{" ", l})
	}
	out = diffLCS(out, x[p:len(x)-s], y[p:len(y)-s])
	for _, l := range x[len(x)-s:] {
		out = append(out, Line{" ", l})
	}
	return out
}

// diffLCS appends the diff of x and y to out.
func diffLCS(out []Line, x, y []string) []Line {
	n, m := len(x), len(y)
	if (n+1)*(m+1) > maxDiffCells {
		for _, l := range x {
			out = append(out, Line{"-", l})
		}
		for _, l := range y {
			out = append(out, Line{"+", l})
		}
		return out
	}
	// lcs[i][j] is the LCS length of x[i:] and y[j:].
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			out = append(out, Line{" ", x[i]})
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, Line{"-", x[i]})
			i++
		default:
			out = append(out, Line{"+", y[j]})
			j++
		}
	}
	return out
}

// Changed reports whether a diff has any change.
func Changed(d []Line) bool {
	for _, l := range d {
		if l.Op != " " {
			return true
		}
	}
	return false
}

func lines(s string) []string {
	s = strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
