package apply

import "strings"

// Line is a line of a diff: Op is " " (same), "-" (removed) or "+"
// (added).
type Line struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// Diff is the line diff of two texts (longest common subsequence; the
// configs are small).
func Diff(a, b string) []Line {
	x, y := lines(a), lines(b)
	n, m := len(x), len(y)
	// lcs[i][j] is the LCS length of x[i:] and y[j:].
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
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
	out := []Line{}
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
