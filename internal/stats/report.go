package stats

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// DayTotal is one bar of the chart.
type DayTotal struct {
	Day string `json:"day"`
	Counters
}

// Report is the statistics of one period for «Статистика».
type Report struct {
	Period     string     `json:"period"` // as asked
	From       string     `json:"from"`   // "YYYY-MM-DD", inclusive
	To         string     `json:"to"`
	Total      Counters   `json:"total"`
	Events     Events     `json:"events"`
	Days       []DayTotal `json:"days"` // one per day in From..To, zero-filled, except days already rolled into a month file
	Apps       []Row      `json:"apps"` // sorted as trim, capped, "*" last
	Servers    []Row      `json:"servers"`
	Groups     []Row      `json:"groups"`
	Months     []string   `json:"months"`          // "YYYY-MM" with data, newest first; the current month always
	Since      string     `json:"since,omitempty"` // earliest day with data
	Mode       string     `json:"mode"`
	StoreError string     `json:"storeError,omitempty"`
	// ModeUnread: mode.json could not be read (collection is off until
	// the user picks a mode, «Выключен» included).
	ModeUnread bool `json:"modeUnread,omitempty"`
}

var errPeriod = errors.New("неизвестный период статистики")

// periodRange: today, yesterday, 7d, 30d or a calendar month YYYY-MM (not
// a future one; the current month ends today).
func periodRange(now time.Time, period string) (from, to string, month bool, err error) {
	today := dayOf(now)
	switch period {
	case "today":
		return today, today, false, nil
	case "yesterday":
		y := addDays(today, -1)
		return y, y, false, nil
	case "7d":
		return addDays(today, -6), today, false, nil
	case "30d":
		return addDays(today, -29), today, false, nil
	}
	if kind, m, ok := parseName("month-" + period); !ok || kind != kindMonth || m != period || m > today[:7] {
		return "", "", false, errPeriod
	}
	from = period + "-01"
	to = addDays(addMonths(period, 1)+"-01", -1)
	if to > today {
		to = today
	}
	return from, to, true, nil
}

// Report sums a period: its day files, its month file (for a month) and
// the unflushed deltas. A day the month file already holds is taken from
// the month file only.
func (c *Collector) Report(now time.Time, period string) (Report, error) {
	from, to, isMonth, err := periodRange(now, period)
	if err != nil {
		return Report{}, err
	}
	r := Report{Period: period, From: from, To: to, Mode: string(c.Mode())}
	agg := &File{V: 1}
	var names []string
	folded := map[string]bool{}
	// readErr: a file or the folder could not be read now (the period
	// is incomplete); a corrupt or newer file is noted in bad instead.
	readErr := ""
	noteRead := func(name string, st loadState, err error) {
		if st == loadTransient && readErr == "" {
			readErr = "не удалось прочитать " + name + ".json: " + shortErr(err)
		}
	}
	if c.files != nil {
		c.lockIO(now)
		defer c.ioMu.Unlock()
		var err error
		if names, err = c.files.List(); err != nil {
			readErr = "не удалось прочитать папку stats: " + shortErr(err)
		}
		if isMonth {
			mname := "month-" + period
			if !future(mname, now) {
				f, st, err := c.load(mname, now)
				noteRead(mname, st, err)
				if st == loadOK {
					agg.addFile(f)
					for _, d := range f.Days {
						folded[d] = true
					}
				}
			}
		}
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	// At most 31 days (a month), and never a date that does not advance.
	for i, d := 0, from; d <= to && i < 31; i, d = i+1, nextDay(d) {
		if folded[d] {
			continue
		}
		day := &File{V: 1}
		if have["day-"+d] && !future("day-"+d, now) {
			f, st, err := c.load("day-"+d, now)
			noteRead("day-"+d, st, err)
			if st == loadOK {
				day.addFile(f)
			}
		}
		c.mu.Lock()
		if m := c.delta[d]; m != nil {
			day.addMem(m) // one day's delta per hold
		}
		c.mu.Unlock()
		agg.addFile(day)
		r.Days = append(r.Days, DayTotal{Day: d, Counters: day.Total})
	}
	r.Total, r.Events = agg.Total, agg.Events
	foldExeRows(&agg.Apps)
	for i := range nLists {
		l := trimRows(*agg.list(i), reportCaps[i])
		if l == nil {
			l = []Row{}
		}
		*agg.list(i) = l
	}
	r.Apps, r.Servers, r.Groups = agg.Apps, agg.Servers, agg.Groups
	if r.Days == nil {
		r.Days = []DayTotal{}
	}
	r.Months, r.Since = c.months(now, names)
	c.mu.Lock()
	if c.files != nil {
		c.readErr = readErr
	}
	r.StoreError = c.storeErrLocked()
	r.ModeUnread = c.modeErr != ""
	c.mu.Unlock()
	return r, nil
}

// foldExeRows merges a program known only by its file name ("chrome.exe":
// the days imported from HyRoute 1.2.0, or a flow whose path was not
// found) into the row of its full path when exactly one path in the list
// has that file name. The path row keeps its name.
func foldExeRows(l *[]Row) {
	byBase := map[string]int{} // file name -> index of its path row, -1 when several
	for i, r := range *l {
		if j := strings.LastIndexByte(r.Key, '\\'); j >= 0 && !strings.HasPrefix(r.Key, proxyPrefix) {
			base := r.Key[j+1:]
			if _, dup := byBase[base]; dup {
				byBase[base] = -1
			} else {
				byBase[base] = i
			}
		}
	}
	folded := map[int]bool{}
	for i := range *l {
		r := &(*l)[i]
		if r.Key == "" || r.Key == Others || strings.ContainsRune(r.Key, '\\') || strings.HasPrefix(r.Key, proxyPrefix) {
			continue
		}
		if j, ok := byBase[r.Key]; ok && j >= 0 {
			dst := &(*l)[j]
			name := dst.Name
			dst.add(r)
			dst.Name = name
			folded[i] = true
		}
	}
	if len(folded) == 0 {
		return
	}
	out := make([]Row, 0, len(*l)-len(folded))
	for i, r := range *l {
		if !folded[i] {
			out = append(out, r)
		}
	}
	*l = out
}

// nextDay is the day after d; "~" (after every date) if the date did not
// advance, which ends a loop over days.
func nextDay(d string) string {
	if n := addDays(d, 1); n > d {
		return n
	}
	return "~"
}

// months lists the months with data (files or deltas), newest first, the
// current month always, and the earliest day with data. ioMu held when
// there are files.
func (c *Collector) months(now time.Time, names []string) ([]string, string) {
	set := map[string]bool{dayOf(now)[:7]: true}
	since, firstMonth := "", ""
	for _, n := range names {
		if future(n, now) {
			continue
		}
		kind, date, _ := parseName(n)
		switch kind {
		case kindDay:
			set[date[:7]] = true
			if since == "" || date < since {
				since = date
			}
		case kindMonth:
			set[date] = true
			if firstMonth == "" || date < firstMonth {
				firstMonth = date
			}
		}
	}
	c.mu.Lock()
	for d := range c.delta {
		set[d[:7]] = true
		if since == "" || d < since {
			since = d
		}
	}
	c.mu.Unlock()
	if firstMonth != "" && (since == "" || firstMonth <= since[:7]) {
		// The month file holds its earliest day.
		first := firstMonth + "-01"
		if f, st, _ := c.load("month-"+firstMonth, now); st == loadOK && len(f.Days) > 0 {
			first = f.Days[0]
		}
		if since == "" || first < since {
			since = first
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, since
}
