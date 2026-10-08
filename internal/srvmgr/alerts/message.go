package alerts

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Message is what a channel sends: the notices glued into one text.
type Message struct {
	// Subject is the mail's subject line.
	Subject string
	// Text is the whole message.
	Text    string
	Notices []events.Notice
	// Dropped notices did not fit the channel's queue.
	Dropped int
	// Test: a test from the settings, no events.
	Test bool
	At   time.Time
}

const (
	// maxLines of events in one message; the rest are counted.
	maxLines = 30
	// maxText fits a Telegram message (4096 characters).
	maxText = 4000
	// title opens every message.
	title = "HyRoute Server"
)

// render glues notices into one message. An event that opened and
// closed within it is one line.
func render(ns []events.Notice, dropped int, at time.Time) Message {
	closedIn := map[int64]events.Notice{}
	for _, n := range ns {
		if n.Closed {
			closedIn[n.Event.ID] = n
		}
	}
	var lines []string
	for _, n := range ns {
		e := n.Event
		switch c, ok := closedIn[e.ID]; {
		case !n.Closed && ok:
			lines = append(lines, "Было и прошло: "+e.Text+" → "+c.Event.CloseText)
		case n.Closed && containsOpen(ns, e.ID):
			// told with its opening
		case n.Closed:
			lines = append(lines, "Решено: "+e.CloseText)
		default:
			lines = append(lines, "Проблема: "+e.Text)
		}
	}
	m := Message{Notices: ns, Dropped: dropped, At: at}
	switch {
	case len(lines) == 1 && dropped == 0:
		m.Text = title + ". " + lines[0]
		m.Subject = title + ": " + cut(lines[0], 120)
	default:
		n := len(lines)
		m.Subject = title + ": " + count(n+dropped)
		var b strings.Builder
		b.WriteString(title + " — " + count(n+dropped) + ":")
		for i, l := range lines {
			if i == maxLines {
				b.WriteString("\n…и ещё " + strconv.Itoa(n-maxLines) + ".")
				break
			}
			b.WriteString("\n• " + l)
		}
		if dropped > 0 {
			b.WriteString("\nЕщё " + count(dropped) + " не отправлено: очередь канала была полна.")
		}
		m.Text = b.String()
	}
	m.Text = cut(m.Text, maxText)
	return m
}

func containsOpen(ns []events.Notice, id int64) bool {
	for _, n := range ns {
		if !n.Closed && n.Event.ID == id {
			return true
		}
	}
	return false
}

// testMessage is the message «Отправить тест» sends.
func testMessage(c model.AlertChannel, at time.Time) Message {
	text := title + ". Проверка канала «" + c.Name + "»: оповещения о событиях приходят сюда."
	return Message{Subject: title + ": проверка канала оповещений", Text: text, Test: true, At: at}
}

// count is n events in Russian.
func count(n int) string {
	w := "событий"
	switch m10, m100 := n%10, n%100; {
	case m10 == 1 && m100 != 11:
		w = "событие"
	case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
		w = "события"
	}
	return strconv.Itoa(n) + " " + w
}

// cut shortens s to n characters with an ellipsis.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
