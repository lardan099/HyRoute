package cascade

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Ping is what `hysteria ping` reported (JSON log, --log-format json):
// whether the exit answered and whether the target opened through it.
type Ping struct {
	// Connected: "connected to server" — the handshake with the exit
	// passed.
	Connected bool
	// Handshake is from the first line ("ping mode") to "connected to
	// server": ping does not report it, the log's times do (milliseconds;
	// config parsing is in it too).
	Handshake time.Duration
	// TCP: "connected" — the target opened through the exit; TCPTime is
	// how long that took, as ping reports it.
	TCP     bool
	TCPTime time.Duration
	// Error is the error of a "failed to …" line.
	Error string
}

// ParsePing reads the JSON log lines of `hysteria ping`. Its "connected"
// line has a field "time" (the duration) beside the log's own "time" (the
// epoch milliseconds); the later key wins in a JSON object, so on that
// line "time" is the duration.
func ParsePing(out []byte) Ping {
	var p Ping
	var start, connected float64
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var l struct {
			Msg   string          `json:"msg"`
			Time  json.RawMessage `json:"time"`
			Error string          `json:"error"`
		}
		if json.Unmarshal(line, &l) != nil {
			continue
		}
		ms, isNum := epoch(l.Time)
		switch {
		case l.Msg == "ping mode" && isNum:
			start = ms
		case l.Msg == "connected to server":
			p.Connected = true
			if isNum {
				connected = ms
			}
		case l.Msg == "connected":
			p.TCP = true
			var s string
			if json.Unmarshal(l.Time, &s) == nil {
				p.TCPTime, _ = time.ParseDuration(s)
			}
		case strings.HasPrefix(l.Msg, "failed to"):
			p.Error = strings.TrimSpace(l.Msg + ": " + l.Error)
		}
	}
	if p.Connected && start > 0 && connected >= start {
		p.Handshake = time.Duration((connected - start) * float64(time.Millisecond))
	}
	return p
}

func epoch(raw json.RawMessage) (float64, bool) {
	f, err := strconv.ParseFloat(string(raw), 64)
	return f, err == nil
}
