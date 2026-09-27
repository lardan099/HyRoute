package hysteria

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LogLine is one line of Hysteria's JSON log (HYSTERIA_LOG_FORMAT=json):
// {"level":"info","time":1726480000000,"msg":"connected to server","addr":"...","udpEnabled":true,...}
type LogLine struct {
	Level  string
	Time   time.Time
	Msg    string
	Fields map[string]any
	Raw    string
}

// ParseLogLine parses a JSON log line. Non-JSON lines (panics, early
// startup errors) come back with Level "raw".
func ParseLogLine(line string) LogLine {
	l := LogLine{Raw: line, Level: "raw", Msg: line}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return l
	}
	if s, ok := m["level"].(string); ok {
		l.Level = s
	}
	if s, ok := m["msg"].(string); ok {
		l.Msg = s
	}
	if ms, ok := m["time"].(float64); ok {
		l.Time = time.UnixMilli(int64(ms))
	}
	delete(m, "level")
	delete(m, "msg")
	delete(m, "time")
	l.Fields = m
	return l
}

// Str returns a string field.
func (l LogLine) Str(k string) string {
	s, _ := l.Fields[k].(string)
	return s
}

// ErrorKind classifies connection failures for the UI.
type ErrorKind int

const (
	ErrNone ErrorKind = iota
	ErrAuth
	ErrTLS
	ErrTimeout
	ErrConfig
	ErrOther
	// ErrPortBusy: the local SOCKS5 port was taken between choosing it and
	// Hysteria binding it. Retried at once with another port.
	ErrPortBusy
)

// Classify maps an error text from Hysteria to a kind and a user message.
func Classify(errText string) (ErrorKind, string) {
	e := strings.ToLower(errText)
	switch {
	case strings.Contains(e, "authentication error"):
		return ErrAuth, "Неверный пароль (auth): сервер отклонил авторизацию"
	case strings.Contains(e, "x509") || strings.Contains(e, "certificate") || strings.Contains(e, "crypto_error"):
		return ErrTLS, "Сертификат сервера не прошёл проверку: проверьте sni, используйте pinSHA256 или insecure"
	case strings.Contains(e, "timeout") || strings.Contains(e, "no recent network activity") || strings.Contains(e, "deadline exceeded"):
		return ErrTimeout, "Сервер не отвечает: проверьте адрес, порт и пароль obfs"
	case strings.Contains(e, "only one usage of each socket address") || strings.Contains(e, "address already in use") ||
		(strings.Contains(e, "bind") && strings.Contains(e, "listen tcp")):
		return ErrPortBusy, "Локальный порт SOCKS5 оказался занят, перезапуск на другом порту"
	case strings.Contains(e, "invalid config") || strings.Contains(e, "failed to parse client config") || strings.Contains(e, "failed to load client config"):
		return ErrConfig, "Ошибка в конфигурации профиля: " + errText
	}
	return ErrOther, errText
}

// Event is what a log line means for the supervisor.
type Event struct {
	Connected  bool
	UDPEnabled bool
	Fatal      bool
	// Lost: Hysteria failed to reconnect to the server. The process keeps
	// running, so the supervisor restarts it.
	Lost    bool
	Kind    ErrorKind
	Message string
}

// Interpret extracts supervisor-relevant events from a log line.
func Interpret(l LogLine) (Event, bool) {
	switch {
	case l.Msg == "connected to server":
		udp, _ := l.Fields["udpEnabled"].(bool)
		return Event{Connected: true, UDPEnabled: udp}, true
	case l.Level == "fatal":
		errText := l.Str("error")
		if errText == "" {
			errText = l.Msg
		}
		kind, msg := Classify(errText)
		if kind == ErrOther {
			msg = fmt.Sprintf("%s: %s", l.Msg, errText)
		}
		return Event{Fatal: true, Kind: kind, Message: msg}, true
	case (l.Level == "warn" || l.Level == "error") && reconnectFailed(l.Str("error")):
		errText := l.Str("error")
		kind, msg := Classify(errText)
		// The config was valid at start: "invalid config" here means the
		// host no longer resolves, retried with the normal backoff.
		if kind == ErrOther || kind == ErrConfig {
			kind, msg = ErrOther, "Потеряна связь с сервером: "+errText
		}
		return Event{Lost: true, Kind: kind, Message: msg}, true
	}
	return Event{}, false
}

// reconnectFailed reports the request errors that mean the client could
// not connect to the server again. Hysteria is fatal only when the first
// connection fails: later it drops a dead connection and reconnects on the
// next request, and a failure is logged as a warning of that request
// ("SOCKS5 TCP error") while the process keeps running. Errors of the
// target ("dial error: ...", reported by a working server) or of a single
// stream do not count.
func reconnectFailed(errText string) bool {
	e := strings.ToLower(errText)
	return strings.HasPrefix(e, "connect error") || // QUIC handshake or auth request failed
		strings.HasPrefix(e, "authentication error") ||
		strings.HasPrefix(e, "invalid config") // the host no longer resolves
}
