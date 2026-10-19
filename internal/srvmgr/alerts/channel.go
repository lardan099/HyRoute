// Package alerts sends notifications of events (P4-05b) to the channels
// the owner or an admin set up: a Telegram bot, a webhook with a JSON
// body signed by HMAC, or mail over SMTP. Sending never holds up whoever
// raised the event: the Notifier queues every notice per channel (a
// bounded queue), glues what comes within a short window into one
// message, holds messages through the channel's quiet hours, and retries
// a failed send after a pause, each send within a timeout.
//
// Channel secrets (bot token, webhook signing key, SMTP password) are
// sealed with the master key and opened only to send.
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	// Quiet hours are in the admin's time zone: the zones are built in, so
	// a server (or Windows) without tzdata knows them too.
	_ "time/tzdata"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// DefaultTelegramAPI is where the Bot API is.
const DefaultTelegramAPI = "https://api.telegram.org"

// TelegramSettings: the chat the bot writes to (its numeric ID or
// @channel). APIBase is the Bot API (DefaultTelegramAPI if ""): a local
// Bot API server or a proxy. The bot token is the channel's secret.
type TelegramSettings struct {
	ChatID  string `json:"chatId"`
	APIBase string `json:"apiBase,omitempty"`
}

// WebhookSettings: where the JSON goes (POST). The signing key is the
// channel's secret.
type WebhookSettings struct {
	URL string `json:"url"`
}

// SMTP security of the connection.
const (
	SecurityStartTLS = "starttls" // plain connection upgraded by STARTTLS (port 587)
	SecurityTLS      = "tls"      // TLS from the start (port 465)
	SecurityNone     = "none"     // no TLS: a mail server on this machine only
)

// SMTPSettings: the mail server, who sends and who gets the mail. The
// password (when Username is set) is the channel's secret.
type SMTPSettings struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

var (
	hhmm     = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	botToken = regexp.MustCompile(`^[0-9]{3,20}:[A-Za-z0-9_-]{20,100}$`)
	chatID   = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{4,64})$`)
)

// minWebhookSecret is the shortest signing key taken.
const minWebhookSecret = 16

func invalid(field, msg string) error { return &model.FieldError{Field: field, Msg: msg} }

// Check validates a channel as the admin set it and normalizes its
// settings (unknown fields are refused). secret is the secret the
// channel will have ("" none).
func Check(c *model.AlertChannel, secret string) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 64 {
		return invalid("name", "Название — от 1 до 64 символов.")
	}
	if !c.Kind.Valid() {
		return invalid("kind", "Канал — Telegram, вебхук или почта.")
	}
	seen := map[model.EventKind]bool{}
	var kinds []model.EventKind
	for _, k := range c.Events {
		if !k.Valid() {
			return invalid("events", "Неизвестный вид событий: "+string(k)+".")
		}
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	c.Events = kinds
	if err := checkQuiet(&c.Quiet); err != nil {
		return err
	}
	var (
		norm any
		err  error
	)
	switch c.Kind {
	case model.ChannelTelegram:
		norm, err = checkTelegram(c.Settings, secret)
	case model.ChannelWebhook:
		norm, err = checkWebhook(c.Settings, secret)
	case model.ChannelSMTP:
		norm, err = checkSMTP(c.Settings, secret)
	}
	if err != nil {
		return err
	}
	c.Settings, _ = json.Marshal(norm)
	return nil
}

func checkQuiet(q *model.QuietHours) error {
	q.From, q.To, q.Zone = strings.TrimSpace(q.From), strings.TrimSpace(q.To), strings.TrimSpace(q.Zone)
	if q.From == "" && q.To == "" {
		*q = model.QuietHours{}
		return nil
	}
	if !hhmm.MatchString(q.From) || !hhmm.MatchString(q.To) || q.From == q.To {
		return invalid("quiet", "Тихие часы — начало и конец в виде ЧЧ:ММ, разные.")
	}
	if q.Zone != "" {
		if _, err := time.LoadLocation(q.Zone); err != nil {
			return invalid("quiet", "Неизвестный часовой пояс: "+q.Zone+".")
		}
	}
	return nil
}

// decode reads settings of a kind; unknown fields are an error.
func decode(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("settings", "Настройки канала не разобрать: "+err.Error())
	}
	return nil
}

func checkTelegram(raw json.RawMessage, secret string) (TelegramSettings, error) {
	var s TelegramSettings
	if err := decode(raw, &s); err != nil {
		return s, err
	}
	s.ChatID, s.APIBase = strings.TrimSpace(s.ChatID), strings.TrimRight(strings.TrimSpace(s.APIBase), "/")
	if !chatID.MatchString(s.ChatID) {
		return s, invalid("chatId", "ID чата — число (у групп и каналов со знаком минус) или @имя канала.")
	}
	if s.APIBase == DefaultTelegramAPI {
		s.APIBase = ""
	}
	if s.APIBase != "" {
		if err := checkURL(s.APIBase, false); err != nil {
			return s, invalid("apiBase", "Адрес Bot API: "+err.Error())
		}
	}
	if !botToken.MatchString(secret) {
		return s, invalid("secret", "Токен бота — как его выдаёт @BotFather: «123456789:AA…».")
	}
	return s, nil
}

func checkWebhook(raw json.RawMessage, secret string) (WebhookSettings, error) {
	var s WebhookSettings
	if err := decode(raw, &s); err != nil {
		return s, err
	}
	s.URL = strings.TrimSpace(s.URL)
	if err := checkURL(s.URL, true); err != nil {
		return s, invalid("url", "Адрес вебхука: "+err.Error())
	}
	if len(secret) < minWebhookSecret {
		return s, invalid("secret", fmt.Sprintf("Ключ подписи — не короче %d символов: им получатель проверяет, что запрос пришёл от панели.", minWebhookSecret))
	}
	return s, nil
}

// checkURL takes http(s) URLs without a user and password; plain http
// only to this machine unless anyHTTP.
func checkURL(raw string, anyHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("нужен полный адрес вида https://example.com/…")
	}
	if u.User != nil {
		return fmt.Errorf("без имени и пароля в адресе")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !anyHTTP && !loopback(u.Hostname()) {
			return fmt.Errorf("http — только для этой машины, иначе https")
		}
	default:
		return fmt.Errorf("нужен http или https")
	}
	return nil
}

// loopback: localhost or a loopback address.
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkSMTP(raw json.RawMessage, secret string) (SMTPSettings, error) {
	var s SMTPSettings
	if err := decode(raw, &s); err != nil {
		return s, err
	}
	s.Host, s.Username, s.From = strings.TrimSpace(s.Host), strings.TrimSpace(s.Username), strings.TrimSpace(s.From)
	if s.Host == "" || strings.ContainsAny(s.Host, " /:@[]") && net.ParseIP(s.Host) == nil {
		return s, invalid("host", "Сервер почты — имя или IP-адрес, без порта.")
	}
	switch s.Security {
	case SecurityStartTLS, SecurityTLS:
	case SecurityNone:
		if !loopback(s.Host) {
			return s, invalid("security", "Без TLS — только к почтовому серверу на этой же машине (localhost): иначе пароль и письма пойдут по сети открыто.")
		}
	default:
		return s, invalid("security", "Защита — STARTTLS, TLS или без TLS (только localhost).")
	}
	if s.Port == 0 {
		s.Port = map[string]int{SecurityStartTLS: 587, SecurityTLS: 465, SecurityNone: 25}[s.Security]
	}
	if s.Port < 1 || s.Port > 65535 {
		return s, invalid("port", "Порт — от 1 до 65535.")
	}
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return s, invalid("from", "Адрес отправителя не разобрать.")
	}
	s.From = from.Address
	var to []string
	for _, a := range s.To {
		if strings.TrimSpace(a) == "" {
			continue
		}
		addr, err := mail.ParseAddress(strings.TrimSpace(a))
		if err != nil {
			return s, invalid("to", "Адрес получателя не разобрать: "+a+".")
		}
		to = append(to, addr.Address)
	}
	if len(to) == 0 || len(to) > 20 {
		return s, invalid("to", "Получатели — от 1 до 20 адресов.")
	}
	s.To = to
	if s.Username != "" && secret == "" {
		return s, invalid("secret", "С именем пользователя нужен и пароль.")
	}
	if strings.ContainsAny(s.Username, "\r\n") {
		return s, invalid("username", "Имя пользователя — одной строкой.")
	}
	return s, nil
}

// quiet reports whether t is inside the quiet hours q.
func quiet(q model.QuietHours, t time.Time) bool {
	if !hhmm.MatchString(q.From) || !hhmm.MatchString(q.To) || q.From == q.To {
		return false
	}
	loc := time.Local
	if q.Zone != "" {
		if l, err := time.LoadLocation(q.Zone); err == nil {
			loc = l
		}
	}
	t = t.In(loc)
	m := t.Hour()*60 + t.Minute()
	from, to := minutes(q.From), minutes(q.To)
	if from < to {
		return m >= from && m < to
	}
	return m >= from || m < to // across midnight
}

func minutes(hm string) int {
	h, _ := strconv.Atoi(hm[:2])
	m, _ := strconv.Atoi(hm[3:])
	return h*60 + m
}

// Destination is where a channel's secret goes, from its checked
// settings: the Bot API, the webhook URL, or the mail server with its
// security and login. A channel whose destination changes must be given
// its secret again: a stored token or password never goes to an address
// it was not entered for.
func Destination(kind model.ChannelKind, settings json.RawMessage) string {
	switch kind {
	case model.ChannelTelegram:
		var s TelegramSettings
		if decode(settings, &s) != nil {
			return ""
		}
		if s.APIBase == "" {
			s.APIBase = DefaultTelegramAPI
		}
		return s.APIBase
	case model.ChannelWebhook:
		var s WebhookSettings
		if decode(settings, &s) != nil {
			return ""
		}
		return s.URL
	case model.ChannelSMTP:
		var s SMTPSettings
		if decode(settings, &s) != nil {
			return ""
		}
		return fmt.Sprintf("%s %s:%d %s", s.Security, strings.ToLower(s.Host), s.Port, s.Username)
	}
	return ""
}
