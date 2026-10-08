package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Sender delivers a message through one channel.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// senderOptions are what senders share: the HTTP client of Telegram and
// webhooks, the TLS settings of SMTP (tests trust their own CA).
type senderOptions struct {
	http *http.Client
	tls  *tls.Config
}

// newSender is the sender of a channel with its opened secret.
func newSender(c model.AlertChannel, secret string, o senderOptions) (Sender, error) {
	switch c.Kind {
	case model.ChannelTelegram:
		var s TelegramSettings
		if err := json.Unmarshal(c.Settings, &s); err != nil {
			return nil, err
		}
		if s.APIBase == "" {
			s.APIBase = DefaultTelegramAPI
		}
		return &telegram{s: s, token: secret, http: o.http}, nil
	case model.ChannelWebhook:
		var s WebhookSettings
		if err := json.Unmarshal(c.Settings, &s); err != nil {
			return nil, err
		}
		return &webhook{s: s, key: secret, http: o.http}, nil
	case model.ChannelSMTP:
		var s SMTPSettings
		if err := json.Unmarshal(c.Settings, &s); err != nil {
			return nil, err
		}
		return &mailer{s: s, password: secret, tls: o.tls}, nil
	}
	return nil, fmt.Errorf("unknown channel kind %q", c.Kind)
}

// plainError drops the URL of a request error: the Bot API URL holds the
// token.
func plainError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// telegram sends through a bot (sendMessage).
type telegram struct {
	s     TelegramSettings
	token string
	http  *http.Client
}

func (t *telegram) Send(ctx context.Context, m Message) error {
	body, _ := json.Marshal(map[string]any{"chat_id": t.s.ChatID, "text": m.Text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.s.APIBase+"/bot"+t.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("bad Bot API address")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return plainError(err)
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode != http.StatusOK || !out.OK {
		return fmt.Errorf("telegram: %d %s", resp.StatusCode, out.Description)
	}
	return nil
}

// Webhook headers: the time of the request (Unix seconds) and the
// signature: "sha256=" and the hex HMAC-SHA256, keyed with the channel's
// secret, of the timestamp, a dot and the body.
const (
	HeaderTimestamp = "X-HyRoute-Timestamp"
	HeaderSignature = "X-HyRoute-Signature"
)

// Sign is the signature of a webhook body sent at timestamp ts.
func Sign(key string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// WebhookBody is the JSON a webhook gets.
type WebhookBody struct {
	Source string    `json:"source"` // "hyroute-server"
	Test   bool      `json:"test,omitempty"`
	SentAt time.Time `json:"sentAt"`
	// Text is the message as Telegram and mail have it.
	Text    string         `json:"text"`
	Dropped int            `json:"dropped,omitempty"`
	Events  []WebhookEvent `json:"events"`
}

// WebhookEvent is one event of a webhook body.
type WebhookEvent struct {
	ID        int64           `json:"id"`
	Kind      model.EventKind `json:"kind"`
	State     string          `json:"state"` // open, closed
	Severity  model.Severity  `json:"severity"`
	Subject   string          `json:"subject"`
	SubjectID int64           `json:"subjectId"`
	Text      string          `json:"text"`
	CloseText string          `json:"closeText,omitempty"`
	Count     int             `json:"count"`
	OpenedAt  time.Time       `json:"openedAt"`
	ClosedAt  *time.Time      `json:"closedAt"`
}

func webhookBody(m Message) WebhookBody {
	b := WebhookBody{Source: "hyroute-server", Test: m.Test, SentAt: m.At.UTC(), Text: m.Text, Dropped: m.Dropped, Events: []WebhookEvent{}}
	for _, n := range m.Notices {
		e := n.Event
		we := WebhookEvent{ID: e.ID, Kind: e.Kind, State: "open", Severity: e.Severity, Subject: e.Subject, SubjectID: e.SubjectID,
			Text: e.Text, CloseText: e.CloseText, Count: e.Count, OpenedAt: e.OpenedAt.UTC()}
		if n.Closed {
			we.State = "closed"
			at := e.ClosedAt.UTC()
			we.ClosedAt = &at
		}
		b.Events = append(b.Events, we)
	}
	return b
}

// webhook posts the JSON with its signature.
type webhook struct {
	s    WebhookSettings
	key  string
	http *http.Client
}

func (w *webhook) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(webhookBody(m))
	if err != nil {
		return err
	}
	ts := m.At.Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.s.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad webhook address")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hyroute-server")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(w.key, ts, body))
	resp, err := w.http.Do(req)
	if err != nil {
		return plainError(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// mailer sends mail over SMTP.
type mailer struct {
	s        SMTPSettings
	password string
	tls      *tls.Config
}

func (ml *mailer) tlsConfig() *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if ml.tls != nil {
		c = ml.tls.Clone()
	}
	c.ServerName = ml.s.Host
	return c
}

func (ml *mailer) Send(ctx context.Context, m Message) error {
	addr := net.JoinHostPort(ml.s.Host, strconv.Itoa(ml.s.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	// The context bounds the whole conversation, not only the dial.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if ml.s.Security == SecurityTLS {
		tc := tls.Client(conn, ml.tlsConfig())
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, ml.s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello("hyroute-server"); err != nil {
		return err
	}
	if ml.s.Security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: the server does not offer STARTTLS")
		}
		if err := c.StartTLS(ml.tlsConfig()); err != nil {
			return err
		}
	}
	if ml.s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", ml.s.Username, ml.password, ml.s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(ml.s.From); err != nil {
		return err
	}
	for _, to := range ml.s.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(ml.letter(m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// letter is the mail: plain text in UTF-8, base64.
func (ml *mailer) letter(m Message) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	rand.Read(id)
	fmt.Fprintf(&b, "From: %s\r\n", ml.s.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(ml.s.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", m.At.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@hyroute-server>\r\n", hex.EncodeToString(id))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(m.Text, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}
