package model

import (
	"encoding/json"
	"strconv"
	"time"
)

// ChannelKind is how a notification channel delivers (P4-05).
type ChannelKind string

const (
	ChannelTelegram ChannelKind = "telegram"
	ChannelWebhook  ChannelKind = "webhook"
	ChannelSMTP     ChannelKind = "smtp"
)

// Valid reports whether k is a known kind.
func (k ChannelKind) Valid() bool {
	return k == ChannelTelegram || k == ChannelWebhook || k == ChannelSMTP
}

// QuietHours hold notifications from From to To ("HH:MM", across
// midnight when To is earlier) in the time zone Zone (IANA; "": the
// controller's): what comes then is sent, glued, when they end. Empty
// From or To: none.
type QuietHours struct {
	From string `json:"from"`
	To   string `json:"to"`
	Zone string `json:"zone"`
}

// AlertChannel is where notifications of events go. Its secret (bot
// token, webhook signing key, SMTP password) is sealed apart
// (AlertSecretContext) and never leaves the controller.
type AlertChannel struct {
	ID      int64
	Name    string
	Kind    ChannelKind
	Enabled bool
	// Settings are the kind's settings without the secret (JSON).
	Settings json.RawMessage
	// Events are the kinds sent; empty: every kind.
	Events []EventKind
	Quiet  QuietHours
	// HasSecret: a secret is stored.
	HasSecret bool

	CreatedBy int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Wants reports whether the channel sends events of kind k.
func (c AlertChannel) Wants(k EventKind) bool {
	if len(c.Events) == 0 {
		return true
	}
	for _, x := range c.Events {
		if x == k {
			return true
		}
	}
	return false
}

// CanManageAlerts: may set up notification channels and send tests.
func (r Role) CanManageAlerts() bool { return r.Can(PermSettings) }

// AlertSecretContext is the additional data the secret of a channel is
// sealed with: a sealed value copied to another channel does not open.
func AlertSecretContext(channelID int64) string {
	return "alert/" + strconv.FormatInt(channelID, 10) + "/secret"
}
