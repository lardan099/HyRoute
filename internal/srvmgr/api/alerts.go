package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/alerts"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// channelJSON is a notification channel without its secret.
type channelJSON struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Kind     model.ChannelKind `json:"kind"`
	Enabled  bool              `json:"enabled"`
	Settings json.RawMessage   `json:"settings"`
	// Events are the kinds sent ([]: every kind).
	Events []model.EventKind `json:"events"`
	Quiet  model.QuietHours  `json:"quiet"`
	// HasSecret: a bot token, signing key or password is stored (it is
	// never shown).
	HasSecret bool      `json:"hasSecret"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func toChannelJSON(c model.AlertChannel) channelJSON {
	evs := c.Events
	if evs == nil {
		evs = []model.EventKind{}
	}
	settings := c.Settings
	if len(settings) == 0 {
		settings = json.RawMessage("{}")
	}
	return channelJSON{ID: c.ID, Name: c.Name, Kind: c.Kind, Enabled: c.Enabled, Settings: settings, Events: evs, Quiet: c.Quiet,
		HasSecret: c.HasSecret, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// channelInput creates or changes a channel.
type channelInput struct {
	Name string `json:"name"`
	// Kind is set at creation only.
	Kind     model.ChannelKind `json:"kind"`
	Enabled  *bool             `json:"enabled"`
	Settings json.RawMessage   `json:"settings"`
	Events   []model.EventKind `json:"events"`
	Quiet    model.QuietHours  `json:"quiet"`
	// Secret replaces the secret; absent or null keeps the stored one.
	// ClearSecret removes it (SMTP without login).
	Secret      *string `json:"secret"`
	ClearSecret bool    `json:"clearSecret"`
}

// manageAlerts answers 403 to whoever may not set up channels.
func manageAlerts(w http.ResponseWriter, r *http.Request) bool {
	if !principal(r).User.Role.CanManageAlerts() {
		writeError(w, errForbidden)
		return false
	}
	return true
}

func (s *server) reloadAlerts(r *http.Request) {
	if s.Alerts != nil {
		if err := s.Alerts.Reload(r.Context()); err != nil {
			s.Log.Warn("alerts: reload", "err", err)
		}
	}
}

func channelTarget(id int64) string { return "alert_channel/" + strconv.FormatInt(id, 10) }

// channelDetails is what the audit keeps of a channel: never its secret
// or settings.
func channelDetails(c model.AlertChannel) string { return string(c.Kind) + " «" + c.Name + "»" }

func (s *server) listChannels(w http.ResponseWriter, r *http.Request) {
	if !manageAlerts(w, r) {
		return
	}
	list, err := s.Store.ListAlertChannels(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]channelJSON, 0, len(list))
	for _, c := range list {
		out = append(out, toChannelJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createChannel(w http.ResponseWriter, r *http.Request) {
	if !manageAlerts(w, r) {
		return
	}
	var in channelInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	now := time.Now()
	c := model.AlertChannel{Name: in.Name, Kind: in.Kind, Enabled: in.Enabled == nil || *in.Enabled, Settings: in.Settings, Events: in.Events,
		Quiet: in.Quiet, CreatedBy: principal(r).User.ID, CreatedAt: now, UpdatedAt: now}
	secret := ""
	if in.Secret != nil {
		secret = *in.Secret
	}
	if err := alerts.Check(&c, secret); err != nil {
		writeError(w, mapError(err))
		return
	}
	if err := s.Store.CreateAlertChannel(r.Context(), &c, s.sealAlert(secret)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: now, UserID: principal(r).User.ID, Action: "alert_channel_created", Target: channelTarget(c.ID), Details: channelDetails(c)})
	s.reloadAlerts(r)
	writeJSON(w, http.StatusCreated, toChannelJSON(c))
}

// sealAlert seals a channel's secret ("": none).
func (s *server) sealAlert(secret string) func(id int64) ([]byte, error) {
	return func(id int64) ([]byte, error) {
		if secret == "" {
			return nil, nil
		}
		if s.Keys == nil {
			return nil, errors.New("no master key")
		}
		return s.Keys.Seal([]byte(secret), model.AlertSecretContext(id))
	}
}

func (s *server) updateChannel(w http.ResponseWriter, r *http.Request) {
	if !manageAlerts(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in channelInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	old, err := s.Store.AlertChannelByID(ctx, id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	if in.Kind != "" && in.Kind != old.Kind {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Вид канала не меняется: создайте новый канал.", Details: "kind"})
		return
	}
	c := old
	c.Name, c.Settings, c.Events, c.Quiet, c.UpdatedAt = in.Name, in.Settings, in.Events, in.Quiet, time.Now()
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	// The checks need the secret the channel will have: the new one, none,
	// or the stored one.
	var seal func(int64) ([]byte, error)
	secret, replaced := "", false
	switch {
	case in.Secret != nil && *in.Secret != "":
		secret, replaced = *in.Secret, true
		seal = s.sealAlert(secret)
	case in.ClearSecret:
		replaced = old.HasSecret
		seal = s.sealAlert("")
	case old.HasSecret:
		if secret, err = s.openAlert(r, id); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if err := alerts.Check(&c, secret); err != nil {
		writeError(w, mapError(err))
		return
	}
	if err := s.Store.UpdateAlertChannel(ctx, c, seal); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	details := channelDetails(c)
	if replaced {
		details += ", secret replaced"
	}
	s.Store.AddAudit(ctx, model.AuditEntry{Time: c.UpdatedAt, UserID: principal(r).User.ID, Action: "alert_channel_updated", Target: channelTarget(id), Details: details})
	s.reloadAlerts(r)
	c, err = s.Store.AlertChannelByID(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toChannelJSON(c))
}

// openAlert opens a channel's stored secret.
func (s *server) openAlert(r *http.Request, id int64) (string, error) {
	sealed, err := s.Store.AlertChannelSecret(r.Context(), id)
	if err != nil || len(sealed) == 0 {
		return "", err
	}
	if s.Keys == nil {
		return "", errors.New("no master key")
	}
	b, err := s.Keys.Open(sealed, model.AlertSecretContext(id))
	return string(b), err
}

func (s *server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	if !manageAlerts(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	c, err := s.Store.AlertChannelByID(r.Context(), id)
	if err == nil {
		err = s.Store.DeleteAlertChannel(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: "alert_channel_deleted", Target: channelTarget(id), Details: channelDetails(c)})
	s.reloadAlerts(r)
	w.WriteHeader(http.StatusNoContent)
}

// testChannel sends a test message through a channel now.
func (s *server) testChannel(w http.ResponseWriter, r *http.Request) {
	if !manageAlerts(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok || s.Alerts == nil {
		writeError(w, errNotFound)
		return
	}
	err := s.Alerts.Test(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, errNotFound)
		return
	}
	outcome := "sent"
	if err != nil {
		outcome = "failed"
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: "alert_channel_tested", Target: channelTarget(id), Details: outcome})
	if err != nil {
		writeError(w, &Error{Status: http.StatusBadGateway, Code: "send_failed", Message: "Сообщение не отправлено: проверьте настройки канала.", Details: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
