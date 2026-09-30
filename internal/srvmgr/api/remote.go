package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
)

type hostKeyJSON struct {
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	TrustedAt   time.Time `json:"trustedAt"`
}

func toHostKeyJSON(k *model.HostKey) *hostKeyJSON {
	if k == nil {
		return nil
	}
	return &hostKeyJSON{Type: k.Type, Fingerprint: k.Fingerprint, TrustedAt: k.TrustedAt}
}

// remoteError maps SSH-layer errors to API errors.
func remoteError(err error) error {
	var unknown *remote.HostKeyUnknownError
	var changed *remote.HostKeyChangedError
	var unreachable *remote.UnreachableError
	var exit *remote.ExitError
	switch {
	case errors.As(err, &unknown):
		return &Error{Status: http.StatusConflict, Code: "host_key_unknown",
			Message: "Сервер ещё не проверен. Сверьте отпечаток ключа сервера и подтвердите его.",
			Data:    map[string]string{"keyType": unknown.KeyType, "fingerprint": unknown.Fingerprint}}
	case errors.As(err, &changed):
		return &Error{Status: http.StatusConflict, Code: "host_key_changed",
			Message: "Ключ сервера изменился. Так бывает после переустановки системы, но так же выглядит и перехват соединения. Подключение заблокировано, пока вы не подтвердите новый ключ.",
			Data:    map[string]string{"keyType": changed.KeyType, "fingerprint": changed.Fingerprint, "oldKeyType": changed.OldKeyType, "oldFingerprint": changed.OldFingerprint}}
	case errors.Is(err, connect.ErrFingerprintMismatch):
		return &Error{Status: http.StatusConflict, Code: "fingerprint_mismatch", Message: "Сервер сейчас показывает другой ключ, чем тот, что вы подтвердили. Проверьте ещё раз."}
	case errors.Is(err, remote.ErrAuthFailed):
		return &Error{Status: http.StatusBadRequest, Code: "ssh_auth_failed", Message: "Сервер отклонил вход по SSH: проверьте пользователя, пароль или ключ.", Details: err.Error()}
	case errors.Is(err, remote.ErrSudoRequired):
		return &Error{Status: http.StatusBadRequest, Code: "sudo_required", Message: "Пользователь SSH — не root и не может выполнять sudo без пароля. Войдите как root или разрешите sudo без пароля (NOPASSWD)."}
	case errors.As(err, &unreachable):
		return &Error{Status: http.StatusBadGateway, Code: "ssh_unreachable", Message: "Не удалось подключиться к серверу по SSH: проверьте адрес, порт и что сервер включён.", Details: unreachable.Err.Error()}
	case errors.Is(err, servers.ErrNoCredentials):
		return &Error{Status: http.StatusBadRequest, Code: "no_credentials", Message: "У сервера нет сохранённых данных для входа по SSH."}
	case errors.As(err, &exit):
		return &Error{Status: http.StatusBadGateway, Code: "remote_command_failed", Message: "Команда на сервере завершилась с ошибкой.", Details: exit.Error()}
	}
	return err
}

func (s *server) checkServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	p, err := s.Connect.Check(r.Context(), id)
	if err != nil && !errors.Is(err, remote.ErrSudoRequired) {
		s.fail(w, r, mapError(err))
		return
	}
	resp := map[string]any{"probe": p, "ok": err == nil}
	if err != nil {
		e := mapError(err).(*Error)
		resp["warning"] = e
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) trustHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
		Replace     bool   `json:"replace"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	hk, err := s.Connect.Trust(r.Context(), principal(r).User.ID, id, req.Fingerprint, req.Replace)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, toHostKeyJSON(&hk))
}
