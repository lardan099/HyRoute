package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Error is the structured error every API failure returns: Code for
// programs, Message for people (Russian, shown in the UI as is), Details
// for the technical cause.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *Error) Error() string {
	if e.Details != "" {
		return e.Code + ": " + e.Details
	}
	return e.Code
}

// Errorf builds an Error.
func Errorf(status int, code, message string, cause error) *Error {
	e := &Error{Status: status, Code: code, Message: message}
	if cause != nil {
		e.Details = cause.Error()
	}
	return e
}

var (
	errNotFound = &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Не найдено."}
	errInternal = &Error{Status: http.StatusInternalServerError, Code: "internal", Message: "Внутренняя ошибка сервера. Подробности — в журнале controller."}
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	enc.Encode(v)
}

// writeError answers with err as a structured error; anything that is not
// an *Error becomes a generic internal error (its text stays in the log).
// Details are technical text (remote output, library errors): they pass
// through redaction.
func writeError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = errInternal
	}
	out := *e
	out.Details = redact.String(out.Details)
	writeJSON(w, out.Status, struct {
		Error *Error `json:"error"`
	}{&out})
}
