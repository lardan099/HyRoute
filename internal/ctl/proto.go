// Package ctl is the control channel between hyroutectl.exe and a running
// HyRoute: the protocol (frames, requests, results, error codes), the
// named pipe transport and the run event. It does not depend on
// internal/app: hyroutectl imports it and stays small.
package ctl

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Proto is bumped only for an incompatible change; additions (commands,
// optional args, result fields) keep it. MinProto is the oldest client
// version this server still serves.
const (
	Proto    = 1
	MinProto = 1
)

// Frame limits. A request carries at most a rules file: MaxImport bytes of
// UTF-8 text. Requests are encoded by EncodeRequest (no HTML or ASCII
// escaping), so only '"' and '\' grow (2 bytes) and U+2028/U+2029 (3 → 6
// bytes); the client refuses C0 controls and invalid UTF-8, so the body is
// at most 2x MaxImport plus a few hundred bytes. The client still checks
// the size before sending. A response frame carries at most a rules
// export, a report or a page of log entries.
const (
	MaxImport   = 1 << 20
	MaxRequest  = 4 << 20
	MaxResponse = 16 << 20
)

// Frame is every message; exactly one of Hello, Result, Event, Error is
// meaningful.
type Frame struct {
	V      int             `json:"v"`
	OK     bool            `json:"ok"`
	Hello  *Hello          `json:"hello,omitempty"`  // first frame from the server
	Result json.RawMessage `json:"result,omitempty"` // final frame on success
	Event  json.RawMessage `json:"event,omitempty"`  // logs pages (ok=true, not final)
	Final  bool            `json:"final,omitempty"`  // last frame of the request
	Error  *Error          `json:"error,omitempty"`  // denied (as first frame) or a final failure
}

// Hello is the server's first frame to an accepted client.
type Hello struct {
	App      string `json:"app"`      // HyRoute version
	Proto    int    `json:"proto"`    // newest version the server speaks
	MinProto int    `json:"minProto"` // oldest version it accepts (0 from a server that predates the field = Proto)
	Mode     string `json:"mode"`     // "full" | "read"
}

// Request is the one request of a connection.
type Request struct {
	V       int             `json:"v"`
	Cmd     string          `json:"cmd"`
	Args    json.RawMessage `json:"args,omitempty"`
	Private bool            `json:"private,omitempty"`
}

// Error is a refusal or a failure.
type Error struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Lines   []ErrorLine `json:"lines,omitempty"` // rules: per-line/per-rule errors
	Field   string      `json:"field,omitempty"` // unknown-arg: the JSON arg name the server did not know
}

func (e *Error) Error() string { return e.Message }

// ErrorLine is a problem at a line (rules text) or a rule (rules JSON; 0 =
// the file or its default route).
type ErrorLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Server error codes (their exit codes in ExitCode).
const (
	CodeFailed     = "failed"
	CodeBusy       = "busy"
	CodeUsage      = "usage" // bad args, name not found / ambiguous
	CodeDenied     = "denied"
	CodeOff        = "off" // mode switched off while the connection was being accepted
	CodeReadOnly   = "read-only"
	CodeTimeout    = "timeout"
	CodeRules      = "rules"
	CodeUnknown    = "unknown-command"
	CodeUnknownArg = "unknown-arg" // Field set
	CodeVersion    = "version"     // v outside [MinProto, Proto]
)

// Client-side codes (hyroutectl finds these out itself).
const (
	CodeNotRunning  = "not-running"
	CodeStarting    = "starting" // HyRoute did not come up within the timeout
	CodeOtherUser   = "other-user"
	CodeImpostor    = "impostor"
	CodeDropped     = "dropped"
	CodeProtoOld    = "proto-old" // hyroutectl is older than HyRoute
	CodeProtoNew    = "proto-new" // hyroutectl is newer than HyRoute
	CodeTooBig      = "too-big"
	CodeInterrupted = "interrupted"
)

// ExitCode maps a code to hyroutectl's exit code; unknown → 1.
func ExitCode(code string) int {
	switch code {
	case CodeUsage, CodeTooBig:
		return 2
	case CodeNotRunning:
		return 3
	case CodeDenied, CodeOff, CodeReadOnly, CodeOtherUser, CodeImpostor:
		return 4
	case CodeTimeout, CodeStarting:
		return 5
	case CodeRules:
		return 6
	case CodeUnknown, CodeUnknownArg, CodeVersion, CodeProtoOld, CodeProtoNew:
		return 7
	case CodeInterrupted:
		return 130
	}
	return 1 // failed, busy, dropped and anything new
}

// EncodeRequest is the only way the client builds a request frame body:
// no HTML escaping, raw UTF-8 (see MaxRequest).
func EncodeRequest(r Request) ([]byte, error) { return Marshal(r) }

// Marshal is json.Marshal without HTML escaping (the "->" of every rules
// line and "<", "&" stay one byte).
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Transport errors.
var (
	ErrUnsupported = errors.New("the HyRoute control channel exists on Windows only")
	ErrNameTaken   = errors.New("pipe name is taken by another process")
	ErrNotRunning  = errors.New("no pipe")
	ErrBusy        = errors.New("all pipe instances busy")
	ErrDenied      = errors.New("access denied")
	ErrImpostor    = errors.New("pipe owner is not Administrators/SYSTEM")
	ErrClosed      = errors.New("listener closed")
)

// Identity is what the server learnt from the client's token.
type Identity struct {
	User         string // SID string
	Elevated     bool
	Admin        bool // BUILTIN\Administrators enabled in the token
	System       bool
	IntegrityRID uint32 // SECURITY_MANDATORY_*_RID
	PID          uint32 // GetNamedPipeClientProcessId (logging only)
}

// SECURITY_MANDATORY_MEDIUM_RID: the integrity a client needs at least.
const MediumRID = 0x2000

// ---- wire DTOs (stable, additive only) ----

type VersionView struct {
	App   string `json:"app"`
	Core  string `json:"core"`
	Proto int    `json:"proto"`
}

type StatusView struct {
	App             string          `json:"app"`
	State           string          `json:"state"`
	Message         string          `json:"message,omitempty"`
	Since           string          `json:"since,omitempty"` // RFC 3339, "" when off
	Main            *TargetView     `json:"main,omitempty"`
	MainGroup       json.RawMessage `json:"mainGroup,omitempty"` // groups' GroupBrief
	GroupsNote      string          `json:"groupsNote,omitempty"`
	Ruleset         *RulesetBrief   `json:"ruleset,omitempty"` // nil while not saved
	Net             json.RawMessage `json:"net,omitempty"`     // netmodes' NetState
	KillSwitch      string          `json:"killSwitch"`        // "" | armed | blocking
	KillSwitchError string          `json:"killSwitchError,omitempty"`
	NoTunnel        bool            `json:"noTunnel,omitempty"`
	Tunnels         []TunnelView    `json:"tunnels"`
	Warnings        []string        `json:"warnings"`            // RuleWarning.Text
	SubAlerts       json.RawMessage `json:"subAlerts,omitempty"` // subinfo's []SubAlert
	LoadError       string          `json:"loadError,omitempty"`
	SettingsRev     uint64          `json:"settingsRev"`
	Stats           json.RawMessage `json:"stats,omitempty"` // session counters while a session runs
	DNS             json.RawMessage `json:"dns,omitempty"`   // dns' DNSStatus while a session runs
}

type TunnelView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Message  string `json:"message,omitempty"`
	Restarts int    `json:"restarts"`
	Rejected int64  `json:"rejected"`
	Sent     int64  `json:"sent"`
	Recv     int64  `json:"recv"`
}

type TargetView struct {
	Kind string `json:"kind"` // server | group
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RulesetBrief struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ConnectView struct {
	Already   bool       `json:"already"`
	WaitedOut bool       `json:"waitedOut"`
	Status    StatusView `json:"status"`
}

type DisconnectView struct {
	Already          bool       `json:"already"`
	KillSwitchOpened bool       `json:"killSwitchOpened"`
	Status           StatusView `json:"status"`
}

type ServerView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"` // host:port
	Source  string `json:"source"`  // subscription name, "" = manual
	Main    bool   `json:"main"`
	Missing bool   `json:"missing"`
	State   string `json:"state,omitempty"` // tunnel state while connected
}

type GroupsView struct {
	Groups    []GroupLine `json:"groups"`
	LoadError string      `json:"loadError,omitempty"`
}

type GroupLine struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Strategy   string       `json:"strategy"`
	Active     string       `json:"active"`
	ActiveName string       `json:"activeName"`
	Main       bool         `json:"main"`
	Running    bool         `json:"running"`
	Up         int          `json:"up"`
	Total      int          `json:"total"`
	Rejected   int64        `json:"rejected"`
	Members    []MemberLine `json:"members"`
}

type MemberLine struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	ProbeError string `json:"probeError,omitempty"`
	Reason     string `json:"reason,omitempty"`
	LatencyMs  int64  `json:"latencyMs"`
	Errors     int    `json:"errors"`
	Skipped    bool   `json:"skipped"`
	Missing    bool   `json:"missing"`
}

type CheckStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Skip   bool   `json:"skip"`
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

type CheckView struct {
	Profile    string      `json:"profile"`
	OK         bool        `json:"ok"`
	Steps      []CheckStep `json:"steps"`
	ExternalIP string      `json:"externalIP"`
	LatencyMs  int64       `json:"latencyMs"`
}

type RulesetLine struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Rules         int    `json:"rules"`
	DefaultAction string `json:"defaultAction"`
	Active        bool   `json:"active"`
	Warnings      int    `json:"warnings"`
	Error         string `json:"error,omitempty"`
}

type RulesetsView struct {
	Active string        `json:"active"`
	Saved  bool          `json:"saved"`
	Error  string        `json:"error,omitempty"`
	List   []RulesetLine `json:"list"`
}

type RulesetSwitchView struct {
	Already        bool         `json:"already"`
	Ruleset        RulesetBrief `json:"ruleset"`
	Note           string       `json:"note,omitempty"`
	Warnings       []string     `json:"warnings"`
	Connected      bool         `json:"connected"`
	Reconnected    bool         `json:"reconnected"`
	ReconnectError string       `json:"reconnectError,omitempty"`
}

type RulesExportView struct {
	Format  string `json:"format"`
	Content string `json:"content"`
	Rules   int    `json:"rules"`
}

type RulesImportView struct {
	Summary  string      `json:"summary"`
	Rules    int         `json:"rules"`
	Warnings []ErrorLine `json:"warnings"`
	Saved    bool        `json:"saved"`
	Replace  bool        `json:"replace"`
	JSON     bool        `json:"json"` // the content was rules JSON (lines are rules)
	// Of Rules when adding: those the list had already (not added) and
	// those whose copy was off and is on now.
	Skipped int `json:"skipped,omitempty"`
	Enabled int `json:"enabled,omitempty"`
}

type SubLine struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Profiles  int    `json:"profiles"`
	Missing   int    `json:"missing"`
	UpdatedAt string `json:"updatedAt,omitempty"` // RFC 3339
	NextAt    string `json:"nextAt,omitempty"`
	LastError string `json:"lastError,omitempty"`
	Summary   string `json:"summary,omitempty"` // subinfo's Info.Summary
}

type SubUpdateView struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Added       int    `json:"added"`
	Updated     int    `json:"updated"`
	Removed     int    `json:"removed"`
	MissingKept int    `json:"missingKept"`
	Error       string `json:"error,omitempty"`
}

// ---- request args ----

type WaitArgs struct {
	Wait int `json:"wait,omitempty"` // seconds, 0–600
}

type NameArgs struct {
	Name string `json:"name,omitempty"`
}

type RulesetArgs struct {
	Name      string `json:"name,omitempty"`
	Reconnect bool   `json:"reconnect,omitempty"`
}

type ExplainArgs struct {
	Target string `json:"target"`
	App    string `json:"app,omitempty"`
	Port   int    `json:"port,omitempty"`
	UDP    bool   `json:"udp,omitempty"`
	Steps  bool   `json:"steps,omitempty"`
}

type RulesExportArgs struct {
	Format string `json:"format,omitempty"` // text | json
}

type RulesImportArgs struct {
	Content string `json:"content"`
	Format  string `json:"format,omitempty"` // auto | text | json
	Replace bool   `json:"replace,omitempty"`
	DryRun  bool   `json:"dryRun,omitempty"`
}

type LogsArgs struct {
	Kind   string `json:"kind,omitempty"`
	Lines  int    `json:"lines,omitempty"` // 1–10000, default 50
	Follow bool   `json:"follow,omitempty"`
}

// StatsArgs: today | yesterday | 7d | 30d | YYYY-MM (stats feature).
type StatsArgs struct {
	Period string `json:"period,omitempty"`
}

// NetworksSetArgs turns «Действовать по сети» on or off (netmodes feature).
type NetworksSetArgs struct {
	Enabled bool `json:"enabled"`
}

// NetworksApplyArgs: Yes also runs a rule that disconnects (the window
// asks first; --yes is that answer).
type NetworksApplyArgs struct {
	Yes bool `json:"yes,omitempty"`
}
