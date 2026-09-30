package model

import (
	"strconv"
	"time"
)

// ConfigSource is where a config revision came from.
type ConfigSource string

const (
	ConfigDeploy ConfigSource = "deploy"
	ConfigImport ConfigSource = "import"
	ConfigEdit   ConfigSource = "edit"
)

// ConfigMeta is the non-secret summary of a config revision: what the UI
// shows and what client links need besides the passwords.
type ConfigMeta struct {
	Version   string `json:"version,omitempty"`   // Hysteria version installed with it
	Listen    string `json:"listen,omitempty"`    // as in the config
	Ports     string `json:"ports,omitempty"`     // public ports for clients
	TLS       string `json:"tls,omitempty"`       // self-signed, acme, file
	PinSHA256 string `json:"pinSHA256,omitempty"` // self-signed certificate
	SNI       string `json:"sni,omitempty"`
	Obfs      string `json:"obfs,omitempty"` // salamander, gecko
	Auth      string `json:"auth,omitempty"` // password, userpass…
}

// ServerConfig is one revision of a server's Hysteria config.
type ServerConfig struct {
	ID       int64
	ServerID int64
	Revision int // 1, 2… per server
	Sealed   []byte
	SHA256   string // of the YAML as installed
	Meta     ConfigMeta
	Source   ConfigSource
	JobID    int64
	By       int64
	At       time.Time
}

// ConfigContext is the additional data a config revision is sealed with.
func ConfigContext(serverID int64, revision int) string {
	return "server/" + strconv.FormatInt(serverID, 10) + "/config/" + strconv.Itoa(revision)
}
