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
	// ConfigRollback: an earlier revision installed again (FromRevision).
	ConfigRollback ConfigSource = "rollback"
	// ConfigRotate: new passwords or a new certificate (P2-05).
	ConfigRotate ConfigSource = "rotate"
	// ConfigCascade: a cascade link added or removed its part (P3-02):
	// the link's user on the exit, the outbound on the entry.
	ConfigCascade ConfigSource = "cascade"
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
	// FromRevision is the revision a rollback brought back (0 otherwise).
	FromRevision int
	JobID        int64
	By           int64
	At           time.Time
}

// ConfigContext is the additional data a config revision is sealed with.
func ConfigContext(serverID int64, revision int) string {
	return "server/" + strconv.FormatInt(serverID, 10) + "/config/" + strconv.Itoa(revision)
}

// Installation is where Hysteria is on a server.
type Installation struct {
	ServerID int64
	Binary   string // /usr/local/bin/hysteria
	Config   string // /etc/hysteria/config.yaml
	Unit     string // hysteria-server.service
	User     string // the service's user ("" = root)
	Version  string
	// Managed: HyRoute installed it (deploy); an imported installation is
	// left as it is until the admin replaces it.
	Managed bool
	At      time.Time
	// Firewall is kept by SetFirewall; SetInstallation leaves it alone.
	Firewall Firewall
}

// Firewall is what HyRoute opened in a server's firewall: the rules it
// may close again. Rules that were there before are never recorded.
type Firewall struct {
	Tool  string // ufw, firewalld ("" = nothing recorded)
	Ports string // PortSpec strings, sorted, comma-separated: "443/udp,20000-50000/udp"
	// Keep: the admin chose at deploy to leave the firewall alone.
	Keep bool
}

// Preset is a reusable part of a server config (package preset): its
// sections as YAML, without secrets and server addresses.
type Preset struct {
	ID     int64
	Name   string
	Config string
	// Notes say what was left out when it was made.
	Notes     []string
	CreatedBy int64 // 0: unknown or removed
	CreatedAt time.Time
	UpdatedAt time.Time
}
