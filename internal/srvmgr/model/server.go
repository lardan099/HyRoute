package model

import (
	"strconv"
	"time"
)

// AuthType is how the controller logs in over SSH.
type AuthType string

const (
	AuthPassword AuthType = "password"
	AuthKey      AuthType = "key"
)

// ServerRole is the place of a server in a topology. Phase 1 deploys
// standalone servers; entry/relay/exit are for cascades (Phase 3).
type ServerRole string

const (
	RoleStandalone ServerRole = "standalone"
	RoleEntry      ServerRole = "entry"
	RoleRelay      ServerRole = "relay"
	RoleExit       ServerRole = "exit"
)

// Valid reports whether r is a known role.
func (r ServerRole) Valid() bool {
	switch r {
	case RoleStandalone, RoleEntry, RoleRelay, RoleExit:
		return true
	}
	return false
}

// ServerState is what the controller last knew about a server.
type ServerState string

const (
	StateNew            ServerState = "new"
	StateDeploying      ServerState = "deploying"
	StateHealthy        ServerState = "healthy"
	StateDegraded       ServerState = "degraded"
	StateOffline        ServerState = "offline"
	StateNeedsAttention ServerState = "needs_attention"
)

// Server is a managed machine. Its SSH credentials are separate
// (Credential) and never leave the controller.
type Server struct {
	ID       int64
	Name     string
	Tags     []string
	Country  string // ISO 3166-1 alpha-2, optional ("DE")
	Location string // free label ("Frankfurt, Hetzner")
	Host     string // domain or IP, no port
	SSHPort  int
	SSHUser  string
	AuthType AuthType
	Role     ServerRole
	Notes    string
	State    ServerState
	// HopInterval is the port hopping interval of the client links, in
	// seconds (0: the client's default); used when the ports are a union.
	HopInterval int

	CreatedAt time.Time
	UpdatedAt time.Time
}

// CredKind names a stored SSH credential.
type CredKind string

const (
	CredSSHPassword      CredKind = "ssh_password"
	CredSSHKey           CredKind = "ssh_key"
	CredSSHKeyPassphrase CredKind = "ssh_key_passphrase"
)

// Credential is a sealed secret of a server (secrets.Keyring, context
// CredContext).
type Credential struct {
	Kind   CredKind
	Sealed []byte
}

// CredContext is the additional data a server credential is sealed with:
// a sealed value copied to another server or kind does not open.
func CredContext(serverID int64, kind CredKind) string {
	return "server/" + strconv.FormatInt(serverID, 10) + "/" + string(kind)
}

// HostKey is the trusted SSH host key of a server.
type HostKey struct {
	ServerID    int64
	Type        string // ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa…
	Key         []byte // SSH wire format
	Fingerprint string // SHA256:…
	TrustedAt   time.Time
	TrustedBy   int64
}
