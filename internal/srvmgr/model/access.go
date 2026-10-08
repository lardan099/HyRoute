package model

import (
	"slices"
	"strings"
)

// Permission is one thing a user may do (P4-04). The set is fixed in code;
// a role is a named set of them. The names are stable: the API and the UI
// use them.
type Permission string

const (
	// PermView: see servers, their state, metrics, config summaries,
	// jobs, logs and cascades.
	PermView Permission = "view"
	// PermService: start, stop and restart the Hysteria service.
	PermService Permission = "service"
	// PermConfig: change the config and the routing (editor, rollback,
	// ports, tuning, geo, presets laid over a server, rotation), and read
	// the config text (masked) and the routing.
	PermConfig Permission = "config"
	// PermDeploy: deploy, import, preflight, update or reinstall Hysteria,
	// add and delete servers.
	PermDeploy Permission = "deploy"
	// PermClientsReveal: show the client links and QR codes (passwords).
	PermClientsReveal Permission = "clients.reveal"
	// PermClientsManage: add and remove the client users of a server and
	// change their passwords, nothing else of the config.
	PermClientsManage Permission = "clients.manage"
	// PermCredentials: change how the controller reaches a server (address,
	// SSH user, password or key) and trust or replace its host key.
	PermCredentials Permission = "credentials"
	// PermChains: create, change, deploy, check and delete cascades; needed
	// on every server of the cascade.
	PermChains Permission = "chains"
	// PermPresets: manage presets, rule and cascade templates.
	PermPresets Permission = "presets"
	// PermUsers: manage panel users and read the audit log.
	PermUsers Permission = "users"
	// PermSettings: the panel's own settings (the master key check).
	PermSettings Permission = "settings"
)

// Permissions are all permissions, in the order the UI lists them.
var Permissions = []Permission{
	PermView, PermService, PermConfig, PermDeploy, PermClientsReveal, PermClientsManage,
	PermCredentials, PermChains, PermPresets, PermUsers, PermSettings,
}

// Valid reports whether p is a known permission.
func (p Permission) Valid() bool { return slices.Contains(Permissions, p) }

// ServerBound reports whether p is held on servers, so a user's scope
// limits it; presets, users and settings belong to the panel.
func (p Permission) ServerBound() bool {
	switch p {
	case PermPresets, PermUsers, PermSettings:
		return false
	}
	return p.Valid()
}

// rolePerms are the built-in roles. Owners and admins hold everything
// (backups are the owner's on top: CanBackup).
var rolePerms = map[Role][]Permission{
	RoleOwner:    Permissions,
	RoleAdmin:    Permissions,
	RoleOperator: {PermView, PermService, PermConfig, PermDeploy, PermClientsReveal, PermClientsManage, PermCredentials, PermChains, PermPresets},
	RoleClients:  {PermView, PermClientsReveal, PermClientsManage},
	RoleReadOnly: {PermView},
}

// Permissions are what the role may do, in the order of Permissions.
func (r Role) Permissions() []Permission {
	return slices.Clone(rolePerms[r])
}

// Can reports whether the role holds p.
func (r Role) Can(p Permission) bool { return slices.Contains(rolePerms[r], p) }

// Unscoped: the role always reaches every server; its users' scope is all
// whatever is stored.
func (r Role) Unscoped() bool { return r == RoleOwner || r == RoleAdmin }

// Scope is which servers a user's server-bound permissions reach: all of
// them, or those with at least one of Tags. The zero value reaches none,
// so a scope that went missing locks out instead of opening everything.
type Scope struct {
	All  bool     `json:"all,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// ScopeAll reaches every server.
var ScopeAll = Scope{All: true}

// Covers reports whether a server with tags is in the scope. Tags compare
// as the inventory stores them: trimmed, case-insensitively.
func (s Scope) Covers(tags []string) bool {
	if s.All {
		return true
	}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		for _, want := range s.Tags {
			if t != "" && strings.EqualFold(t, strings.TrimSpace(want)) {
				return true
			}
		}
	}
	return false
}

// Normalize trims the tags and drops empty ones and repeats (case-
// insensitively); a scope of all has no tags.
func (s Scope) Normalize() Scope {
	if s.All {
		return ScopeAll
	}
	out := Scope{}
	for _, t := range s.Tags {
		t = strings.TrimSpace(t)
		if t != "" && !slices.ContainsFunc(out.Tags, func(o string) bool { return strings.EqualFold(o, t) }) {
			out.Tags = append(out.Tags, t)
		}
	}
	return out
}

// Equal reports whether a and b reach the same servers.
func (s Scope) Equal(o Scope) bool {
	a, b := s.Normalize(), o.Normalize()
	if a.All || b.All {
		return a.All == b.All
	}
	return len(a.Tags) == len(b.Tags) && !slices.ContainsFunc(a.Tags, func(t string) bool { return !b.Covers([]string{t}) })
}

// Reach is the scope that holds for u: all for the roles that always
// reach every server (Unscoped), the stored one otherwise.
func (u User) Reach() Scope {
	if u.Role.Unscoped() {
		return ScopeAll
	}
	return u.Scope
}

// Can reports whether u may do p on a server with tags: the role holds p
// and, for a server-bound p, the server is in u's scope.
func (u User) Can(p Permission, tags []string) bool {
	return u.Role.Can(p) && (!p.ServerBound() || u.Reach().Covers(tags))
}
