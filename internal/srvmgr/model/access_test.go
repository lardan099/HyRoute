package model

import (
	"slices"
	"testing"
)

func TestRolePermissions(t *testing.T) {
	for _, r := range Roles {
		if !r.Valid() {
			t.Fatalf("%s: not valid", r)
		}
		for _, p := range r.Permissions() {
			if !p.Valid() || !r.Can(p) {
				t.Fatalf("%s: %s", r, p)
			}
		}
	}
	if Role("root").Valid() || Role("root").Can(PermView) || len(Role("").Permissions()) != 0 {
		t.Fatal("an unknown role holds something")
	}
	for _, r := range []Role{RoleOwner, RoleAdmin} {
		if !slices.Equal(r.Permissions(), Permissions) || !r.Unscoped() {
			t.Fatalf("%s: %v", r, r.Permissions())
		}
	}
	// What the roles of Phase 1 could do stays as it was.
	if RoleOperator.Can(PermUsers) || RoleOperator.Can(PermSettings) || !RoleOperator.Can(PermDeploy) || !RoleOperator.Can(PermConfig) {
		t.Fatal("operator")
	}
	if !slices.Equal(RoleReadOnly.Permissions(), []Permission{PermView}) {
		t.Fatalf("readonly: %v", RoleReadOnly.Permissions())
	}
	// The client manager: users and links, no config, no service.
	want := []Permission{PermView, PermClientsReveal, PermClientsManage}
	if !slices.Equal(RoleClients.Permissions(), want) {
		t.Fatalf("clients: %v", RoleClients.Permissions())
	}
	// Changing the returned slice does not change the role.
	ps := RoleOperator.Permissions()
	ps[0] = PermUsers
	if RoleOperator.Can(PermUsers) {
		t.Fatal("role changed through its permissions")
	}
	if !RoleOwner.CanBackup() || RoleAdmin.CanBackup() || !RoleAdmin.CanManageUsers() || RoleOperator.CanManageUsers() || RoleClients.CanCheckKey() {
		t.Fatal("the Can* methods")
	}
}

func TestScope(t *testing.T) {
	de := Scope{Tags: []string{" de ", "NL", "", "nl"}}
	if n := de.Normalize(); !slices.Equal(n.Tags, []string{"de", "NL"}) || n.All {
		t.Fatalf("normalize: %+v", n)
	}
	for tags, want := range map[string]bool{"de": true, "DE": true, " nl": true, "us": false, "": false} {
		if got := de.Covers([]string{"x", tags}); got != want {
			t.Errorf("covers %q: %v", tags, got)
		}
	}
	if de.Covers(nil) {
		t.Error("a server without tags is in a scope of tags")
	}
	if (Scope{}).Covers([]string{"de"}) || (Scope{}).Covers(nil) {
		t.Error("the zero scope reaches something")
	}
	if !ScopeAll.Covers(nil) || (Scope{All: true, Tags: []string{"x"}}).Normalize().Tags != nil {
		t.Error("all")
	}
	if !de.Equal(Scope{Tags: []string{"nl", "De"}}) || de.Equal(ScopeAll) || de.Equal(Scope{Tags: []string{"de"}}) || !ScopeAll.Equal(Scope{All: true}) {
		t.Error("equal")
	}
	u := User{Role: RoleOperator, Scope: Scope{Tags: []string{"de"}}}
	if !u.Can(PermConfig, []string{"de"}) || u.Can(PermConfig, []string{"us"}) || u.Can(PermUsers, nil) || !u.Can(PermPresets, nil) {
		t.Error("operator with a scope")
	}
	// Owners and admins reach everything whatever is stored.
	a := User{Role: RoleAdmin, Scope: Scope{Tags: []string{"de"}}}
	if !a.Reach().All || !a.Can(PermConfig, []string{"us"}) {
		t.Error("admin with a stored scope")
	}
}
