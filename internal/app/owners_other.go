//go:build !windows

package app

import "github.com/lardan099/hyroute/internal/localproxy"

// proxyOwners: HyRoute ships for Windows only; the builds for other systems
// exist for tests, which set a fake here.
var proxyOwners localproxy.OwnerLookup
