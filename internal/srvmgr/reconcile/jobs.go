package reconcile

import (
	"context"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Reverter queues the jobs that put HyRoute's version back: the existing
// jobs that write each thing, with their checks, backups and rollback.
// The reconciliation itself writes nothing on a server.
type Reverter interface {
	// RevertConfig: the apply job with the current revision over the
	// config found (its SHA-256, "" when there was none).
	RevertConfig(ctx context.Context, serverID int64, found string, actor int64) (model.Job, error)
	// Maintain: the maintenance job (deploy.OpReinstall, or
	// deploy.OpUpgrade to version).
	Maintain(ctx context.Context, serverID int64, op, version string, actor int64) (model.Job, error)
	// InstallGeo: the geo job with the controller's databases.
	InstallGeo(ctx context.Context, serverID int64, actor int64) (model.Job, error)
	// Relink: the link job that deploys link idx of the chain again.
	Relink(ctx context.Context, chainID int64, idx int, actor int64) (model.Job, error)
}

// Jobs is the Reverter of the controller.
type Jobs struct {
	Apply  *apply.Applier
	Deploy *deploy.Submitter
	Geo    *geo.Installer
	Links  *cascade.Linker
}

func (j Jobs) RevertConfig(ctx context.Context, serverID int64, found string, actor int64) (model.Job, error) {
	return j.Apply.Revert(ctx, serverID, found, actor)
}

func (j Jobs) Maintain(ctx context.Context, serverID int64, op, version string, actor int64) (model.Job, error) {
	return j.Deploy.Maintain(ctx, serverID, deploy.MaintainParams{Op: op, Version: version}, actor)
}

func (j Jobs) InstallGeo(ctx context.Context, serverID int64, actor int64) (model.Job, error) {
	return j.Geo.Submit(ctx, serverID, geo.SourceAuto, 0, actor)
}

func (j Jobs) Relink(ctx context.Context, chainID int64, idx int, actor int64) (model.Job, error) {
	return j.Links.Submit(ctx, chainID, idx, actor)
}
