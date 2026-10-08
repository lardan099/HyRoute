package apply

import (
	"context"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Revert queues the apply job that puts the current revision back on a
// server whose config was changed outside HyRoute (P4-06): found is the
// SHA-256 of the config the reconciliation found there ("" or
// remote.Absent: there was none). It is the apply job with its checks,
// backup, restart and rollback: the config on the server must still be
// the one found (or the revision), the found one comes back if Hysteria
// does not work with the revision, and no revision is added.
func (a *Applier) Revert(ctx context.Context, serverID int64, found string, actor int64) (model.Job, error) {
	cur, b, err := (&Editor{Store: a.x.Store, Keys: a.x.Keys}).Current(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if found == "" {
		found = remote.Absent
	}
	if found == cur.SHA256 {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Конфиг на сервере совпадает с версией HyRoute: возвращать нечего."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: cur.SHA256, Drift: found}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, map[string]string{SecretConfig: string(b)}, actor)
}

// CompareConfigs is the difference between two configs without secrets,
// as the editor shows it: the diff of the masked texts and the paths of
// the secrets that differ.
func CompareConfigs(before, after []byte) ([]Line, []string, error) {
	ma, _, err := Mask(before)
	if err != nil {
		return nil, nil, err
	}
	mb, _, err := Mask(after)
	if err != nil {
		return nil, nil, err
	}
	return Diff(string(ma), string(mb)), append([]string{}, ChangedSecrets(before, after)...), nil
}
