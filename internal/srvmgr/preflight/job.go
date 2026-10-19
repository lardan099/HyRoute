package preflight

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// JobKind is the name of the preflight job.
const JobKind = "preflight"

// Kind is the preflight job: connect and probe, then inspect. The report
// goes to the job data ("report") and to the log; the job fails only when
// the server cannot be inspected, not when checks fail.
func Kind() *jobs.Kind {
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: connectStep},
				{Name: "inspect", Phase: model.JobPreflight, Safe: true, Run: inspectStep},
			}, nil
		},
		// Preflight changes nothing: after a restart it simply runs again.
		Recover: func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
	}
}

func connectStep(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return jobs.Fail("Не удалось выполнить команды на сервере.", err)
	}
	env.Set("user", p.User)
	env.Set("root", strconv.FormatBool(p.Root))
	env.Set("sudo", strconv.FormatBool(p.Sudo))
	env.Set("kernel", p.Kernel)
	env.Set("arch", p.Arch)
	env.Set("hostname", p.Hostname)
	env.Logf("Подключено как %s к %s (%s, %s).", p.User, p.Hostname, p.Kernel, p.Arch)
	return nil
}

func probeFromEnv(env *jobs.Env) remote.Probe {
	b := func(k string) bool { v, _ := strconv.ParseBool(env.Get(k)); return v }
	return remote.Probe{User: env.Get("user"), Root: b("root"), Sudo: b("sudo"), Kernel: env.Get("kernel"), Arch: env.Get("arch"), Hostname: env.Get("hostname")}
}

func inspectStep(ctx context.Context, env *jobs.Env) error {
	var opt Options
	if len(env.Params) > 0 {
		if err := env.DecodeParams(&opt); err != nil {
			return jobs.Fail("Неверные параметры проверки.", err)
		}
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	r, err := Run(ctx, ex, probeFromEnv(env), opt)
	if err != nil {
		return jobs.Fail("Проверка сервера прервалась.", err)
	}
	for _, c := range r.Checks {
		line := c.Title
		if c.Details != "" {
			line += ". " + c.Details
		}
		switch c.Level {
		case OK:
			env.Logf("✓ %s", line)
		default:
			env.Warnf("%s %s", map[Level]string{Warn: "!", Fail: "✗"}[c.Level], line)
		}
	}
	env.Set("report", r.JSON())
	if r.Blocked {
		env.Warnf("Есть препятствия: развёртывание на этом сервере сейчас не пройдёт.")
	} else {
		env.Logf("Препятствий для развёртывания нет.")
	}
	return nil
}
