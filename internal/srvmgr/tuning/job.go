package tuning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// JobKind is the name of the job that applies the settings.
const JobKind = "tuning"

// Backup is the suffix of the previous file kept while the job runs.
const Backup = ".hyroute-prev"

// Params are the settings to put in HyRoute's file.
type Params struct {
	Keys []string `json:"keys"`
}

// Kind is the job: check the kernel and decide the values, write the file
// (copy first), apply it, check the values; a failure puts the file and
// the values back.
func Kind() *jobs.Kind {
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p Params
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			if len(p.Keys) == 0 {
				return nil, errors.New("no keys")
			}
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: connect},
				{Name: "check", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return check(ctx, env, p) }},
				{Name: "sysctl", Phase: model.JobConfiguring, Safe: true, Done: fileDone, Run: writeFile, Undo: undoFile},
				{Name: "load", Phase: model.JobConfiguring, Safe: true, Done: applied, Run: apply, Undo: undoApply},
				{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: verify},
				{Name: "tidy", Phase: model.JobVerifying, Safe: true, Run: cleanup},
			}, nil
		},
		// Every step checks the server first: after a restart the job
		// goes on.
		Recover: func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
	}
}

func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

func connect(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return jobs.Fail("Не удалось выполнить команды на сервере.", err)
	}
	if !p.Privileged() {
		return jobs.Fail("Пользователь SSH не root и не может выполнять sudo без пароля.", nil)
	}
	env.Set("root", strconv.FormatBool(p.Root))
	env.Set("kernel", p.Kernel)
	return nil
}

// check decides the file once: a step run again uses the same values.
func check(ctx context.Context, env *jobs.Env, p Params) error {
	if env.Get("text") != "" {
		return nil
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	st, err := Read(ctx, ex, env.Get("kernel"))
	if err != nil {
		return jobs.Fail("Не удалось прочитать параметры ядра.", err)
	}
	plan, err := Plan(st, p.Keys)
	if err != nil {
		return jobs.Fail(sentence(err.Error()), nil)
	}
	want := map[string]string{}
	for _, s := range plan {
		want[s.Key] = s.Want
		if s.Done {
			env.Logf("%s уже %s.", s.Key, s.Current)
		} else {
			env.Logf("%s: %s → %s.", s.Key, s.Current, s.Want)
		}
	}
	b, _ := json.Marshal(want)
	env.Set("want", string(b))
	return env.Set("text", FileText(plan))
}

func sentence(s string) string {
	s = strings.TrimPrefix(s, ErrUnsupported.Error()+": ")
	r := []rune(s)
	s = strings.ToUpper(string(r[0])) + string(r[1:])
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func fileDone(ctx context.Context, env *jobs.Env) (bool, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, FilePath, false)
	return sum == sha(env.Get("text")), err
}

// writeFile records the file's state (once), keeps a copy and writes
// HyRoute's file.
func writeFile(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	su := sudo(env)
	state, err := remote.FileState(ctx, ex, FilePath, su)
	if err != nil {
		return err
	}
	if env.Get("fileState") == "" {
		if err := env.Set("fileState", state); err != nil {
			return err
		}
	}
	if state != remote.Absent && state == env.Get("fileState") {
		if err := remote.CopyFile(ctx, ex, FilePath, FilePath+Backup, su); err != nil {
			return jobs.Fail("Не удалось сохранить копию "+FilePath+".", err)
		}
	}
	if err := ex.WriteFile(ctx, FilePath, []byte(env.Get("text")), remote.FileSpec{Mode: 0o644, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать "+FilePath+".", err)
	}
	env.Logf("Записан %s.", FilePath)
	return nil
}

func undoFile(ctx context.Context, env *jobs.Env) error {
	state := env.Get("fileState")
	if state == "" {
		return jobs.ErrNothingToUndo
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	changed, err := remote.RestoreFile(ctx, ex, FilePath, FilePath+Backup, state, sudo(env))
	if err != nil {
		return err
	}
	if !changed {
		return jobs.ErrNothingToUndo
	}
	if state == remote.Absent {
		env.Logf("Файл %s убран.", FilePath)
	} else {
		env.Logf("Прежний %s возвращён.", FilePath)
	}
	return nil
}

func wanted(env *jobs.Env) map[string]string {
	var want map[string]string
	json.Unmarshal([]byte(env.Get("want")), &want)
	return want
}

func keysOf(m map[string]string) []string {
	var out []string
	for _, k := range Keys {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// applied: the kernel has the values already.
func applied(ctx context.Context, env *jobs.Env) (bool, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return false, err
	}
	want := wanted(env)
	cur, err := remote.SysctlRead(ctx, ex, keysOf(want)...)
	if err != nil {
		return false, err
	}
	for k, v := range want {
		if cur[k] != v {
			return false, nil
		}
	}
	return true, nil
}

// apply records the values the kernel has (once) and loads the file.
func apply(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	want := wanted(env)
	if env.Get("old") == "" {
		cur, err := remote.SysctlRead(ctx, ex, keysOf(want)...)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(cur)
		if err := env.Set("old", string(b)); err != nil {
			return err
		}
	}
	if err := remote.SysctlLoad(ctx, ex, FilePath, sudo(env)); err != nil {
		return jobs.Fail("Ядро не приняло настройки из "+FilePath+".", err)
	}
	env.Logf("Настройки применены (sysctl -p %s).", FilePath)
	return nil
}

// undoApply puts the recorded values back.
func undoApply(ctx context.Context, env *jobs.Env) error {
	var old map[string]string
	if err := json.Unmarshal([]byte(env.Get("old")), &old); err != nil || len(old) == 0 {
		return jobs.ErrNothingToUndo
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	for _, k := range keysOf(old) {
		if err := remote.SysctlSet(ctx, ex, k, old[k], sudo(env)); err != nil {
			return err
		}
	}
	env.Logf("Прежние значения возвращены.")
	return nil
}

func verify(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	want := wanted(env)
	cur, err := remote.SysctlRead(ctx, ex, keysOf(want)...)
	if err != nil {
		return err
	}
	var bad []string
	for _, k := range keysOf(want) {
		if cur[k] != want[k] {
			bad = append(bad, k+" = "+cur[k]+" (нужно "+want[k]+")")
		}
	}
	if len(bad) > 0 {
		return jobs.Fail("Ядро не установило значения: "+strings.Join(bad, "; ")+".", nil)
	}
	env.Logf("Значения на месте; они сохранятся и после перезагрузки.")
	return nil
}

// cleanup removes the copy of the previous file; it never fails the job.
func cleanup(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	if err := remote.RemoveFile(ctx, ex, FilePath+Backup, sudo(env)); err != nil {
		env.Warnf("Копия %s%s осталась на сервере.", FilePath, Backup)
	}
	return nil
}
