# HyRoute: how Claude works in this repo

HyRoute is a Windows Hysteria 2 client: Go + Wails v2 + Svelte 5, WinDivert
routing, WFP kill switch. Architecture: docs/ARCHITECTURE.md; user guide:
docs/GUIDE.md. The users speak Russian: answer in Russian, UI text is Russian.

## Two sessions, one branch

Two people drive Claude on this repo at the same time. There is one line of
history, `main`; nobody works on long-lived branches.

- Before starting any task: `git pull --rebase origin main`, then read
  docs/HANDOFF.md. The hook in .claude/settings.json runs on every prompt and
  says when origin/main has commits you do not have: pull them before
  touching code, even in the middle of a task (commit or stash first).
- Push as soon as a piece of work is done and checked, not at the end of the
  day: `git pull --rebase origin main`, re-run the checks, then
  `git push origin HEAD:main`. If your session must also push to its own
  `claude/...` branch, push the same commit there; main is the truth.
- Never force-push main and never rewrite published history. On a rebase
  conflict keep what both sides meant; do not revert the other session's code
  without asking the user.
- Update docs/HANDOFF.md in the same push when you finish something or leave
  something open: it is the shared memory between the sessions.

## Commits

- English messages, a subject line and a short body of what and why.
- No session-link trailers. `Co-Authored-By` is fine.

## Checks before a push

- `gofmt -l internal *.go` prints nothing (third_party/ is not ours).
- `go vet ./...` and `GOOS=windows go vet . ./internal/...`
- `go test ./...`; `go test -race` for the packages you touched.
- UI changes: `cd frontend && npx svelte-check --threshold warning && npx vite build`.
  frontend/dist is committed: commit the rebuilt dist with the change.
- Docs: user-visible changes go into docs/GUIDE.md and the next
  docs/release-notes/vX.Y.Z.txt.

## Never commit

- Share links (hysteria2://, hy2://), their passwords, pins, SNI, server IPs,
  subscription URLs or hosts of the users. Test links live in `.dev/`
  (gitignored). Mask auth and obfs passwords in every log line.
- Release tags are pushed by the user, not by Claude.

## Product decisions to respect

- Statistics never record which sites were visited, in any mode (the
  owner's requirement): only programs, servers and groups.
