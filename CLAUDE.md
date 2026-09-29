# HyRoute development notes

HyRoute is a Windows Hysteria 2 client: Go + Wails v2 + Svelte 5, WinDivert
routing, WFP kill switch. Architecture: docs/ARCHITECTURE.md; user guide:
docs/GUIDE.md. The users speak Russian: answer in Russian, UI text is Russian.

## Workflow

- Development happens on `main`. Start from the current code:
  `git pull --rebase origin main`. The hook in .claude/settings.json says
  when origin/main has moved; pull before changing code.
- Push each finished and checked piece of work: pull with rebase, re-run
  the checks, `git push origin HEAD:main`.
- Never force-push main or rewrite published history. On a rebase conflict
  keep the intent of both changes; ask before reverting someone else's code.
- Open work is tracked in GitHub issues. Close or update the issue in the
  same push that finishes it.

## Commits

- English messages: a subject line and a short body of what and why.
- No session-link trailers. `Co-Authored-By` is fine.

## Checks before a push

- `gofmt -l cmd internal build tools frontend/*.go` prints nothing
  (third_party/ is not ours).
- `go vet ./...` and `GOOS=windows go vet ./...`
- `go test ./...`; `go test -race` for the packages you touched.
- UI changes: `cd frontend && npx svelte-check --threshold warning && npx vite build`.
  frontend/dist is committed: commit the rebuilt dist with the change.
- Docs: user-visible changes go into docs/GUIDE.md and the next
  docs/release-notes/vX.Y.Z.txt.

## Never commit

- Share links (hysteria2://, hy2://), their passwords, pins, SNI, server IPs,
  subscription URLs or hosts of the users. Test links live in `.dev/`
  (gitignored). Mask auth and obfs passwords in every log line.
- Release tags are created by the maintainer.
- Details of an unfixed vulnerability: they go through the private channel
  in SECURITY.md, not into issues, commits or docs.

## Product decisions

- Statistics never record which sites were visited, in any mode: only
  programs, servers and groups. Files with sites from earlier builds are
  purged on first disk access (internal/stats: purgeSitesLocked).
