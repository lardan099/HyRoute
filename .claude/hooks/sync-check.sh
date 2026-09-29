#!/bin/sh
# Two Claude sessions work on this repo at once, both on main. Before
# every prompt this tells Claude what the other one has pushed since, so
# that it works on the current code. Silent when there is nothing new or
# the network is down.
cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
if command -v timeout >/dev/null 2>&1; then
	timeout 20 git fetch -q origin main 2>/dev/null || exit 0
else
	git fetch -q origin main 2>/dev/null || exit 0
fi
behind=$(git rev-list --count HEAD..origin/main 2>/dev/null) || exit 0
[ "${behind:-0}" -gt 0 ] || exit 0
echo "origin/main has $behind commit(s) that this working copy does not:"
git log --format='  %h %an: %s' HEAD..origin/main | head -20
echo "Before any work: git pull --rebase origin main (commit or stash first), then read docs/HANDOFF.md."
exit 0
