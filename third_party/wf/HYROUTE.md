# tailscale/wf, patched

Copy of github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
(BSD-3-Clause, see LICENSE), used through a `replace` in HyRoute's go.mod.
Tests, command-line tools and generators are left out.

Change: `arena.Alloc` in malloc.go rounds every allocation up to pointer
alignment. Without it a struct holding pointers could be stored at an
unaligned address, and the Go runtime aborts the process when that
happens during a garbage collection ("bulkBarrierPreWrite: unaligned
arguments"). HyRoute crashed this way when arming the kill switch.
