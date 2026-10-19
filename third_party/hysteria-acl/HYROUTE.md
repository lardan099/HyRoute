# Hysteria ACL, copied

Copy of `extras/outbounds/acl` (with `v2geo`) from
github.com/apernet/hysteria at tag app/v2.12.3
(e1366b173ccf5706e1e4630fe8aa654a4b574085), MIT, see LICENSE. The server
manager matches rules with it exactly as a Hysteria server does: "check a
rule", dry-run and lint. The extras module cannot be required as is: its
go.mod replaces core with a relative path.

Change: the import path of `v2geo` only.

Left out: compile_test.go, matchers_v2geo_test.go and v2geo/load_test.go,
which need the 14 MB geoip.dat and geosite.dat of the upstream repository.
HyRoute's own tests (internal/srvmgr/acl) cover compiling and geo
matching with small generated databases.

To update: copy the same files from the new tag, change the import path
again, update the tag and commit above, and run the tests.
