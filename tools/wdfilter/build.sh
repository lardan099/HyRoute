#!/bin/sh
# Builds tools/wdfilter/wdfilter from the WinDivert v2.2.2 sources.
#   WINDIVERT_SRC=/path/to/windivert ./tools/wdfilter/build.sh
# Then run: HYROUTE_WDFILTER=$PWD/tools/wdfilter/wdfilter go test ./internal/divert/
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src=${WINDIVERT_SRC:-}
if [ -z "$src" ]; then
    src=$(mktemp -d)
    git clone -q --depth 1 --branch v2.2.2 https://github.com/basil00/WinDivert "$src"
fi
work=$(mktemp -d)
# windivert.c holds the string helpers the compiler needs; pull out the
# prototypes and the helper bodies (stable line ranges in v2.2.2).
sed -n 61,75p "$src/dll/windivert.c" > "$work/protos.c"
echo '#define IPPROTO_MH 135' >> "$work/protos.c"
sed -n 752,990p "$src/dll/windivert.c" > "$work/strfuncs.c"
cc -w -fgnu89-inline -I"$src/include" -I"$src/dll" -I"$work" -I"$here/shim" \
    -DIPPROTO_HOPOPTS=0 -DIPPROTO_ICMP=1 -DIPPROTO_TCP=6 -DIPPROTO_UDP=17 \
    -DIPPROTO_ROUTING=43 -DIPPROTO_FRAGMENT=44 -DIPPROTO_AH=51 \
    -DIPPROTO_ICMPV6=58 -DIPPROTO_NONE=59 -DIPPROTO_DSTOPTS=60 \
    "$here/main.c" -o "$here/wdfilter"
echo "built $here/wdfilter"
