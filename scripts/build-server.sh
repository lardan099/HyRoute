#!/bin/sh
# Builds the HyRoute Server packages of a release into dist/server:
#   hyroute-server-<version>-linux-amd64.tar.gz    hyroute-server, hyroute-server.service
#   hyroute-server-<version>-linux-arm64.tar.gz
#   hyroute-server-<version>-windows-amd64.zip     hyroute-server.exe
#   install-server.sh, SHA256SUMS
# SQLite is pure Go: no C compiler, any OS builds them all. The admin UI is
# the one in web/admin/dist (the release workflow rebuilds it first).
#
#   HYROUTE_VERSION=v1.3.7 sh scripts/build-server.sh
set -eu
cd "$(dirname "$0")/.."

version=${HYROUTE_VERSION:-$(git describe --tags --always --dirty)}
# The version names files and goes into -ldflags: a tag may hold anything.
case "$version" in
  '' | *[!0-9A-Za-z.-]*) echo "build-server: bad version: $version" >&2; exit 1 ;;
esac
out=$(pwd)/dist/server
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in linux/amd64 linux/arm64 windows/amd64; do
  goos=${target%/*}
  goarch=${target#*/}
  name=hyroute-server-${version#v}-$goos-$goarch
  dir=$work/$name
  mkdir -p "$dir"
  exe=hyroute-server
  [ "$goos" = windows ] && exe=hyroute-server.exe
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$dir/$exe" ./cmd/hyroute-server
  if [ "$goos" = windows ]; then
    (cd "$dir" && zip -q -X "$out/$name.zip" "$exe")
  else
    cp build/linux/hyroute-server.service "$dir/"
    tar -czf "$out/$name.tar.gz" -C "$dir" --owner=0 --group=0 --numeric-owner "$exe" hyroute-server.service
  fi
done
cp scripts/install-server.sh "$out/"
(cd "$out" && sha256sum -- *.tar.gz *.zip install-server.sh > SHA256SUMS)
cat "$out/SHA256SUMS"
