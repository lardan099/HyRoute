#!/bin/sh
# Installs or updates HyRoute Server on Linux with systemd (Debian, Ubuntu
# and the like):
#
#   curl -fsSL https://github.com/lardan099/HyRoute/releases/latest/download/install-server.sh | sudo sh
#
# The latest release; HYROUTE_SERVER_VERSION=v1.3.7 picks another. The
# package is checked against the release's SHA256SUMS. The program goes to
# /usr/local/bin and the service to /etc/systemd/system; the data in
# /var/lib/hyroute-server is never touched. Running it again updates the
# panel and restarts it. docs/SERVER_MANAGER.md, «Установка».
set -eu

repo=lardan099/HyRoute
bin=/usr/local/bin/hyroute-server
unit=/etc/systemd/system/hyroute-server.service
data=/var/lib/hyroute-server
# The service file this script writes starts with this: one that does not
# was written by hand and is left as it is.
mark='# HyRoute Server. Installed by install-server.sh'

fail() {
  echo "hyroute-server: $*" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || fail "этот скрипт — для Linux. Сборка для Windows лежит в релизе: https://github.com/$repo/releases/latest"
[ "$(id -u)" = 0 ] || fail "нужны права root: запустите скрипт через sudo"
command -v systemctl >/dev/null 2>&1 || fail "нужен systemd (не найден systemctl)"
for c in curl tar sha256sum; do
  command -v "$c" >/dev/null 2>&1 || fail "нужна программа $c (Debian, Ubuntu: apt install $c)"
done

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "процессор $(uname -m) не поддерживается: сборки есть для x86_64 и arm64" ;;
esac

tag=${HYROUTE_SERVER_VERSION:-}
if [ -z "$tag" ]; then
  # github.com answers /releases/latest with a redirect to the tag's page.
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
    fail "не удалось узнать последнюю версию на github.com"
  tag=${url##*/}
fi
case "$tag" in
  v[0-9]*) ;;
  *) fail "непонятная версия: $tag" ;;
esac
case "$tag" in
  *[!0-9A-Za-z.-]*) fail "непонятная версия: $tag" ;;
esac

name=hyroute-server-${tag#v}-linux-$arch.tar.gz
base=https://github.com/$repo/releases/download/$tag
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Скачиваю HyRoute Server $tag ($arch)…"
curl -fsSL --retry 3 -o "$tmp/$name" "$base/$name" ||
  fail "в релизе $tag нет сборки $name"
curl -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" ||
  fail "в релизе $tag нет SHA256SUMS: без него сборку не проверить"
want=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "сборки $name нет в SHA256SUMS"
got=$(sha256sum "$tmp/$name" | cut -d ' ' -f 1)
[ "$want" = "$got" ] || fail "контрольная сумма $name не совпала: файл повреждён или подменён"
mkdir "$tmp/pkg"
tar -xzf "$tmp/$name" -C "$tmp/pkg"
"$tmp/pkg/hyroute-server" version >/dev/null 2>&1 || fail "скачанная программа не запускается на этой машине"

fresh=yes
[ -e "$unit" ] && fresh=no
newdb=yes
[ -e "$data/hyroute-server.db" ] && newdb=no

# Replaced by a rename: the running panel keeps its file until it restarts.
install -m 0755 "$tmp/pkg/hyroute-server" "$bin.new"
mv -f "$bin.new" "$bin"
ours=$fresh
case "$(head -n 1 "$unit" 2>/dev/null)" in
  "$mark"*) ours=yes ;;
esac
if [ "$ours" = yes ]; then
  install -m 0644 "$tmp/pkg/hyroute-server.service" "$unit"
else
  echo "Файл службы $unit написан не этим скриптом: оставляю его как есть."
fi
systemctl daemon-reload

if [ "$fresh" = yes ]; then
  systemctl enable --now hyroute-server
elif systemctl is-active --quiet hyroute-server; then
  systemctl restart hyroute-server
else
  echo "HyRoute Server $tag установлен. Служба не запущена; запустить: systemctl start hyroute-server"
  exit 0
fi

# The panel writes the setup code on its first start.
i=0
while [ "$i" -lt 20 ]; do
  systemctl is-active --quiet hyroute-server || break
  # Two seconds to see it does not fall over; a new one, to its setup code.
  if [ "$i" -ge 2 ] && { [ "$newdb" = no ] || [ -s "$data/setup-token" ]; }; then
    break
  fi
  sleep 1
  i=$((i + 1))
done
if ! systemctl is-active --quiet hyroute-server; then
  journalctl -u hyroute-server -n 20 --no-pager >&2 || true
  fail "служба не запустилась (журнал выше; весь — journalctl -u hyroute-server)"
fi

# Where this shell's SSH session came in: the address to tunnel to.
host=
if [ -n "${SSH_CONNECTION:-}" ]; then
  # shellcheck disable=SC2086 # "client port server port": split on purpose
  set -- $SSH_CONNECTION
  host=${3:-}
fi
user=${SUDO_USER:-root}

echo
echo "HyRoute Server $tag установлен и работает."
echo
echo "Панель слушает 127.0.0.1:8480 только на этой машине. Со своего компьютера откройте SSH-туннель:"
echo
echo "    ssh -L 8480:127.0.0.1:8480 $user@${host:-адрес-этого-сервера}"
echo
echo "и затем в браузере http://127.0.0.1:8480 (если вы за этой машиной — сразу этот адрес)."
if [ -s "$data/setup-token" ]; then
  echo
  echo "Код первого запуска: $(cat "$data/setup-token")"
  echo "Введите его в панели и задайте имя и пароль владельца."
fi
if [ "$newdb" = yes ] && [ -e "$data/master.key" ]; then
  echo
  echo "Сохраните копию $data/master.key (например, в менеджере паролей):"
  echo "без него базу панели не восстановить."
fi
echo
echo "Обновить панель: эта же команда. Журнал: journalctl -u hyroute-server -f"
