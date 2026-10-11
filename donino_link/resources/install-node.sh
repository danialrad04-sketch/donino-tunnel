#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
source_dir=$(realpath -- "${1:?Pass the extracted payload directory}")
[[ -f "$source_dir/node/install.json" && -f "$source_dir/pyproject.toml" ]] || exit 1
command -v systemctl >/dev/null
[[ -d /run/systemd/system ]] || { echo 'A running systemd is required.' >&2; exit 1; }
mode=${2:---all}
[[ "$mode" == --all || "$mode" == --prepare || "$mode" == --activate ]] || exit 1
release_id=${3:-$(date -u +%Y%m%dT%H%M%SZ)-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')}
[[ "$release_id" =~ ^[A-Za-z0-9-]{8,80}$ ]] || exit 1
release_dir=/opt/donino-link/releases/$release_id
previous_dir=$(readlink -f /opt/donino-link/current || true)
switched=0
rollback_on_error() {
  echo 'Installation failed; reverting Donino Link service changes.' >&2
  if [[ -e "$release_dir/venv/bin/python" ]]; then
    namei -l "$release_dir/venv/bin/python" >&2 || true
    runuser -u donino-link -- "$release_dir/venv/bin/python" --version >&2 || true
  fi
  if [[ $switched == 1 ]]; then bash "$release_dir/scripts/rollback.sh" "$release_dir" || true; fi
}
trap rollback_on_error ERR

if [[ "$mode" != --activate ]]; then
[[ ! -e "$release_dir" ]] || { echo 'Staged release already exists.' >&2; exit 1; }
source "$source_dir/donino_link/resources/platform.sh"
donino_platform
donino_apt update -q
donino_apt install -y -q --no-install-recommends python3 python3-venv python3-pip openssl iproute2 iputils-ping iptables ca-certificates openssh-client util-linux
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
id donino-link >/dev/null 2>&1 || useradd --system --user-group --home /var/lib/donino-link --shell /usr/sbin/nologin donino-link
install -d -m 0750 -o root -g donino-link /etc/donino-link /opt/donino-link /opt/donino-link/releases
install -d -m 0700 -o donino-link -g donino-link /var/lib/donino-link
install -d -m 0750 -o root -g donino-link "$release_dir"
cp -a "$source_dir/donino_link" "$source_dir/scripts" "$source_dir/pyproject.toml" "$source_dir/node" "$release_dir/"
python3 -m venv "$release_dir/venv"
install -d -m 0700 /var/cache/donino-link/pip
"$release_dir/venv/bin/pip" --cache-dir /var/cache/donino-link/pip install --disable-pip-version-check "$release_dir"
if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("browser") else 1)' "$release_dir/node/install.json"; then
  donino_browser "$release_dir/venv/bin/python"
  "$release_dir/venv/bin/python" - "$release_dir/node/transports/browser-wss.json" "$DONINO_CHROMIUM" <<'PYBROWSER'
import sys
from donino_link.config import atomic_json
from donino_link.provision import read_json
cfg=read_json(sys.argv[1]);cfg['chromium']=sys.argv[2];atomic_json(sys.argv[1],cfg)
PYBROWSER
fi
engines=$(/usr/bin/python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["engines"]))' "$release_dir/node/install.json")
fetch_args=()
for engine in $engines; do fetch_args+=(--engine "$engine"); done
install -d -m 0700 /var/cache/donino-link
if ((${#fetch_args[@]})); then
  "$release_dir/venv/bin/donino-link" fetch-engines "${fetch_args[@]}" --destination "$release_dir/bin" --cache /var/cache/donino-link
fi
"$release_dir/venv/bin/donino-link" prepare-paqet --node "$release_dir/node"
"$release_dir/venv/bin/python" -m donino_link.bootstrap --preserve "$release_dir/node"

chown -R root:donino-link "$release_dir"
find "$release_dir" -type d -exec chmod 0750 {} +
find "$release_dir" -type f -exec chmod 0640 {} +

find "$release_dir/venv/bin" -type f -exec chmod 0750 {} +
[[ ! -d "$release_dir/bin" ]] || find "$release_dir/bin" -type f -exec chmod 0750 {} +
"$release_dir/venv/bin/donino-link" validate --config "$release_dir/node/node.json"
for config in "$release_dir"/node/transports/frp-*.toml; do
  [[ -e "$config" ]] || continue
  role=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["role"])' "$release_dir/node/install.json")
  binary=frpc; [[ "$role" == iran ]] && binary=frps
  staged_config=$(mktemp "$release_dir/verify-XXXX.toml")
  sed "s|/etc/donino-link/current/|$release_dir/node/|g" "$config" > "$staged_config"
  "$release_dir/bin/$binary" verify -c "$staged_config"
  rm -f "$staged_config"
done
# Non-mutating port/resource checks, including Paqet interface/MAC discovery.
"$release_dir/venv/bin/python" -m donino_link.preflight --node "$release_dir/node"
printf '%s\n' ready > "$release_dir/prepared"
fi
if [[ "$mode" == --prepare ]]; then
  trap - ERR
  echo "Prepared $release_dir. No active release switched."
  exit 0
fi
[[ -f "$release_dir/prepared" && -f "$release_dir/node/install.json" ]] || { echo 'Release was not prepared.' >&2; exit 1; }
previous_dir=$(readlink -f /opt/donino-link/current || true)
printf '%s\n' "$previous_dir" > "$release_dir/previous-release"
# Only our named units are replaced. The old release stays available for rollback.
switched=1
if [[ -n "$previous_dir" && -f "$previous_dir/node/install.json" ]]; then
  while IFS= read -r service; do systemctl stop "$service"; systemctl disable "$service"; done < <(
    python3 -c 'import json,sys; print("\n".join(reversed(json.load(open(sys.argv[1]))["units"])))' "$previous_dir/node/install.json")
fi
ln -sfn "$release_dir" /opt/donino-link/.current-new
mv -Tf /opt/donino-link/.current-new /opt/donino-link/current
ln -sfn "$release_dir/node" /etc/donino-link/.current-new
mv -Tf /etc/donino-link/.current-new /etc/donino-link/current
install -m 0644 "$release_dir"/node/units/*.service /etc/systemd/system/
systemctl daemon-reload
"$release_dir/venv/bin/python" -m donino_link.host_firewall apply --node "$release_dir/node" --release "$release_dir" --tag "$release_id"
while IFS= read -r service; do
  systemctl enable "$service"
  systemctl restart "$service"
done < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["units"]))' "$release_dir/node/install.json")
sleep 2
while IFS= read -r service; do systemctl is-active --quiet "$service"; done < <(
  python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["units"]))' "$release_dir/node/install.json")
role=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["role"])' "$release_dir/node/install.json")
if [[ "$role" == iran ]]; then
  "$release_dir/venv/bin/donino-link" control-enable
else
  if python3 -c 'import json,sys;sys.exit(0 if "panel" in json.load(open(sys.argv[1])) else 1)' "$release_dir/node/node.json"; then
    "$release_dir/venv/bin/python" -c 'from donino_link.peer import enable_agent;enable_agent()'
  fi
fi
trap - ERR
echo 'Donino Link services started. Open only the ports listed in plan.json in provider/host firewalls; then run doctor.'
