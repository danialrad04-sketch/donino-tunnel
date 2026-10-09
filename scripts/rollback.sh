#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || exit 1
current_dir=${1:-$(readlink -f /opt/donino-link/current)}
[[ "$current_dir" == /opt/donino-link/releases/* && -f "$current_dir/node/install.json" ]] || exit 1
if [[ "${2:-}" == --if-current && "$(readlink -f /opt/donino-link/current || true)" != "$current_dir" ]]; then
  echo 'Release is not current; restoration already happened or a later release is active.'
  exit 0
fi
"$current_dir/venv/bin/python" -m donino_link.host_firewall remove --release "$current_dir"
previous_dir=$(cat "$current_dir/previous-release")
while IFS= read -r service; do
  systemctl stop "$service" || true
  systemctl disable "$service" || true
  rm -f "/etc/systemd/system/$service"
done < <(python3 -c 'import json,sys; print("\n".join(reversed(json.load(open(sys.argv[1]))["units"])))' "$current_dir/node/install.json")
if [[ -z "$previous_dir" ]]; then
  rm -f /opt/donino-link/current /etc/donino-link/current
  systemctl daemon-reload
  echo 'First installation removed from active service; archived release retained.'
  exit 0
fi
[[ "$previous_dir" == /opt/donino-link/releases/* && -f "$previous_dir/node/install.json" ]] || exit 1
ln -s "$previous_dir" /opt/donino-link/.rollback-new
mv -Tf /opt/donino-link/.rollback-new /opt/donino-link/current
ln -s "$previous_dir/node" /etc/donino-link/.rollback-new
mv -Tf /etc/donino-link/.rollback-new /etc/donino-link/current
install -m 0644 "$previous_dir"/node/units/*.service /etc/systemd/system/
systemctl daemon-reload
while IFS= read -r service; do systemctl enable "$service"; systemctl restart "$service"; done < <(
  python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["units"]))' "$previous_dir/node/install.json")
echo 'Previous Donino Link release restored.'
