#!/usr/bin/env bash
# Run locally on EACH server. No SSH key/password is copied by the operator.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Run: sudo bash scripts/setup.sh' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
role='';address='';forward=();upgrade=false
while (($#)); do
  case "$1" in
    --role) role=${2:?}; shift 2;;
    --address) address=${2:?}; shift 2;;
    --panel-port|--agent-port|--password-file) forward+=("$1" "${2:?}"); shift 2;;
    --upgrade) upgrade=true; forward+=("$1"); shift;;
    --no-open-ufw|--allow-private-peers) forward+=("$1"); shift;;
    --help) echo 'sudo bash scripts/setup.sh [--role iran|foreign] [--address IP_OR_DNS] [--panel-port PORT] [--agent-port PORT] [--upgrade]'; exit 0;;
    *) echo "Unknown option: $1" >&2; exit 1;;
  esac
done
if $upgrade && [[ -f /etc/donino-link/current/node.json ]]; then
  mapfile -t existing_node < <(python3 - <<'PYCONFIG'
import json
from pathlib import Path
cfg=json.loads(Path('/etc/donino-link/current/node.json').read_text())
print(cfg['role']);print(cfg.get('public_address',''))
PYCONFIG
)
  [[ -n "$role" ]] || role=${existing_node[0]:-}
  [[ -n "$address" ]] || address=${existing_node[1]:-}
fi
if [[ -z "$role" ]]; then
  echo 'Donino Tunnel — install this server'
  echo '1) Iran: control panel and automatic two-node installer'
  echo '2) Foreign: monitoring panel, pairing and origin health'
  read -r -p 'Server role [1/2]: ' answer
  case "$answer" in 1|iran) role=iran;; 2|foreign) role=foreign;; *) echo 'Select 1 or 2.' >&2; exit 1;; esac
fi
[[ "$role" == iran || "$role" == foreign ]] || exit 1
[[ -n "$address" ]] || read -r -p 'Public IP/domain of THIS server: ' address
. /etc/os-release
[[ "$ID" == debian && ( "$VERSION_ID" == 12 || "$VERSION_ID" == 13 ) || "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'Supported: Debian 12/13 or Ubuntu 24.04.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd is required.' >&2; exit 1; }
apt-get update -q
packages=(python3 python3-venv python3-pip openssl ca-certificates openssh-client)
[[ "$role" != foreign ]] || packages+=(openssh-server)
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${packages[@]}"
if [[ "$role" == foreign ]]; then
  ssh-keygen -A
  /usr/sbin/sshd -t
  systemctl enable --now ssh.service
fi
stage=$(mktemp -d /var/tmp/donino-setup-XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
cp -a "$source_dir/donino_link" "$source_dir/pyproject.toml" "$stage/"
python3 -m venv "$stage/venv"
install -d -m 0700 /var/cache/donino-link/pip
"$stage/venv/bin/pip" --cache-dir /var/cache/donino-link/pip install --disable-pip-version-check "$stage"
"$stage/venv/bin/donino-link" init-node --role "$role" --address "$address" "${forward[@]}"
echo 'Open the printed HTTP panel URL. On foreign generate a pairing code; enter it in Iran.'
echo 'Provider firewall: allow the panel port, foreign pairing TCP port (default 9444), and the tunnel ports shown by the panel.'
