#!/usr/bin/env bash
# Run on the already-installed Iran gateway. No credentials on the command line.
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run with sudo on the Iran server.' >&2; exit 1; }
http=0;port=8090;host=''
while (($#)); do
  case "$1" in
    --http) http=1;shift;;
    --port) port=${2:?Missing port};shift 2;;
    --host) host=${2:?Missing public IP/domain};shift 2;;
    *) echo 'Usage: sudo bash scripts/expose-panel.sh --http --host PUBLIC_IP [--port 8090]' >&2;exit 1;;
  esac
done
[[ $http == 1 ]] || { echo 'This helper needs an explicit --http flag.' >&2;exit 1; }
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || exit 1
cli=/opt/donino-link/current/venv/bin/donino-link
config=/etc/donino-link/current/node.json
[[ -x "$cli" && -f "$config" ]] || { echo 'Install Donino Tunnel on the Iran node first.' >&2;exit 1; }
args=(panel-access --config "$config" --listen "0.0.0.0:$port" --http)
[[ -n "$host" ]] && args+=(--public-host "$host")
"$cli" "${args[@]}"
panel_ready() {
  /opt/donino-link/current/venv/bin/python - "$port" <<'PY'
import sys, time, urllib.request
url = f'http://127.0.0.1:{sys.argv[1]}/healthz'
for attempt in range(10):
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            if response.status == 200:
                print(response.read().decode())
                sys.exit(0)
    except (OSError, ValueError):
        pass
    time.sleep(0.5)
sys.exit('Panel health check failed.')
PY
}
if ! systemctl restart donino-link.service || ! systemctl is-active --quiet donino-link.service || ! panel_ready; then
  echo 'Panel activation failed; restoring previous configuration.' >&2
  cp -p -- "$config.panel-backup" "$config"
  chown root:donino-link "$config";chmod 0640 "$config"
  systemctl restart donino-link.service || true
  exit 1
fi
echo
if [[ -n "$host" ]]; then
  url_host=$host
  [[ "$host" == *:* && "$host" != \[*\] ]] && url_host="[$host]"
  echo "Panel URL: http://$url_host:$port"
else
  echo "Panel listens on HTTP port $port. Use your actual server IP/domain in the browser."
fi
echo "If a host/provider firewall is enabled, allow inbound TCP $port there. The helper does not alter firewall rules."
