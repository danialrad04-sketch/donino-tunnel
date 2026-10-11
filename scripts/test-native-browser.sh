#!/usr/bin/env bash
# Disposable GitHub runner only: test Ubuntu's real AppArmor policy unchanged.
set -Eeuo pipefail
[[ ${GITHUB_ACTIONS:-} == true && $(id -u) == 0 ]] || { echo 'CI runner/root required.' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$source_dir/donino_link/resources/platform.sh"
donino_platform
donino_apt update -q
donino_apt install -y -q --no-install-recommends python3 python3-venv openssl iproute2 util-linux
id donino-link >/dev/null 2>&1 || useradd --system --user-group --home /var/lib/donino-link --shell /usr/sbin/nologin donino-link
install -d -m 0700 -o donino-link -g donino-link /var/lib/donino-link
python3 -m venv /opt/donino-link/native-browser-test
python=/opt/donino-link/native-browser-test/bin/python
"$python" -m pip install "$source_dir"
flag=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
before=$(cat "$flag" 2>/dev/null || true)
donino_browser "$python"
[[ "$before" == "$(cat "$flag" 2>/dev/null || true)" ]]
"$python" - "$DONINO_CHROMIUM" <<'PY'
import json,sys,tempfile
from pathlib import Path
from donino_link.preflight import check
with tempfile.TemporaryDirectory() as tmp:
    node=Path(tmp);(node/'transports').mkdir()
    (node/'install.json').write_text(json.dumps({'role':'iran','browser':True,'listeners':[]}))
    (node/'transports/browser-wss.json').write_text(json.dumps({'chromium':sys.argv[1]}))
    print(check(node))
PY
runuser -u donino-link -- "$python" "$source_dir/scripts/test-browser.py" --chromium "$DONINO_CHROMIUM" --output /var/lib/donino-link/browser-results.json
cp /var/lib/donino-link/browser-results.json "$source_dir/native-browser-results.json"
