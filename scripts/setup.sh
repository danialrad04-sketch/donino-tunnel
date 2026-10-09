#!/usr/bin/env bash
# Interactive controller-side setup. Password is read by getpass, never an argv.
set -Eeuo pipefail
umask 077
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
python3 -m venv "$source_dir/.venv"
"$source_dir/.venv/bin/pip" install --disable-pip-version-check "$source_dir"
read -r -p 'Iran public IP/domain: ' iran_address
read -r -p 'Foreign public IP/domain: ' foreign_address
read -r -p 'Iran SSH host (root@IP): ' iran_ssh
read -r -p 'Foreign SSH host (root@IP): ' foreign_ssh
read -r -p 'SSH private key path: ' ssh_identity
read -r -p 'Public TCP port on Iran [443]: ' public_port
public_port=${public_port:-443}
read -r -p 'Origin TCP service port on foreign [443]: ' origin_port
origin_port=${origin_port:-443}
read -r -p 'New private plan directory [./private-plan]: ' plan_directory
plan_directory=${plan_directory:-./private-plan}
"$source_dir/.venv/bin/donino-link" plan --iran "$iran_address" --foreign "$foreign_address" \
  --service "main=0.0.0.0:$public_port,127.0.0.1:$origin_port" --output "$plan_directory"
echo 'Open the ports in plan.json in your provider/host firewalls before deployment.'
echo 'Verify both SSH host fingerprints through your VPS provider console and add them to known_hosts.'
read -r -p 'Type deploy to install both nodes, or press Enter to keep the plan only: ' deploy_choice
if [[ "$deploy_choice" == deploy ]]; then
  "$source_dir/.venv/bin/donino-link" deploy --plan "$plan_directory" --iran-host "$iran_ssh" --foreign-host "$foreign_ssh" --identity "$ssh_identity"
fi
