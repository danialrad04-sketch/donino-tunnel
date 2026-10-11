# Shared platform/dependency handling for terminal and two-node installers.
# Sourcing this file does not modify the host.
donino_platform() {
  local os_release=${1:-/etc/os-release}
  . "$os_release"
  DONINO_APT_OPTIONS=()
  DONINO_EOL=false
  DONINO_CODENAME=''
  case "$ID:${VERSION_ID:-}" in
    debian:12|debian:13) ;;
    ubuntu:22.04) DONINO_CODENAME=jammy ;;
    ubuntu:22.10) DONINO_CODENAME=kinetic; DONINO_EOL=true ;;
    ubuntu:23.04) DONINO_CODENAME=lunar; DONINO_EOL=true ;;
    ubuntu:23.10) DONINO_CODENAME=mantic; DONINO_EOL=true ;;
    ubuntu:24.04) DONINO_CODENAME=noble ;;
    ubuntu:24.10) DONINO_CODENAME=oracular; DONINO_EOL=true ;;
    ubuntu:25.04) DONINO_CODENAME=plucky; DONINO_EOL=true ;;
    ubuntu:25.10) DONINO_CODENAME=questing; DONINO_EOL=true ;;
    ubuntu:26.04) DONINO_CODENAME=resolute ;;
    ubuntu:26.10) DONINO_CODENAME=stonking ;;
    *) echo 'Supported: Debian 12/13 and Ubuntu 22.04 through 26.10 (amd64/arm64, systemd).' >&2; return 1 ;;
  esac
  case "$(dpkg --print-architecture)" in
    amd64|arm64) ;;
    *) echo 'The tunnel engines require amd64 or arm64.' >&2; return 1 ;;
  esac
  command -v apt-get >/dev/null || return 1
  if $DONINO_EOL; then
    echo "Ubuntu $VERSION_ID is end-of-life. Using its signed official archive for Donino dependencies." >&2
    echo 'Existing host APT sources are kept. Archived packages receive no new security fixes.' >&2
    local archive_dir=/var/cache/donino-link/apt
    install -d -m 0755 "$archive_dir"
    local sources=$archive_dir/ubuntu-$VERSION_ID.list
    printf 'deb http://old-releases.ubuntu.com/ubuntu/ %s main restricted universe multiverse\n' \
      "$DONINO_CODENAME" "$DONINO_CODENAME-updates" "$DONINO_CODENAME-security" > "$sources"
    chmod 0644 "$sources"
    DONINO_APT_OPTIONS=(-o "Dir::Etc::sourcelist=$sources" -o 'Dir::Etc::sourceparts=-')
  fi
  echo "Platform: $ID $VERSION_ID ($(dpkg --print-architecture))"
}

donino_apt() {
  local result
  if DEBIAN_FRONTEND=noninteractive apt-get "${DONINO_APT_OPTIONS[@]}" -o Acquire::Retries=3 -o DPkg::Lock::Timeout=120 "$@"; then
    return 0
  else result=$?; fi
  # Archive migration may lag behind the end-of-life date. If the official
  # archive is not available yet, use the still-live configured host sources.
  if [[ ${1:-} == update && "$DONINO_EOL" == true && ${#DONINO_APT_OPTIONS[@]} -gt 0 ]]; then
    echo 'Archived indexes unavailable; trying the current host APT sources.' >&2
    DONINO_APT_OPTIONS=()
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=120 "$@"
  else return "$result"; fi
}

# Ubuntu's time64 transition renamed several libraries. Select real candidates,
# rather than installing obsolete names or changing system repositories.
donino_package() {
  local name candidate
  for name in "$@"; do
    candidate=$(apt-cache "${DONINO_APT_OPTIONS[@]}" policy "$name" | awk '/Candidate:/ {print $2; exit}')
    if [[ -n "$candidate" && "$candidate" != '(none)' ]]; then printf '%s\n' "$name"; return 0; fi
  done
  echo "No APT candidate for: $*" >&2; return 1
}

donino_browser() {
  local python=$1
  if [[ "$ID" == debian ]]; then
    donino_apt install -y -q --no-install-recommends chromium chromium-sandbox nodejs
    DONINO_CHROMIUM=/usr/bin/chromium
    return
  fi
  # Native Chromium from the pinned Microsoft Playwright distribution supports
  # both CPU architectures and avoids Ubuntu's snap/systemd confinement conflict.
  local libraries=(nodejs libnss3 libnspr4 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libx11-6 libxcb1 libxext6 libxshmfence1 fonts-liberation fonts-noto-color-emoji)
  local alternatives names
  for alternatives in 'libasound2t64 libasound2' 'libglib2.0-0t64 libglib2.0-0' 'libatk1.0-0t64 libatk1.0-0' 'libatk-bridge2.0-0t64 libatk-bridge2.0-0' 'libcups2t64 libcups2' 'libatspi2.0-0t64 libatspi2.0-0'; do
    read -r -a names <<< "$alternatives"
    libraries+=("$(donino_package "${names[@]}")")
  done
  donino_apt install -y -q --no-install-recommends "${libraries[@]}"
  "$python" -m pip --cache-dir /var/cache/donino-link/pip install --disable-pip-version-check 'playwright==1.63.0'
  install -d -m 0755 /opt/donino-link/browsers
  PLAYWRIGHT_BROWSERS_PATH=/opt/donino-link/browsers "$python" -m playwright install --no-shell chromium
  DONINO_CHROMIUM=$(PLAYWRIGHT_BROWSERS_PATH=/opt/donino-link/browsers "$python" -c 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); print(p.chromium.executable_path); p.stop()')
  [[ "$DONINO_CHROMIUM" == /opt/donino-link/browsers/*/chrome && -x "$DONINO_CHROMIUM" ]] || { echo 'Native Chromium executable was not installed.' >&2; return 1; }
  chmod -R a+rX /opt/donino-link/browsers
  # Allow namespaces only for Donino's root-owned browser binaries. Never
  # disable AppArmor or its namespace restriction for other host applications.
  local restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
  if [[ -f "$restriction" && $(cat "$restriction") == 1 ]]; then
    donino_apt install -y -q --no-install-recommends apparmor
    cat > /etc/apparmor.d/donino-browser <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>
profile donino-browser /opt/donino-link/browsers/**/chrome flags=(unconfined) {
  userns,
}
PROFILE
    chmod 0644 /etc/apparmor.d/donino-browser
    apparmor_parser -r /etc/apparmor.d/donino-browser
  fi
}
