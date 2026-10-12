# Shared offline Python installation for terminal setup and both node releases.
# All wheels are shipped with the runtime; never query PyPI or host pip caches.
donino_python_runtime() {
  local source_dir=$1
  local interpreter=${2:-python3}
  local wheels=$source_dir/donino_link/resources/wheelhouse
  [[ -f "$wheels/SHA256SUMS" ]] || { echo 'Embedded Python packages are missing. Download the complete new installer.' >&2; return 1; }
  (cd "$wheels" && sha256sum --check --strict SHA256SUMS) || return 1
  "$interpreter" -m venv "$source_dir/venv" || return 1
  local python=$source_dir/venv/bin/python
  local options=(--isolated --disable-pip-version-check --no-cache-dir --no-index --find-links "$wheels")
  echo 'Installing embedded Python dependencies offline (no PyPI access).'
  "$python" -m pip install "${options[@]}" 'setuptools==84.0.0' 'wheel==0.48.0' 'packaging==26.2' || return 1
  "$python" -m pip install "${options[@]}" 'aiohttp==3.14.4' 'PyYAML==6.0.3' || return 1
  "$python" -m pip install "${options[@]}" --no-build-isolation --no-deps "$source_dir" || return 1
  "$python" -m pip --isolated check || return 1
}
