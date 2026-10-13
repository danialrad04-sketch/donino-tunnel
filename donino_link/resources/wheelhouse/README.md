# Embedded Python dependencies

These wheels make terminal setup and both node payloads independent of PyPI.
Runtime dependencies remain aiohttp 3.14.4 and PyYAML 6.0.3. Tomli 2.4.1 is
bundled for reading vendor TOML configurations on Python 3.10. The complete
transitive dependency set includes Python 3.10's conditional async-timeout.
Build tools are bundled too, so local package builds need no downloads.

All wheels use the `py3-none-any` tag and contain no native extensions, allowing
the same installer on Python 3.10–3.14 and amd64/arm64. They use the projects'
supported Python implementations rather than optional C acceleration. This
trades some transport throughput for portability; measure demanding deployments.
Package licenses are included inside the wheels.

`SHA256SUMS` is checked before creating the environment. `sources.json` records
the upstream release URLs and SHA256 values verified when vendoring. Fifteen
wheels are unmodified PyPI pure Python wheels. PyYAML's upstream source archive
was built without its optional LibYAML extension:

```bash
PYYAML_FORCE_LIBYAML=0 python setup.py bdist_wheel
```

Do not relabel a native wheel as portable. To update dependencies, fetch the
upstream pure Python wheels, verify their release hashes, rebuild PyYAML from a
verified source archive if needed, refresh both manifests, and run the offline
installation regression and the full Python CI matrix. Rebuild
`install-donino.sh` with `python scripts/build-standalone.py`.

The Python installer deliberately ignores host pip caches and indexes. APT,
selected external tunnel engines, and optional Ubuntu BrowserLink downloads
still need network access. Existing external Paqet configuration is unaffected
by this dependency installer.
