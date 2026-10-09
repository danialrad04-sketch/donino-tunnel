"""Pinned binary downloads. Verify the archive before extracting only known files."""
import hashlib
import json
import platform
import tarfile
import urllib.request
from pathlib import Path


def install_engines(names, destination, cache=None):
    arch = {"x86_64":"amd64","aarch64":"arm64","arm64":"arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("supported Linux architectures: amd64 and arm64")
    manifest = json.loads(Path(__file__).with_name("engines.json").read_text())
    destination = Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    cache = Path(cache or destination.parent / "archives")
    cache.mkdir(parents=True,exist_ok=True)
    for name in sorted(set(names)):
        spec = manifest[name]["assets"][arch]
        archive = cache / f"{name}-{arch}.tar.gz"
        if not archive.exists():
            req = urllib.request.Request(spec["url"],headers={"User-Agent":"Donino-Link/0.1"})
            # GitHub redirects releases to its release asset storage; HTTPS remains required.
            with urllib.request.urlopen(req,timeout=60) as response:
                if not response.url.startswith("https://"):
                    raise ValueError("insecure artifact redirect")
                with archive.open("wb") as output:
                    total = 0
                    while chunk := response.read(1024*1024):
                        total += len(chunk)
                        if total > 128*1024*1024:
                            raise ValueError("artifact exceeds size limit")
                        output.write(chunk)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != spec["sha256"]:
            raise ValueError(f"checksum mismatch for {name}; remove the cached archive before retrying")
        expected = {"frp":["frpc","frps"],"backpack":["backpack"],"backhaul":["backhaul"],"paqet":["paqet"]}[name]
        found = set()
        with tarfile.open(archive) as tar:
            for member in tar:
                base = Path(member.name).name
                target = "paqet" if name == "paqet" and base.startswith("paqet_linux_") else base
                if not member.isfile() or target not in expected:
                    continue
                if target in found or member.size > 128*1024*1024:
                    raise ValueError("unexpected archive member")
                payload = tar.extractfile(member).read()
                if not payload.startswith(b"\x7fELF"):
                    raise ValueError("release binary is not ELF")
                path = destination / target
                path.write_bytes(payload)
                path.chmod(0o755)
                found.add(target)
        if found != set(expected):
            raise ValueError(f"missing expected binaries for {name}")
