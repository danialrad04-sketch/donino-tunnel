"""Reproducible gzip assets, served natively by aiohttp FileResponse."""
import argparse
import gzip
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / 'donino_link' / 'web'
ASSETS = ('index.html', 'app.js', 'workspace.js', 'ecosystem.js', 'style.css')


def build(check=False):
    stale = []
    for name in ASSETS:
        source = ROOT / name
        content = bytearray(gzip.compress(source.read_bytes(), compresslevel=9, mtime=0))
        content[9] = 255
        target = source.with_suffix(source.suffix + '.gz')
        if check:
            if not target.exists() or target.read_bytes() != content:
                stale.append(name)
        else:
            target.write_bytes(content)
    if stale:
        raise SystemExit('Rebuild compressed web assets: python scripts/build-web.py (' + ', '.join(stale) + ')')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    build(parser.parse_args().check)
