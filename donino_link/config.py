"""Strict, data-only configuration. No executable commands from the web API."""
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path


def atomic_json(path, data, preserve_permissions=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if preserve_permissions and path.exists() else None
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        if previous:
            os.fchown(fd, previous.st_uid, previous.st_gid)
            os.fchmod(fd, previous.st_mode & 0o777)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def endpoint(value):
    if not isinstance(value, str) or len(value) > 300:
        raise ValueError("invalid endpoint")
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
        if not sep:
            raise ValueError("IPv6 endpoint needs brackets")
    else:
        host, sep, port = value.rpartition(":")
        if not sep or ":" in host:
            raise ValueError("endpoint must be host:port")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid endpoint port")
    if not re.fullmatch(r"[A-Za-z0-9_.:%-]+", host):
        raise ValueError("invalid endpoint host")
    return host, int(port)


def loopback(value):
    host, _ = endpoint(value)
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_config(path):
    data = json.loads(Path(path).read_text())
    if data.get("schema") != 1 or data.get("role") not in ("iran", "foreign"):
        raise ValueError("schema=1 and role iran/foreign are required")
    if not re.fullmatch(r"[0-9a-f]{64}", data.get("health_key", "")):
        raise ValueError("health_key must be 32 random bytes in hex")
    if data["role"] == "foreign":
        if not loopback(data["health_listen"]):
            raise ValueError("foreign health responder must bind a literal loopback IP")
        if data.get('udp_health_listen') and not loopback(data['udp_health_listen']):raise ValueError('UDP health must bind loopback')
        for target in data.get('targets',{}).values():
            if not loopback(target):
                raise ValueError('foreign targets must be literal loopback')
        if 'panel' in data: validate_panel(data['panel'])
        return data
    if not data.get("services") or not data.get("paths"):
        native=data.get('native_only') is True and data.get('services')==[] and len(data.get('paths',[]))==1 and data['paths'][0].get('id')=='paqet'
        if not native and (data.get('bootstrap') is not True or data.get('services') != [] or data.get('paths') != []):
            raise ValueError("at least one service and one path are required")
    if not isinstance(data['services'],list) or not isinstance(data['paths'],list):
        raise ValueError("at least one service and one path are required")
    names, listeners = set(), set()
    for s in data["services"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", s["id"]) or s["id"] in names:
            raise ValueError("service IDs must be unique safe names")
        names.add(s["id"])
        endpoint(s["listen"])
        if s["listen"] in listeners:
            raise ValueError("duplicate listener")
        listeners.add(s["listen"])
    ids = set()
    for p in data["paths"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", p["id"]) or p["id"] in ids:
            raise ValueError("path IDs must be unique safe names")
        ids.add(p["id"])
        if not loopback(p["health"]):
            raise ValueError("path health must be loopback")
        if p.get('udp_health') and not loopback(p['udp_health']):raise ValueError('UDP health must be loopback')
        if set(p["backends"]) != names:
            raise ValueError("every path needs every service")
        for value in p["backends"].values():
            if not loopback(value):
                raise ValueError("path backends must be loopback")
        if not isinstance(p.get("priority", 100), int) or not 0 <= p.get("priority", 100) <= 1000:
            raise ValueError("priority must be between 0 and 1000")
    pol = data.setdefault("policy", {})
    for key, default, lo, hi in [("probe_interval", 3, 0.1, 300), ("probe_timeout", 2, 0.05, 60),
                                ("failures", 3, 1, 50), ("recoveries", 2, 1, 50),
                                ("connect_timeout", 2, 0.05, 60), ("idle_timeout", 300, 1, 86400),
                                ("max_connections", 2048, 1, 100000)]:
        v = pol.setdefault(key, default)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise ValueError(f"invalid policy {key}")
        if key in ("failures", "recoveries", "max_connections") and not isinstance(v, int):
            raise ValueError(f"{key} must be an integer")
    validate_panel(data['panel'])
    return data


def validate_panel(panel):
    if not isinstance(panel,dict): raise ValueError('invalid panel configuration')
    endpoint(panel["listen"])
    if bool(panel.get('tls_cert')) != bool(panel.get('tls_key')):
        raise ValueError('panel TLS certificate and key must be set together')
    if not isinstance(panel.get('allow_insecure_http',False),bool):
        raise ValueError('allow_insecure_http must be boolean')
    if not loopback(panel["listen"]) and not (panel.get("tls_cert") and panel.get("tls_key")) and panel.get('allow_insecure_http') is not True:
        raise ValueError('public panel requires TLS or an explicit allow_insecure_http=true setting')
