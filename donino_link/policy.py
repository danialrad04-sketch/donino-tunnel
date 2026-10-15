"""Typed live gateway policy; persisted independently of generated releases."""
LIMITS = {
    'probe_interval': (3, .1, 300, False),
    'probe_timeout': (2, .05, 60, False),
    'failures': (3, 1, 50, True),
    'recoveries': (2, 1, 50, True),
    'connect_timeout': (2, .05, 60, False),
    'idle_timeout': (300, 1, 86400, False),
    'max_connections': (2048, 1, 100000, True),
    'max_udp_associations': (128, 1, 128, True),
    'udp_idle_timeout': (120, 10, 600, False),
    'memory_reserve_mb': (64, 16, 4096, True),
}


def validate(value):
    if not isinstance(value, dict) or set(value) - set(LIMITS):
        raise ValueError('unknown policy setting')
    result = {}
    for key, (default, low, high, integral) in LIMITS.items():
        setting = value.get(key, default)
        if isinstance(setting, bool) or not isinstance(setting, (int, float)) or not low <= setting <= high or (integral and not isinstance(setting, int)):
            raise ValueError('invalid policy ' + key)
        result[key] = setting
    return result
