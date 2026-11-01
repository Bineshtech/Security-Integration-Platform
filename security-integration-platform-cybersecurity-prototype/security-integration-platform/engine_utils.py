"""Stdlib-only helpers: schedule parsing, date/type conversion, mapping specs, config-format normalisation."""
from __future__ import annotations
import copy, re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable

_SCHED = re.compile(r"^\s*(?:every\s+)?(\d+)\s*(s|sec|secs|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?)\s*$", re.I)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}

def parse_schedule(text: str | None, minimum: int = 30, maximum: int = 7 * 86400) -> int | None:
    """'every 15 minutes' / '15m' / '1h' -> seconds. None for empty. ValueError if invalid."""
    if text is None or not str(text).strip(): return None
    m = _SCHED.match(str(text))
    if not m: raise ValueError(f"Invalid schedule {text!r}. Use e.g. '15m', '1h', 'every 30 minutes'.")
    secs = int(m.group(1)) * _UNIT[m.group(2)[0].lower()]
    if secs < minimum or secs > maximum: raise ValueError(f"Schedule must be between {minimum} seconds and {maximum // 86400} days.")
    return secs

def convert_date(value: Any, fmt: str | None = None) -> str | None:
    """Epoch (s/ms), ISO-8601, RFC-2822 or custom strptime format -> ISO-8601 UTC string."""
    if value is None or value == "": return None
    if isinstance(value, bool): raise ValueError(f"Cannot convert {value!r} to a date")
    dt = None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"-?\d+(\.\d+)?", value.strip())):
        n = float(value)
        if abs(n) > 1e11: n /= 1000.0
        try: dt = datetime.fromtimestamp(n, tz=timezone.utc)
        except (OverflowError, OSError, ValueError): raise ValueError(f"Epoch out of range: {value!r}")
    elif isinstance(value, str):
        s = value.strip()
        if fmt:
            try: dt = datetime.strptime(s, fmt)
            except ValueError: raise ValueError(f"Date {value!r} does not match format {fmt!r}")
        else:
            try: dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                try: dt = parsedate_to_datetime(s)
                except (TypeError, ValueError, IndexError): raise ValueError(f"Unparseable date: {value!r}")
    else: raise ValueError(f"Cannot convert {type(value).__name__} to a date")
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def convert_value(value: Any, how: str | None, fmt: str | None = None) -> Any:
    if value is None or not how: return value
    try:
        if how == "date": return convert_date(value, fmt)
        if how == "int": return int(float(value))
        if how == "float": return float(value)
        if how == "str": return str(value)
        if how == "lower": return str(value).lower()
        if how == "upper": return str(value).upper()
    except (TypeError, ValueError) as exc: raise ValueError(f"Conversion '{how}' failed for {value!r}: {exc}")
    raise ValueError(f"Unknown conversion {how!r}")

def resolve_field(record: Any, spec: Any, getter: Callable[[Any, str | None], Any]) -> Any:
    """spec is a dotted path string, or {path, value, default, convert, format}."""
    if isinstance(spec, str): return getter(record, spec)
    if "value" in spec: return spec["value"]
    v = getter(record, spec["path"]) if spec.get("path") else None
    if v in (None, "") and "default" in spec: v = spec["default"]
    return convert_value(v, spec.get("convert"), spec.get("format"))

def _drop_none(d: dict) -> None:
    for k in [k for k, v in d.items() if v is None]: del d[k]

def normalize_config(raw: dict) -> dict:
    """Accept both config dialects (secret/secret_env, header/header_name, type/strategy, start_param/offset_param)."""
    c = copy.deepcopy(raw)
    a = c.get("auth")
    if isinstance(a, dict):
        for old, new in (("secret_env", "secret"), ("header_name", "header")):
            if old in a:
                v = a.pop(old)
                if v is not None: a.setdefault(new, v)
        _drop_none(a)
    p = c.get("pagination")
    if isinstance(p, dict):
        if "strategy" in p:
            v = p.pop("strategy"); p.setdefault("type", v)
        if "offset_param" in p:
            v = p.pop("offset_param"); p.setdefault("start_param", v)
        _drop_none(p)
    e = c.get("endpoint")
    if isinstance(e, dict): _drop_none(e)
    for k in ("vendor", "product", "category", "schedule"):
        if c.get(k) is None: c.pop(k, None)
    return c
