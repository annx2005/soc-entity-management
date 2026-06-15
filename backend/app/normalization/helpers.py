from __future__ import annotations

import re
from typing import Any


IP_RE = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})"
)


def get_nested(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def process_name_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = re.split(r"[\\/]+", path)
    return parts[-1] if parts and parts[-1] else path


def parse_sha256(hashes: str | None) -> str | None:
    if not hashes:
        return None
    for item in hashes.split(","):
        key, _, value = item.partition("=")
        if key.strip().upper() == "SHA256" and value.strip():
            return value.strip().upper()
    return None


def parse_first_ip(value: str | None) -> str | None:
    if not value:
        return None
    match = IP_RE.search(value.replace("::ffff:", ""))
    return match.group(0) if match else None


def normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().rstrip(".").lower() or None


def normalize_empty(value: Any) -> Any:
    if value in ("", "-", None):
        return None
    return value
