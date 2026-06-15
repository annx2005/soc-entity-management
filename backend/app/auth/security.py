from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import get_settings


class TokenError(ValueError):
    pass


def hash_password(password: str, *, iterations: int = 260_000) -> str:
    salt = secrets.token_hex(16)
    digest = _pbkdf2(password, salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt, expected = password_hash.split("$", 3)
        iterations = int(iterations_raw)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    actual = _pbkdf2(password, salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_access_token(claims: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    payload = {
        **claims,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    header = {"alg": settings.jwt_algorithm, "typ": "JWT"}
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = _sign(signing_input, settings.jwt_secret_key)
    return f"{signing_input}.{signature}"


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("invalid token format")

    header_raw, payload_raw, signature = parts
    signing_input = f"{header_raw}.{payload_raw}"
    expected_signature = _sign(signing_input, settings.jwt_secret_key)
    if not hmac.compare_digest(signature, expected_signature):
        raise TokenError("invalid token signature")

    header = _b64_decode_json(header_raw)
    if header.get("alg") != settings.jwt_algorithm or header.get("typ") != "JWT":
        raise TokenError("unsupported token header")

    payload = _b64_decode_json(payload_raw)
    expires_at = payload.get("exp")
    if not isinstance(expires_at, int):
        raise TokenError("missing token expiry")
    if datetime.now(timezone.utc).timestamp() >= expires_at:
        raise TokenError("token expired")
    return payload


def _pbkdf2(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()


def _b64_json(value: dict[str, Any]) -> str:
    return _b64_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode_json(value: str) -> dict[str, Any]:
    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("invalid token payload") from exc
    if not isinstance(payload, dict):
        raise TokenError("invalid token payload")
    return payload


def _sign(signing_input: str, secret_key: str) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64_encode(digest)
