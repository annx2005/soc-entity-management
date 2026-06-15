from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import InvalidAlgorithmError, InvalidTokenError
from jwt.exceptions import ExpiredSignatureError

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
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm, headers={"typ": "JWT"})


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise TokenError("invalid token header") from exc

    if header.get("alg") != settings.jwt_algorithm or header.get("typ") != "JWT":
        raise TokenError("unsupported token header")

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub"]},
        )
    except ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except (InvalidAlgorithmError, InvalidTokenError) as exc:
        raise TokenError("invalid bearer token") from exc

    if not isinstance(payload, dict):
        raise TokenError("invalid token payload")
    return payload


def _pbkdf2(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()
