from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import jwt
import pytest

from app.auth import security
from app.auth.security import TokenError, create_access_token, decode_access_token, hash_password, verify_password


def test_password_verification_rejects_malformed_and_wrong_algorithm_hashes() -> None:
    password_hash = hash_password("correct-password", iterations=1_000)

    assert verify_password("correct-password", password_hash)
    assert not verify_password("wrong-password", password_hash)
    assert not verify_password("password", "not-a-valid-hash")
    assert not verify_password("password", "bcrypt$1000$salt$digest")


def test_decode_access_token_rejects_bad_headers_and_expired_tokens(monkeypatch) -> None:
    secret = "unit-secret-" + ("x" * 80)
    settings = SimpleNamespace(jwt_secret_key=secret, jwt_algorithm="HS256", access_token_expire_minutes=60)
    monkeypatch.setattr(security, "get_settings", lambda: settings)

    expired = create_access_token({"sub": "account-1"}, expires_delta=timedelta(seconds=-1))
    wrong_algorithm = jwt.encode(
        {"sub": "account-1", "iat": 1, "exp": 9999999999},
        secret,
        algorithm="HS512",
        headers={"typ": "JWT"},
    )
    wrong_type = jwt.encode(
        {"sub": "account-1", "iat": 1, "exp": 9999999999},
        secret,
        algorithm="HS256",
        headers={"typ": "NotJWT"},
    )
    missing_sub = jwt.encode(
        {"iat": 1, "exp": 9999999999},
        secret,
        algorithm="HS256",
        headers={"typ": "JWT"},
    )

    assert decode_access_token(create_access_token({"sub": "account-1"}))["sub"] == "account-1"
    for token, message in (
        ("not-a-token", "invalid token header"),
        (wrong_algorithm, "unsupported token header"),
        (wrong_type, "unsupported token header"),
        (expired, "token expired"),
        (missing_sub, "invalid bearer token"),
    ):
        with pytest.raises(TokenError, match=message):
            decode_access_token(token)
