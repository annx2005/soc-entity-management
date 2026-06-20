from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import TenantContext, get_tenant_context
from app.auth.schemas import LoginRequest, LoginResponse, RegisterRequest, TenantContextResponse
from app.auth.security import create_access_token
from app.auth.service import AmbiguousAccountError, AuthenticationError, AuthenticatedAccount, RegistrationError, authenticate_account, register_tenant_account
from app.core.config import get_settings
from app.database.session import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> LoginResponse:
    try:
        authenticated = authenticate_account(db, email=payload.email, password=payload.password, tenant_slug=payload.tenant_slug)
    except AmbiguousAccountError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return _build_login_response(authenticated)


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> LoginResponse:
    try:
        authenticated = register_tenant_account(
            db,
            tenant_name=payload.tenant_name,
            tenant_slug=payload.tenant_slug,
            email=payload.email,
            password=payload.password,
        )
    except RegistrationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return _build_login_response(authenticated)


@router.get("/me", response_model=TenantContextResponse)
def me(context: Annotated[TenantContext, Depends(get_tenant_context)]) -> TenantContextResponse:
    return _context_response(
        account_id=str(context.account_id),
        tenant_id=str(context.tenant_id) if context.tenant_id else None,
        tenant_slug=context.tenant_slug,
        email=context.email,
        role=context.role,
        scope=context.scope,
    )


def _context_response(
    *,
    account_id: str,
    tenant_id: Optional[str],
    tenant_slug: Optional[str],
    email: str,
    role: str,
    scope: str,
) -> TenantContextResponse:
    return TenantContextResponse(
        account_id=account_id,
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
        email=email,
        role=role,
        scope=scope,
    )


def _build_login_response(authenticated: AuthenticatedAccount) -> LoginResponse:
    account = authenticated.account
    tenant = authenticated.tenant
    settings = get_settings()
    expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    claims = {
        "sub": str(account.id),
        "tenant_id": str(account.tenant_id) if account.tenant_id else None,
        "tenant_slug": tenant.slug if tenant else None,
        "email": account.email,
        "role": account.role.value,
        "scope": account.scope.value,
    }
    access_token = create_access_token(claims, expires_delta=expires_delta)

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
        context=_context_response(
            account_id=str(account.id),
            tenant_id=str(account.tenant_id) if account.tenant_id else None,
            tenant_slug=tenant.slug if tenant else None,
            email=account.email,
            role=account.role.value,
            scope=account.scope.value,
        ),
    )
