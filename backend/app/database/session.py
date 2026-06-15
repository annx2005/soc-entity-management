from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_postgres_schema_extras()


def _ensure_postgres_schema_extras() -> None:
    if engine.dialect.name != "postgresql":
        return

    statements = [
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        "ALTER TABLE tenants ALTER COLUMN id SET DEFAULT gen_random_uuid()",
        "ALTER TABLE tenants ALTER COLUMN status SET DEFAULT 'active'",
        "ALTER TABLE tenants ALTER COLUMN created_at SET DEFAULT now()",
        "ALTER TABLE tenants ALTER COLUMN updated_at SET DEFAULT now()",
        "ALTER TABLE accounts ALTER COLUMN id SET DEFAULT gen_random_uuid()",
        "ALTER TABLE accounts ALTER COLUMN role SET DEFAULT 'viewer'",
        "ALTER TABLE accounts ALTER COLUMN scope SET DEFAULT 'tenant'",
        "ALTER TABLE accounts ALTER COLUMN status SET DEFAULT 'active'",
        "ALTER TABLE accounts ALTER COLUMN created_at SET DEFAULT now()",
        "ALTER TABLE accounts ALTER COLUMN updated_at SET DEFAULT now()",
        """
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """,
        "DROP TRIGGER IF EXISTS trg_tenants_updated_at ON tenants",
        """
        CREATE TRIGGER trg_tenants_updated_at
            BEFORE UPDATE ON tenants
            FOR EACH ROW EXECUTE FUNCTION set_updated_at()
        """,
        "DROP TRIGGER IF EXISTS trg_accounts_updated_at ON accounts",
        """
        CREATE TRIGGER trg_accounts_updated_at
            BEFORE UPDATE ON accounts
            FOR EACH ROW EXECUTE FUNCTION set_updated_at()
        """,
    ]

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
