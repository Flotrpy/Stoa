"""Database engine and session lifecycle."""

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from stoa_shared.settings import Settings, get_settings


class Base(DeclarativeBase):
    """Declarative root for central metadata models."""


def build_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine with conservative connection validation."""

    return create_engine(database_url, pool_pre_ping=True)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create sessions that keep ORM values available after commits."""

    return sessionmaker(bind=engine, expire_on_commit=False)


_settings = get_settings()
engine = build_engine(_settings.database_url)
SessionLocal = build_session_factory(engine)


def get_session() -> Generator[Session, None, None]:
    """Yield one transaction-capable session for a request."""

    with SessionLocal() as session:
        yield session


def database_url_from_settings(settings: Settings) -> str:
    """Expose the validated URL without leaking it to logs."""

    return settings.database_url
