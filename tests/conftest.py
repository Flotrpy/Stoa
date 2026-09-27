from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from stoa_server import models as stoa_models  # noqa: F401
from stoa_server.app import create_app
from stoa_server.database import Base, get_session
from stoa_shared.settings import Settings, get_settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url="sqlite+pysqlite://",
        auth_secret="test-secret-that-is-long-enough-for-signing",  # noqa: S106
    )


@pytest.fixture
def session_factory() -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(
    settings: Settings, session_factory: sessionmaker[Session]
) -> Generator[TestClient, None, None]:
    application = create_app()

    def session_override() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    application.dependency_overrides[get_session] = session_override
    application.dependency_overrides[get_settings] = lambda: settings
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture
def admin_token(client: TestClient) -> str:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "team_name": "Example Security",
            "team_slug": "example-security",
            "email": "admin@example.test",
            "display_name": "Test Administrator",
            "password": "correct horse battery staple",
        },
    )
    assert response.status_code == 201
    return str(response.json()["access_token"])


@pytest.fixture
def admin_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def temporary_database_url(tmp_path: Path) -> str:
    return f"sqlite+pysqlite:///{(tmp_path / 'migration.db').as_posix()}"
