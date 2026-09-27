"""FastAPI application factory for the Stoá control plane."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from stoa_server import __version__
from stoa_server.database import get_session
from stoa_server.routers.auth import router as auth_router
from stoa_server.routers.platform import router as platform_router
from stoa_shared import HealthResponse, ReadinessResponse, ServiceStatus


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize app-scoped state without opening external connections in PR 1."""

    app.state.accepting_requests = True
    yield
    app.state.accepting_requests = False


def create_app() -> FastAPI:
    """Create an isolated API instance for production and tests."""

    application = FastAPI(
        title="Stoá API",
        description="Safety-first coordination plane for authorized security work.",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    router = APIRouter(prefix="/api/v1")

    @router.get("/health", response_model=HealthResponse, tags=["operations"])
    async def health() -> HealthResponse:
        return HealthResponse(version=__version__)

    @router.get("/ready", response_model=ReadinessResponse, tags=["operations"])
    def ready(session: Annotated[Session, Depends(get_session)]) -> ReadinessResponse:
        try:
            session.execute(text("SELECT 1"))
        except SQLAlchemyError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="database unavailable",
            ) from error
        return ReadinessResponse(
            status=ServiceStatus.READY,
            checks={"application": ServiceStatus.READY, "database": ServiceStatus.READY},
        )

    application.include_router(router)
    application.include_router(auth_router, prefix="/api/v1")
    application.include_router(platform_router, prefix="/api/v1")
    return application


app = create_app()
