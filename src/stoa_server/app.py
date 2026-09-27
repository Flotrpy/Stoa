"""FastAPI application factory for the Stoá control plane."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from stoa_server import __version__
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
    async def ready() -> ReadinessResponse:
        return ReadinessResponse(
            status=ServiceStatus.READY,
            checks={"application": ServiceStatus.READY},
        )

    application.include_router(router)
    return application


app = create_app()
