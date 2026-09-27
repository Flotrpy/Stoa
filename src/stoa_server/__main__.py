"""Development server entry point."""

import uvicorn

from stoa_shared.settings import get_settings


def main() -> None:
    """Run the API using validated local settings."""

    settings = get_settings()
    uvicorn.run(
        "stoa_server.app:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        reload=settings.env == "development",
    )


if __name__ == "__main__":
    main()
