FROM python:3.12.10-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade "pip==26.2.1" "build==1.3.0" && python -m build --wheel

FROM python:3.12.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 stoa && useradd --system --uid 10001 --gid stoa --no-create-home stoa
COPY --from=builder /build/dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER stoa
EXPOSE 8787
ENTRYPOINT ["python", "-m", "stoa_server"]
