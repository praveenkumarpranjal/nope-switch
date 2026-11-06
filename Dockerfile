FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml README.md ./
COPY apps ./apps
RUN uv sync --no-dev --extra semgrep --no-editable

FROM python:3.12-slim-bookworm
ENV PATH="/app/.venv/bin:${PATH}" PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY --from=builder /app /app
RUN useradd --create-home --uid 10001 nope && mkdir -p /var/lib/nope && chown -R nope:nope /var/lib/nope
USER nope
EXPOSE 8010
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=2)" || exit 1
CMD ["uvicorn", "nope_core.main:app", "--host", "0.0.0.0", "--port", "8010"]
