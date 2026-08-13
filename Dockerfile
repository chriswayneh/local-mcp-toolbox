# syntax=docker/dockerfile:1
FROM python:3.12.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10001 toolbox \
    && useradd --uid 10001 --gid toolbox --create-home --shell /usr/sbin/nologin toolbox

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[docker]"

COPY config/container.yml /app/config/container.yml
RUN mkdir --parents /var/lib/local-mcp-toolbox/audit \
    && chown --recursive toolbox:toolbox /app /var/lib/local-mcp-toolbox

USER toolbox:toolbox

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["local-mcp-toolbox", "doctor", "--config", "/app/config/container.yml"]

ENTRYPOINT ["local-mcp-toolbox"]
CMD ["serve", "--config", "/app/config/container.yml"]
