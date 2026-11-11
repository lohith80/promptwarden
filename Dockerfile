# Build stage: install into a virtualenv so the runtime image carries no
# build tooling.
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
RUN python -m venv /opt/venv
COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/venv/bin/pip install .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="PromptWarden" \
      org.opencontainers.image.description="Security gateway for LLM and agent traffic" \
      org.opencontainers.image.source="https://github.com/lohith80/promptwarden" \
      org.opencontainers.image.licenses="Apache-2.0"

# Run as non-root; the gateway needs no privileges and no writable root
# filesystem (compatible with readOnlyRootFilesystem: true).
RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin warden
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY config/policy.example.yaml ./config/policy.example.yaml

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PW_POLICY=/app/config/policy.yaml
USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", \
  "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]

CMD ["promptwarden", "serve", "--host", "0.0.0.0", "--port", "8080"]
