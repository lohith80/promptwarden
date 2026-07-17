FROM python:3.12-slim

# Run as non-root; the gateway needs no privileges.
RUN useradd --create-home --uid 10001 warden
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config/policy.example.yaml ./config/policy.example.yaml

USER warden
EXPOSE 8080
ENV PW_POLICY=/app/config/policy.yaml

HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", \
  "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]

CMD ["uvicorn", "promptwarden.app:app", "--host", "0.0.0.0", "--port", "8080"]
