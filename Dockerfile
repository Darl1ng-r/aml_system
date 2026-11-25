# Multi-Stage Production Dockerfile for AML Platform Gateway
# Stage 1: Build & Dependencies
FROM python:3.11.9-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# Stage 2: Hardened Runtime Container (P1-05, P1-14, P3-01, P3-07)
FROM python:3.11.9-slim-bookworm AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.11/site-packages:$PYTHONPATH" \
    PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc

# Minimal runtime libs + unprivileged user with /usr/sbin/nologin (no curl or bash shell)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M appuser \
    && mkdir -p /tmp/prometheus_multiproc \
    && chown -R appuser:appgroup /tmp/prometheus_multiproc

COPY --from=builder /install /install
# Root-owned read-only application code (UID 10001 cannot modify source files at runtime)
COPY --chown=root:root . /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3).status == 200 else 1)"

CMD ["sh", "-c", "mkdir -p \"${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus_multiproc}\" && exec python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers \"${WEB_CONCURRENCY:-2}\" --proxy-headers --forwarded-allow-ips \"${TRUSTED_PROXY_CIDRS:-127.0.0.1}\" --no-server-header --timeout-keep-alive 75 --timeout-graceful-shutdown 25 --limit-concurrency 500 --limit-max-requests 10000"]
