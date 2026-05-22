# AML Monitoring System — Backend Dockerfile
# Multi-stage build for minimal production image
# Base: Python 3.11-slim (Debian Bookworm)

ARG PYTHON_VERSION=3.11

# ── Stage 1: Build dependencies ───────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev git curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into /build/packages
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/build/packages -r requirements.txt

# ── Stage 2: Runtime image ───────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL maintainer="AML Technology Team <aml-tech@bank.de>"
LABEL org.opencontainers.image.title="AML Monitoring System API"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Deloitte Switzerland"

# Security: non-root user
RUN groupadd --gid 1001 amlapp \
    && useradd --uid 1001 --gid amlapp --no-create-home --shell /bin/false amlapp

WORKDIR /app

# Install runtime system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built packages from builder stage
COPY --from=builder /build/packages /usr/local

# Copy application code (read-only mounting in dev via docker-compose)
COPY --chown=amlapp:amlapp . /app/

# Create log directory
RUN mkdir -p /app/logs && chown amlapp:amlapp /app/logs

# Switch to non-root user
USER amlapp

# Expose metrics and API ports
EXPOSE 8000
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Production: 4 workers, no reload
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["gunicorn", "main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "30", \
     "--keepalive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info"]
