# ═══════════════════════════════════════════════════════════════
# Recon Sentinel — Backend Dockerfile (multi-stage)
# Stage 1: Install deps with build tools
# Stage 2: Slim runtime with only what's needed
# ═══════════════════════════════════════════════════════════════

# ─── Builder ──────────────────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Runtime ──────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

# Create non-root user
RUN groupadd -g 1000 sentinel && \
    useradd -u 1000 -g sentinel -s /bin/sh sentinel && \
    mkdir -p /data/screenshots /data/reports /tmp && \
    chown -R sentinel:sentinel /app /data /tmp

EXPOSE 8000

# Default: run as non-root
USER sentinel

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
