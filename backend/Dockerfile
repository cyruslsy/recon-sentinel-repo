# ═══════════════════════════════════════════════════════════════
# Recon Sentinel — Backend Dockerfile
# Python 3.11 + FastAPI + Celery + Alembic
# ═══════════════════════════════════════════════════════════════

FROM python:3.11-slim AS base

# System deps for asyncpg, bcrypt, and pg_isready
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for production
RUN groupadd -g 1000 sentinel && \
    useradd -u 1000 -g sentinel -s /bin/sh sentinel && \
    mkdir -p /data/screenshots /data/reports /tmp && \
    chown -R sentinel:sentinel /app /data /tmp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
