# ═══════════════════════════════════════════════════════════════
# Recon Sentinel — Backend Dockerfile (multi-stage)
# Stage 1: Python deps
# Stage 2: Go tool binaries (subfinder, naabu, httpx, nuclei, ffuf)
# Stage 3: Slim runtime
# ═══════════════════════════════════════════════════════════════

# ─── Stage 1: Python Builder ─────────────────────────────────
FROM python:3.11-slim AS py-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Go Tool Builder ────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/sensepost/gowitness@latest

# ─── Stage 3: Runtime ────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpcap0.8 \
    postgresql-client \
    curl \
    nmap \
    dnsutils \
    openssl \
    chromium \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install theHarvester via pip (not available as apt package in Debian Trixie)
RUN pip install --no-cache-dir theHarvester

# Install SecLists wordlists (not available as apt package in Debian Trixie)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists && \
    rm -rf /usr/share/seclists/.git

# Copy Python packages from py-builder
COPY --from=py-builder /install /usr/local

# Install optional Python scanning libraries
RUN pip install --no-cache-dir badsecrets 2>/dev/null || true

# Copy Go binaries from go-builder
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/naabu /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/
COPY --from=go-builder /go/bin/gowitness /usr/local/bin/

# Download Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /app
COPY . .

# Create non-root user
RUN groupadd -g 1000 sentinel && \
    useradd -u 1000 -g sentinel -s /bin/sh sentinel && \
    mkdir -p /data/screenshots /data/reports /data/nuclei-templates /tmp && \
    chown -R sentinel:sentinel /app /data /tmp

EXPOSE 8000

USER sentinel

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
