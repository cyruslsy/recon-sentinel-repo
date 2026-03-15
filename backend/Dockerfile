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
FROM golang:1.25-bookworm AS go-builder

# Allow Go to auto-download newer toolchains if any tool requires it
ENV GOTOOLCHAIN=auto

# naabu requires libpcap-dev for packet capture support
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools + Phase B additions (puredns, katana, gau)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
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

# Compile massdns from source (Phase B1)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && cp bin/massdns /usr/local/bin/ && \
    rm -rf /tmp/massdns && \
    apt-get purge -y build-essential && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Download wordlists for subdomain brute-force (Phase B1)
RUN mkdir -p /usr/share/wordlists && \
    curl -sL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt \
      -o /usr/share/wordlists/n0kovo_subdomains_huge.txt && \
    curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
      -o /usr/share/wordlists/resolvers.txt

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
COPY --from=go-builder /go/bin/puredns /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/

# Download Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /app
COPY . .

ENV PYTHONPATH=/app

# Create non-root user
RUN groupadd -g 1000 sentinel && \
    useradd -u 1000 -g sentinel -s /bin/sh sentinel && \
    mkdir -p /data/screenshots /data/reports /data/nuclei-templates /tmp && \
    chown -R sentinel:sentinel /app /data /tmp

EXPOSE 8000

USER sentinel

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
