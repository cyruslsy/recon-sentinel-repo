# ═══════════════════════════════════════════════════════════════
# Recon Sentinel — Frontend Dockerfile (multi-stage)
# Stage 1: Install dependencies
# Stage 2: Build Next.js
# Stage 3: Slim runtime with standalone output
# ═══════════════════════════════════════════════════════════════

# ─── Stage 1: Dependencies ─────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

# ─── Stage 2: Build ────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ─── Stage 3: Runtime ──────────────────────────────────────────
FROM node:20-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 sentinel && \
    adduser --system --uid 1001 sentinel

COPY --from=builder --chown=sentinel:sentinel /app/public ./public
COPY --from=builder --chown=sentinel:sentinel /app/.next/standalone ./
COPY --from=builder --chown=sentinel:sentinel /app/.next/static ./.next/static

USER sentinel

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
