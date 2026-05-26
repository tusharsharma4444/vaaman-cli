# ─────────────────────────────────────────────
# Vaaman AI — Security-Hardened Dockerfile
# Single container: API + CLI + Dashboard (port 3001)
# strace for behavioral monitoring (Linux only)
# Hardened for public deployment
# ─────────────────────────────────────────────

FROM node:20-slim

WORKDIR /app

# ── System dependencies ──────────────────────
# strace  = kernel-level syscall interception (core monitoring)
# curl    = health check
# procps  = debugging (ps, top)
# iptables = network isolation for sandboxed installs (coming in next phase)
RUN apt-get update && apt-get install -y \
    strace \
    curl \
    procps \
    iptables \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# ── Create non-root user for running unsafe code ──
RUN groupadd -r vaaman && useradd -r -g vaaman -d /app -s /sbin/nologin vaaman \
    && mkdir -p /app/apps/api/data /tmp/vaaman \
    && chown -R vaaman:vaaman /app /tmp/vaaman

# ── Node dependencies (layer caching) ────────
COPY package.json package-lock.json* ./
COPY tsconfig.base.json ./
COPY apps/cli/package.json ./apps/cli/
COPY apps/api/package.json ./apps/api/
COPY apps/dashboard/package.json ./apps/dashboard/
COPY packages/core/package.json ./packages/core/
COPY packages/deep-intel/package.json ./packages/deep-intel/
COPY packages/trust-engine/package.json ./packages/trust-engine/

RUN npm install

# ── Source code ──────────────────────────────
COPY . .

# ── Build all 6 packages ─────────────────────
RUN npm run build

# ── Verify ──────────────────────────────────
RUN ls apps/cli/dist/index.js && echo "[OK] CLI"
RUN ls apps/api/dist/index.js && echo "[OK] API"
RUN ls apps/dashboard/dist/index.html && echo "[OK] Dashboard"

# ── Block AWS IMDS (prevents metadata exfiltration on EC2) ──
RUN iptables -A OUTPUT -d 169.254.169.254 -j DROP || true

# ── Runtime env ─────────────────────────────
ENV PORT=3001
ENV NODE_ENV=production
ENV CORS_ORIGIN=*
ENV NODE_OPTIONS="--max-old-space-size=768"
ENV VAAMAN_MODEL=""

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

# ── Run as non-root user ────────────────────
USER vaaman

# API serves backend endpoints + dashboard static files
CMD ["node", "apps/api/dist/index.js"]
