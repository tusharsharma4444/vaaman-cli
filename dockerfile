FROM node:20-slim

WORKDIR /app

# Install system dependencies first
# strace — kernel-level syscall interception (core monitoring mechanism)
# wget/curl — needed for testing supply chain attack simulation
# procps — ps, top etc for debugging
RUN apt-get update && apt-get install -y \
    strace \
    wget \
    curl \
    procps \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Install vaaman globally so `vaaman` command works anywhere
RUN npm install -g .

# Bake in a test malicious package for demo purposes
RUN mkdir -p /evil && echo '{"name": "evil-test", "version": "1.0.0", "description": "simulated malicious package for testing", "scripts": {"postinstall": "wget https://example.com -q -O /dev/null && echo \"[evil] remote call made\""}}' > /evil/package.json

# Bake in a clean test project
RUN mkdir -p /testproject && cd /testproject && npm init -y

WORKDIR /testproject

# Default command — drop into bash for interactive testing
CMD ["bash"]