# Deploying Vaaman AI

This guide covers deploying the Vaaman AI platform for a public demo or production instance.

---

## Option 1: Docker on Any VPS (Simplest)

Works on any Linux VPS with Docker installed. Suitable for $5-10/month VPS from DigitalOcean, Linode, Hetzner, or AWS Lightsail.

### Prerequisites

- Linux VPS (Ubuntu 22.04 recommended, 1GB+ RAM)
- Docker and Docker Compose installed
- A domain name (optional — for HTTPS)

### Deploy

```bash
# SSH into your VPS
ssh user@your-server

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Clone and setup
git clone https://github.com/your-username/vaaman-cli /opt/vaaman
cd /opt/vaaman
cp .env.example .env
nano .env  # Add OPENROUTER_API_KEY

# Build and run
docker compose up -d

# Verify
curl http://localhost:3001/api/health
```

### With HTTPS (Caddy)

Add to `docker-compose.yml`:

```yaml
  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
    restart: unless-stopped

volumes:
  caddy_data:
```

Create `Caddyfile`:

```
your-domain.com {
    reverse_proxy vaaman:3001
}
```

---

## Option 2: Fly.io (One Command)

Fly.io runs Docker containers on Firecracker microVMs. Great for quick demos.

### Deploy

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Deploy (auto-detects Dockerfile)
cd vaaman-cli
fly launch
# Follow prompts: name=vaaman, region=bom (Mumbai or nearest)

# Set secrets
fly secrets set OPENROUTER_API_KEY=sk-or-v1-your-key

# Deploy
fly deploy

# Open
fly open
```

### Pricing

- ~$5.70/month for 1 shared CPU + 1GB RAM
- Billed per second of actual usage
- Free trial credits available

---

## Option 3: AWS EC2 Free Tier

New AWS accounts get $200 in credits. Good for 12-15 months of free hosting.

### Instance

```
Ubuntu 22.04 ARM (aarch64)
T4g.small: 2 vCPU, 2 GB RAM
30 GB gp3 SSD
```

### Security Group

Allow inbound: TCP 22 (SSH from your IP), TCP 443 (HTTPS), TCP 80 (HTTP)
Allow outbound: TCP 443 only

### Deploy

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Install Docker (ARM64 native)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu
newgrp docker

# Clone and run
git clone https://github.com/your-username/vaaman-cli /opt/vaaman
cd /opt/vaaman
cp .env.example .env
nano .env
docker compose up -d
```

### AWS Security Hardening

**Block Instance Metadata Service** from inside containers:

```dockerfile
# In Dockerfile, add:
RUN iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

**Attach NO IAM role** to the EC2 instance. If malware reads the metadata endpoint, it gets nothing.

---

## Option 4: Oracle Cloud Free Tier (Always Free)

4 ARM cores, 24 GB RAM, $0/month forever.

### Deploy

```bash
# Launch VM.Standard.A1.Flex with 2 OCPU, 8GB RAM, Ubuntu 22.04 ARM
# SSH in and run:

curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu
newgrp docker

git clone https://github.com/your-username/vaaman-cli /opt/vaaman
cd /opt/vaaman
cp .env.example .env
nano .env
docker compose up -d
```

**Important:** Oracle reclaims idle free-tier resources. Keep a cron job:

```bash
# /etc/cron.d/vaaman-health
*/5 * * * * ubuntu curl -s http://localhost:3001/api/health > /dev/null
```

---

## Security Hardening (Required for Public Demo)

When exposing Vaaman to the public internet, apply these layers:

### 1. Docker Security Options

```yaml
# docker-compose.yml
services:
  vaaman:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - SYS_PTRACE    # strace needs this
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=256M
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
```

### 2. Network Isolation for Scans

The audit-runner spawns `npm install` as a child process. This process should:

- Only access `registry.npmjs.org` (block all other outbound)
- Run as a non-root user
- Have a 60-second timeout
- Be killed if it exceeds resource limits

### 3. Rate Limiting

Add to `apps/api/src/index.ts`:

```typescript
// Simple in-memory rate limiter
const scanLimits = new Map<string, number>()
app.addHook('onRequest', async (request, reply) => {
  if (request.url === '/api/audit' && request.method === 'POST') {
    const ip = request.ip
    const count = (scanLimits.get(ip) || 0) + 1
    if (count > 10) return reply.status(429).send({ error: 'Rate limit exceeded' })
    scanLimits.set(ip, count)
    setTimeout(() => scanLimits.delete(ip), 3600000) // Reset after 1 hour
  }
})
```

### 4. Read-Only Pre-Scan First

Before running `npm install` with behavioral monitoring, run `npm install --ignore-scripts` first. This downloads and extracts the package WITHOUT executing any lifecycle scripts. If the pre-scan shows dangerous signals, skip the behavioral step entirely.

---

## Cost Comparison

| Provider | Monthly Cost | RAM | CPU | strace | Setup |
|----------|:---:|-----|-----|:---:|:---:|
| Oracle Cloud | $0 | 8 GB | 2 ARM | ✅ | 15 min |
| AWS EC2 (free tier) | $0* | 2 GB | 2 ARM | ✅ | 20 min |
| Hetzner CX22 | €4 | 4 GB | 2 x86 | ✅ | 15 min |
| Fly.io | $5.70 | 1 GB | 1 shared | ✅ | 1 min |
| Railway | $10-20 | 1 GB | 1 shared | ✅ | 1 min |

*With $200 credits. ~$13.40/month consumed from credits for 15 months.

## Domain + TLS

For a custom domain with HTTPS:

1. Point your domain's A record to the server IP
2. Use Caddy as a reverse proxy (automatic Let's Encrypt):

```dockerfile
# Add to docker-compose.yml:
  caddy:
    image: caddy:2-alpine
    ports: ["80:80", "443:443"]
    volumes: ["./Caddyfile:/etc/caddy/Caddyfile"]
```

```
# Caddyfile:
vaaman.your-domain.com {
    reverse_proxy vaaman:3001
}
```

---

*Choose Oracle Cloud for max specs at zero cost. Choose Fly.io for simplest deployment.*
