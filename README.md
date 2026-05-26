# Vaaman AI

**AI-native supply chain security.** Watches what npm packages actually DO at install time — not just what CVE databases say.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)

---

## What It Does

Paste a `package.json`. Get a comprehensive security audit in markdown.

Vaaman runs **7 layers of analysis** on every dependency:

```
1. Pre-scan          → Static tarball analysis (lifecycle scripts, primitives, chains)
2. Behavioral        → strace-based install monitoring (processes, network, filesystem)
3. OSV.dev           → Known CVE database (severity + fix versions)
4. Deep Intel (AI)   → Intent classification (is child_process.exec in a CLI tool legitimate?)
5. Trust Engine (AI) → 6-dimension scoring (ecosystem, identity, behavior, deception, transparency)
6. AI Auditor        → Per-package verdict with evidence
7. Summarizer        → Comprehensive markdown report with recommendations
```

## Quick Start
# Vaaman uses strace for postinstall and preinstall behaviour monitoring , so it requires a linux environment for running

```bash
# Clone and setup
git clone https://github.com/tusharsharma4444/vaaman-cli
cd vaaman-cli
cp .env.example .env
# Edit .env → add your OPENROUTER_API_KEY from https://openrouter.ai/keys

# Run with Docker (recommended)

docker compose up -d
open http://localhost:3001

# or if you are using windows 
.\start.ps1 - # run this command in powershell

# Or run locally on linux (dashboard dev mode)
npm install && npm run build
npm run dev:api          # Terminal 1: API on :3001
npm run dev:dashboard    # Terminal 2: Dashboard on :5173
```

## Architecture

```
vaaman-cli/
├── apps/
│   ├── cli/              CLI: pre-scan, deep-intel, trust, install (strace)
│   ├── api/              Fastify: /audit, /scan, /events, /history
│   └── dashboard/        React: Home, ScanResult, AuditReport, History
├── packages/
│   ├── core/             Shared types, OpenRouter AI client, cache
│   ├── deep-intel/       AI intent classifier (package type + legitimacy)
│   └── trust-engine/     AI 6-dimension trust scoring
└── dockerfile            Single container: API + CLI + Dashboard
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/audit` | **Full project audit** — package.json → markdown report |
| `GET` | `/api/audit/:id` | Fetch audit result |
| `POST` | `/api/scan` | Single package pre-scan |
| `POST` | `/api/deep-intel` | AI intent classification |
| `POST` | `/api/trust` | AI trust scoring |
| `GET` | `/api/events` | SSE real-time event stream |
| `GET` | `/api/history` | Past scan history |

## CLI Commands

```bash
vaaman pre-scan <pkg>              # Static tarball analysis
vaaman deep-intel <pkg>            # AI intent + legitimacy
vaaman trust <pkg>                 # 6-dimension trust score
vaaman install <pkg>               # Runtime behavioral monitoring (strace)
vaaman install <pkg> --json        # Structured output for API consumption
```

## Example Audit Report

```
# Supply Chain Security Audit Report
Packages analyzed: 32 | Risk: 2 CRITICAL · 2 DANGEROUS · 2 SUSPICIOUS · 26 SAFE

## 🔴 CRITICAL (2)

### axios@1.16.1 — Risk: 92/100
Contains 1 MALICIOUS flag: MAL-2026-2307. Investigate immediately.
- **Pre-scan:** Score 30/100, 8 primitive hits
- **CVEs:** 25 (2 HIGH, 1 MEDIUM MAL)
- **AI Analysis:** Type: runtime-utility · Intent: likely-malicious (5/100)
- **Trust Score:** Grade C (68/100)
```

## Why Vaaman

| | npm audit | Snyk | Socket.dev | **Vaaman** |
|---|:---:|:---:|:---:|:---:|
| CVE database lookup | ✅ | ✅ | ✅ | ✅ |
| Static code analysis | ❌ | ✅ | ✅ | ✅ |
| **Runtime behavioral monitoring** | ❌ | ❌ | ❌ | **✅** |
| AI-powered intent classification | ❌ | ❌ | ❌ | **✅** |
| Multi-dimension trust scoring | ❌ | ❌ | ❌ | **✅** |
| **Catches zero-day supply chain attacks** | ❌ | ❌ | ❌ | **✅** |

Vaaman's USP: strace watches every `execve()`, `connect()`, and file write during `npm install`. A package that downloads and executes a remote payload — even one with zero CVEs — gets caught immediately.

## Requirements

- **Docker** (for behavioral monitoring with strace)
- **OpenRouter API key** (for AI features — get one free at [openrouter.ai/keys](https://openrouter.ai/keys))
- Node.js 18+ (for dashboard dev mode)

## Documentation

| Doc | Content |
|-----|---------|
| [Architecture](./docs/README.md) | Complete architecture + data flow |
| [Contributing](./CONTRIBUTING.md) | Development setup + workflow |
| [Deployment](./docs/DEPLOYMENT.md) | Hosting on Fly.io, Railway, EC2 |
| [Phase 1](./docs/phase-1-foundation.md) | Monorepo + OpenRouter client |
| [Phase 2](./docs/phase-2-deep-intel.md) | AI intent classifier |
| [Phase 3](./docs/phase-3-trust-engine.md) | AI trust scoring |
| [Phase 4](./docs/phase-4-agentic-layer.md) | Agentic layer + AI reasoner |
| [Phase 5](./docs/phase-5-dashboard.md) | Dashboard + API |

## Security

Vaaman analyzes potentially malicious code. We take precautions:

- **Sandboxed execution** — `npm install` runs in an isolated Docker container
- **Resource limits** — CPU, memory, and PID limits per scan
- **Network isolation** — outbound connections restricted to npm registry
- **Non-root execution** — installs run as unprivileged user
- **No secrets in sandbox** — `OPENROUTER_API_KEY` never exposed to analyzed packages

See [DEPLOYMENT.md](./docs/DEPLOYMENT.md) for full security hardening guide.

## License

MIT
