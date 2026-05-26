# Vaaman AI — Complete Architecture

**Supply chain security platform. AI-native. Behavioral + static + trust.**

---

## Monorepo Structure

```
vaaman-cli/
├── apps/
│   ├── cli/                    # CLI — 5 commands
│   ├── dashboard/              # React dashboard with markdown audit reports
│   └── api/                    # Fastify backend — 7 endpoints
├── packages/
│   ├── core/                   # @vaaman/core — Types, OpenRouter client, cache, tools
│   ├── deep-intel/             # @vaaman/deep-intel — AI intent classifier
│   └── trust-engine/           # @vaaman/trust-engine — AI trust scoring
├── docs/                       # Phase-by-phase documentation
├── dockerfile                  # Single container: API + CLI + Dashboard
├── docker-compose.yml          # Docker Compose config
├── package.json                # npm workspaces root
└── tsconfig.base.json          # Shared TypeScript config
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        VAAMAN CLI                                  │
│  vaaman pre-scan | deep-intel | trust | install                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  Deep Intel    │     │  Trust Engine  │     │  OSV.dev       │
│  (AI-native)   │────▶│  (AI-native)   │     │  CVE lookup    │
│                │     │                │     │                │
│  Package type  │     │  Identity      │     │  Known CVEs    │
│  Intent class  │     │  Deception     │     │  MAL flags     │
│  Suppression   │     │  Capability    │     │  Fix versions  │
│  Legitimacy    │     │  Transparency  │     │                │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
        └─────────┬───────────┴─────────────────────┘
                  │
                  ▼
        ┌───────────────────┐
        │   OpenRouter API    │  ← unified AI client
        │   (Claude, GPT-4o,  │     single HTTP endpoint
        │    Llama via one key)│     model-agnostic
        └───────────────────┘
```

## CLI Commands

```bash
# Static analysis
vaaman pre-scan <package>              # Tarball analysis + chain detection

# AI intelligence (requires OPENROUTER_API_KEY)
vaaman deep-intel <package>            # Intent classification + legitimacy
vaaman trust <package>                 # 6-dimension trust scoring

# Behavioral monitoring (Linux + strace)
vaaman install <package>               # Rule-based runtime monitoring
vaaman install <package> --json        # Structured JSON output for API
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/audit` | Full project audit — package.json → markdown report |
| `GET` | `/api/audit/:id` | Fetch audit result |
| `POST` | `/api/scan` | Single package pre-scan |
| `GET` | `/api/scan/:id` | Get scan result by ID |
| `POST` | `/api/deep-intel` | AI intent classification |
| `POST` | `/api/trust` | AI trust scoring |
| `GET` | `/api/events` | SSE real-time event stream |
| `GET` | `/api/history` | Past scan history |
| `GET` | `/api/health` | Health check |

## How It Works

1. **Pre-scan** — Static tarball analysis (lifecycle scripts, AST primitive hits, behavioral chains)
2. **Behavioral** — strace-based install-time monitoring (process spawns, network connections, file writes)
3. **OSV.dev** — Known CVE database lookup with severity + fix version extraction
4. **Deep Intel** — AI intent classification (is `eval` in webpack legitimate or postinstall malware?)
5. **Trust Engine** — 6-dimension scoring (ecosystem, identity, behavior, deception, capability, transparency)
6. **AI Auditor** — Per-package verdict with specific evidence
7. **Summarizer** — Comprehensive markdown audit report with recommendations

## Packages

### @vaaman/core
- Unified type definitions (PreScanResult, InstallResult, AIVerdict, TrustScore)
- OpenRouter AI client (single HTTP endpoint, tool-use support)
- LLM response cache (JSON file, debounced writes)
- Agent tool definitions

### @vaaman/deep-intel
- AI-powered package type classifier (8 types)
- Primitive contextualizer — classifies `eval`, `child_process`, `fetch` in context
- Deterministic suppression engine (10 rules for known-good patterns)
- Operational legitimacy assessor

### @vaaman/trust-engine
- 6-dimension trust scoring: identity (25%), intent (25%), capability (20%), ecosystem (15%), deception (10%), transparency (5%)
- npm registry metadata fetcher
- AI-assisted identity analysis (claims vs behavior)
- AI capability inference (what it CAN do vs what it SHOULD)
- Deterministic deception detection

## Dashboard + API

```bash
# Terminal 1: Backend
docker compose up -d              # API on :3001

# Terminal 2: Dashboard (optional — dev mode)
npm run dev:dashboard             # Vite on :5173
```

### Dashboard Pages
- **Home** — Single package scan or full project (paste package.json)
- **ScanResult** — Verdict badge + chain analysis + event log
- **AuditReport** — Comprehensive markdown report with copy/download
- **History** — Past scans table

## Quick Start

```bash
# Install
git clone https://github.com/your-username/vaaman-cli
cd vaaman-cli
cp .env.example .env    # Add your OPENROUTER_API_KEY
npm install

# Build all packages
npm run build

# Run with Docker (recommended — strace works)
docker compose up -d

# Or run locally
npm run dev:api
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (ESM modules) |
| Runtime | Node.js 18+ |
| CLI | Commander |
| AI | OpenRouter (Claude, GPT-4o, Llama) |
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 |
| Backend | Fastify 4 |
| Storage | JSON files |
| Deployment | Docker (single container) |

## Documentation

| Doc | Content |
|-----|---------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Setup, development workflow, Docker usage |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Step-by-step hosting guide |
| [phase-1-foundation.md](./phase-1-foundation.md) | Monorepo, OpenRouter, types |
| [phase-2-deep-intel.md](./phase-2-deep-intel.md) | AI intent classifier |
| [phase-3-trust-engine.md](./phase-3-trust-engine.md) | Trust scoring engine |
| [phase-4-agentic-layer.md](./phase-4-agentic-layer.md) | BaseAgent, AI reasoner |
| [phase-5-dashboard.md](./phase-5-dashboard.md) | React dashboard + API |

---

*Built by a lone wolf. Shipped fast. One layer at a time.*
