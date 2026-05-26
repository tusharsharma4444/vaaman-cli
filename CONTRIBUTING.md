# Contributing to Vaaman AI

## Prerequisites

- **Node.js 18+** (for development)
- **Docker Desktop** (for behavioral monitoring with strace)
- **OpenRouter API key** (free at [openrouter.ai/keys](https://openrouter.ai/keys))

## Setup

```bash
git clone https://github.com/your-username/vaaman-cli
cd vaaman-cli
npm install
cp .env.example .env
# Edit .env — add your OPENROUTER_API_KEY
```

## Development

### Monorepo Structure

```
apps/cli/       → CLI tool (Commander + strace + monitors)
apps/api/       → Fastify backend (7 API endpoints)
apps/dashboard/ → React frontend (Vite + Tailwind)
packages/core/  → Shared types, OpenRouter client, cache
packages/deep-intel/    → AI intent classifier
packages/trust-engine/  → AI trust scoring
```

### Running Locally

```bash
# Build all packages
npm run build

# Terminal 1: API server
npm run dev:api              # Fastify on http://localhost:3001

# Terminal 2: Dashboard
npm run dev:dashboard        # Vite on http://localhost:5173

# Terminal 3: CLI (optional)
npm run dev:cli              # tsx watch mode
```

### Running with Docker

```bash
docker compose up -d         # API + Dashboard on http://localhost:3001
docker compose logs -f       # View logs
docker compose down          # Stop
```

## Build

```bash
npm run build                 # All 6 packages in order
npm run build:no-dashboard    # Skip dashboard (faster for API changes)

# Build order: core → deep-intel → trust-engine → api → cli → dashboard
```

## Project Conventions

- **TypeScript strict mode** — all packages use `"strict": true`
- **ESM modules** — `"type": "module"` with `.js` extensions in imports
- **No comments in code** — unless documenting a non-obvious decision
- **Single responsibility** — one purpose per file
- **Zero native dependencies** — no C++ compilation required (pure JS/TS)

## Adding a Feature

### New API Route

1. Create `apps/api/src/routes/my-feature.ts`
2. Export an async function: `export async function myFeatureRoutes(app: FastifyInstance)`
3. Register in `apps/api/src/index.ts`: `await app.register(myFeatureRoutes, { prefix: '/api' })`
4. Build: `npm run build -w apps/api`

### New SSE Event Type

1. Emit from service: `events.emitEvent('my:event', { scanId, data })`
2. Dashboard listens: `es.addEventListener('my:event', handler)` in `useSSE.ts`

### New AI Agent

1. Create agent function in `apps/api/src/services/`
2. Import `OpenRouterClient` from `@vaaman/core`
3. Wire into audit-runner.ts pipeline

## Testing

```bash
# Manual verification
curl http://localhost:3001/api/health
curl -X POST http://localhost:3001/api/scan -H 'Content-Type: application/json' -d '{"package":"lodash"}'
curl -X POST http://localhost:3001/api/audit -H 'Content-Type: application/json' -d '{"dependencies":[{"name":"lodash","version":"4.17.21"}]}'
```

## Commit Style

- Phase-based: `phase: add deep-intel pipeline`
- Fix: `fix: robust JSON parsing in auditor agent`
- Docs: `docs: update architecture README`
- Security: `security: add sandboxed install execution`

This project doesn't use conventional commits with `!` for breaking changes.

## Security Notes

- **Never commit `.env`** — it contains API keys. Use `.env.example` as template.
- **Rotate keys** immediately if accidentally committed.
- **The audit pipeline executes untrusted code** — always test with Docker isolation.
- **`npm install` runs postinstall scripts** — use `--ignore-scripts` for pre-scan only mode.
