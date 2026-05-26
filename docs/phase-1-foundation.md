# Phase 1 — Foundation: Monorepo + OpenRouter Client

**Status:** ✅ Complete  
**Duration:** ~1 day  
**Date:** May 2026

---

## Overview

Phase 1 establishes the structural and technical foundation for all future Vaaman AI features. It converts the single-package CLI into a monorepo, creates a shared `@vaaman/core` library with unified types and an OpenRouter AI client, and ensures backward compatibility with the existing CLI.

## What Was Built

### 1. Monorepo Structure

```
vaaman-cli/
├── apps/
│   └── cli/                    # Existing CLI, migrated here
│       ├── src/
│       │   ├── index.ts        # CLI entry (Commander)
│       │   ├── runner.ts       # npm install + strace
│       │   ├── reporter.ts     # terminal output
│       │   ├── types.ts        # → re-exports from @vaaman/core
│       │   ├── prescan/        # static tarball analysis
│       │   ├── monitor/        # runtime monitoring (strace, dtrace)
│       │   └── reasoner/       # rule-based reasoner (fallback)
│       ├── package.json
│       └── tsconfig.json
│
├── packages/
│   └── core/                   # Shared library (@vaaman/core)
│       ├── src/
│       │   ├── index.ts        # barrel export
│       │   ├── types/
│       │   │   ├── index.ts    # barrel re-export
│       │   │   ├── scan.ts     # ScanResult, PreScanResult, InstallResult, events
│       │   │   └── ai.ts       # AIVerdict, TrustScore, AgentFinding, SwarmResult
│       │   └── ai/
│       │       ├── index.ts    # barrel export
│       │       ├── openrouter.ts  # OpenRouter unified API client
│       │       ├── cache.ts       # JSON file-based LLM response cache
│       │       └── tools.ts       # Agent tool definitions
│       ├── package.json
│       └── tsconfig.json
│
├── docs/                        # Phase documentation
│   └── phase-1-foundation.md
├── package.json                 # Root: npm workspaces
├── tsconfig.base.json           # Shared TS config
└── .gitignore
```

### 2. `@vaaman/core` — Shared Library

**Package:** `packages/core`  
**Exports:** `@vaaman/core`, `@vaaman/core/types`, `@vaaman/core/ai`

#### Types (`packages/core/src/types/`)

- **scan.ts** — All monitoring and scan result types (`MonitorEvent`, `ProcessEvent`, `NetworkEvent`, `FilesystemEvent`, `ScanResult`, `PreScanResult`, `InstallResult`, `VaamanReport`)
- **ai.ts** — AI layer types (`AIVerdict`, `IntentType`, `DeepIntelOutput`, `TrustScore`, `NormalizedCVE`, `AgentFinding`, `SwarmResult`, `PackageNode`, `ChainNode`, `CVENode`, `GraphEdge`)

These types are the single source of truth consumed by all packages. The existing `apps/cli/src/types.ts` now re-exports from `@vaaman/core` for backward compatibility.

#### OpenRouter Client (`packages/core/src/ai/openrouter.ts`)

Unified AI client that abstracts away LLM provider complexity:

- **Single API endpoint:** `https://openrouter.ai/api/v1/chat/completions`
- **Model-agnostic:** Swap models via `model` param or `VAAMAN_MODEL` env var
- **Tool calls:** Supports Claude-style tool_use via OpenRouter's translation layer
- **Error handling:** Returns structured error response instead of throwing
- **Headers:** `Authorization`, `HTTP-Referer`, `X-Title` (required by OpenRouter)

**Key design decisions:**
- Temperature = 0.1 for all security analysis (consistency over creativity)
- `fetch()`-based (zero additional HTTP dependencies)
- Tool calls normalized to OpenAI format regardless of underlying model

**API:**
```typescript
import { OpenRouterClient, getOpenRouter } from '@vaaman/core'

const client = getOpenRouter()
const response = await client.chat({
  model: 'anthropic/claude-sonnet-4-20250514',
  messages: [{ role: 'user', content: '...' }],
  maxTokens: 1000,
})
```

#### LLM Cache (`packages/core/src/ai/cache.ts`)

JSON file-based response cache stored at `~/.vaaman/cache/llm-cache.json`:

- **Cache key:** `{packageName}@{version}:{model}:{promptHash}`
- **Debounced writes:** Saves at most every 5 seconds
- **Singleton:** `getLLMCache()` returns the shared instance
- **Schema:**
  ```json
  {
    "version": 1,
    "entries": {
      "lodash@4.18.1:claude-sonnet-4:abc123": {
        "result": { "verdict": "SAFE", ... },
        "model": "anthropic/claude-sonnet-4-20250514",
        "tokensUsed": 450,
        "createdAt": "2026-05-23T...",
        "accessCount": 3
      }
    }
  }
  ```

**Why JSON file instead of SQLite:**
- Zero native dependencies (no build tools needed)
- Sufficient for <1000 entries
- Upgrade path: swap to `better-sqlite3` or `sql.js` when scale demands it

#### Tool Definitions (`packages/core/src/ai/tools.ts`)

Five tools available to swarm agents via OpenRouter's tool_use:

| Tool | Description |
|------|-------------|
| `run_prescan` | Static tarball analysis (lifecycle scripts, AST, chains, score) |
| `run_behavioral` | Runtime strace monitoring (events, attack chains) |
| `query_osv` | Fetch CVEs from osv.dev |
| `score_intent` | Deep Intel intent classification |
| `query_graph` | Neo4j threat graph queries |

### 3. TypeScript Configuration

**`tsconfig.base.json`** — Shared config for all packages:
- Target: ES2022
- Module: ES2022 with `moduleResolution: bundler`
- Strict mode, declarations, source maps

**Per-package tsconfigs** extend the base with `outDir` and `rootDir`.

**Why `moduleResolution: bundler` over `NodeNext`:**
- Does not require `.js` extensions in relative imports
- Compatible with npm workspaces resolution
- Works with both `tsx` (dev) and `tsc` (build)

### 4. Backward Compatibility

The existing CLI source files continue using relative imports:
```typescript
// apps/cli/src/runner.ts — unchanged
import type { MonitorEvent, ScanResult, ThreatSignal } from './types.js'

// apps/cli/src/types.ts — now re-exports from @vaaman/core
export { type MonitorEvent, type ScanResult, ... } from '@vaaman/core'
```

No existing code was broken. The prescan types (`src/prescan/types.ts`) remain local and will be aligned with `@vaaman/core` types in Phase 2.

### 5. Legacy Code Preservation

The previous rule-based implementations (`deep-intel-filter/`, `trust-engine/`) are preserved in `apps/cli/src/` but excluded from the build. They serve as reference for the AI-native implementations in Phases 2-3.

## Build Verification

```bash
# Full build (both packages)
npm run build
# → @vaaman/core compiles cleanly
# → vaaman CLI compiles cleanly

# Smoke test
node apps/cli/dist/index.js --help
# → Shows: pre-scan, install, help commands

node apps/cli/dist/index.js pre-scan lodash
# → Downloads, scans, scores lodash correctly
# → Saves JSON output to apps/cli/dist/json/
```

## Dependencies Added

| Package | Where | Purpose |
|---------|-------|---------|
| `rimraf` | Root (dev) | Cross-platform `rm -rf` for clean script |
| (none else) | — | Core package has zero non-dev dependencies |

## What's NOT in Phase 1

- **No AI integration yet** — OpenRouter client exists but isn't called
- **No Deep Intel filter** — comes in Phase 2
- **No Trust Engine** — comes in Phase 3
- **No agentic loops** — comes in Phase 4
- **No swarm orchestration** — comes in Phase 5-6
- **No web dashboard** — comes in Phase 5
- **No Neo4j integration** — comes in Phase 6

## Next: Phase 2 — Deep Intel Filter

The next phase builds `packages/deep-intel`:
- AI-native intent classification via OpenRouter
- Contextual primitive analysis (is `eval` legitimate here?)
- Package type classification (CLI, library, framework, etc.)
- Suppression engine for known-good patterns
- Operational legitimacy scoring

---

*Phase 1 complete. Foundation laid. Ready for AI.*
