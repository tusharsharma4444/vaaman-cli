# Phase 2 — Deep Intel Filter (AI-Native)

**Status:** ✅ Complete  
**Duration:** ~1 day  
**Depends on:** Phase 1 (Foundation)

---

## Overview

Phase 2 implements the AI-native Deep Intel filter — the contextual intelligence layer that answers: **"What is this package actually trying to do, and is that legitimate?"**

It replaces the previous rule-based approach (file path + regex) with OpenRouter-powered classification that understands context the way regex never could.

## What Was Built

### Architecture

```
PreScanResult (from pre-scan)
    │
    ▼
┌─────────────────────────┐
│  Stage 1: Package Type  │  ← AI (1 OpenRouter call)
│  Classifier             │     classifies: CLI tool, library, framework, etc.
└───────────┬─────────────┘
            │ packageType
            ▼
┌─────────────────────────┐
│  Stage 2: Primitive     │  ← AI (1-2 batched OpenRouter calls)
│  Contextualizer         │     classifies each primitive's INTENT in context
└───────────┬─────────────┘
            │ IntentClassification[]
            ▼
┌─────────────────────────┐
│  Stage 3: Suppression   │  ← DETERMINISTIC (no AI)
│  Engine                 │     removes known-good patterns (tests, build output)
└───────────┬─────────────┘
            │ filtered intents
            ▼
┌─────────────────────────┐
│  Stage 4: Legitimacy    │  ← AI (1 OpenRouter call)
│  Assessor               │     final verdict: likely-legitimate / uncertain / likely-malicious
└───────────┬─────────────┘
            │
            ▼
       DeepIntelOutput
```

### 1. Package Type Classifier (`src/intent/classifier.ts`)

**AI call: 1 per analysis**  
**Model:** `anthropic/claude-sonnet-4-20250514`  
**Input:** package name, version, pre-scan results (file count, lifecycle scripts, chains, primitive hits)  
**Output:** `PackageType` + confidence + reasoning

Available types:
- `cli-tool` — command-line executable
- `build-tool` — bundler, transpiler, compiler
- `framework` — UI framework (React, Vue, Angular, etc.)
- `library` — imported by other code
- `dev-tool` — linter, formatter, test runner
- `runtime-utility` — DB driver, HTTP client, logging
- `malicious-tool` — typosquatting, obfuscated
- `unknown` — cannot determine

**System prompt design:** Forces the model to classify into exactly one type with specific rules:
- A package with `bin` AND commands like "build", "dev" is a build-tool, not cli-tool
- Typo-squatted names (reaact, angluar) → malicious-tool
- README content is the strongest signal for classification

### 2. Primitive Contextualizer (`src/intent/contextualizer.ts`)

**AI calls: 1-2 per analysis (batched, 20 hits per call)**  
**Input:** primitive hits from AST scanner + package type  
**Output:** `IntentClassification[]` — one per hit

Intent types (the core intelligence):
| Type | Example | Risk |
|------|---------|------|
| `compiler-utility` | `eval` in webpack bootstrap | Safe — suppressed |
| `framework-internal` | `fetch` in React DOM | Safe — suppressed |
| `operational-legitimate` | `child_process` in CLI tool | Safe |
| `suspicious-execution` | `eval` in postinstall, unclear context | Needs scrutiny |
| `payload-execution` | `fetch` → `decode` → `eval` in same function | Near-certain malware |
| `credential-harvesting` | `process.env` + `fetch` in postinstall | Exfiltration |

**Why batching:** Each API call has 500ms-2s latency. With 30 primitive hits, 2 batched calls (2-4s) vs 30 individual calls (15-60s). Cache key includes package+version+type+batchIndex.

**Fallback:** If OpenRouter fails, all hits default to `suspicious-execution` with 30% confidence — conservative but doesn't silently pass malware.

### 3. Suppression Engine (`src/suppression/engine.ts`)

**Deterministic — zero API calls.** 10 rules covering:
- Test files (`__tests__`, `.test.ts`, `.spec.js`)
- Build output (`/dist/`, `/build/`, `.min.js`)
- Cache directories (`node_modules/.cache`, `.parcel-cache`)
- Fixtures and examples
- Webpack bootstrap
- TypeScript declarations
- Config files (process.env access is expected)
- CLI framework internals (commander, yargs)
- Generated code
- Benchmarks

**Why deterministic:** False positives from known-safe patterns waste API calls and dilute the AI's attention. The LLM should focus on genuinely ambiguous cases.

### 4. Legitimacy Assessor (`src/legitimacy/assessor.ts`)

**AI call: 1 per analysis**  
**Input:** filtered intents (post-suppression), behavioral chains, package type  
**Output:** `LegitimacyResult` — score 0-100, verdict, reasoning, capabilities needed vs exceeded

This is the final reasoning pass. The system prompt enforces the critical rule:
> "Never flag a signal as suspicious if it's normal for the package type."

Examples baked into the prompt:
- `eval` in a build tool = legitimate (code generation)
- `child_process` in a CLI tool = legitimate (spawning commands)
- `eval` + `fetch` + `child_process` in a React date-picker = highly suspicious

### 5. CLI Integration (`apps/cli/src/index.ts`)

New command: `vaaman deep-intel <package>`

```
vaaman deep-intel lodash            # Full AI analysis
vaaman deep-intel lodash --no-ai    # Deterministic only (no API key needed)
vaaman deep-intel lodash --json     # Machine-readable JSON output
```

**Execution flow:**
1. Run pre-scan (collect primitives + chains)
2. If `--no-ai` or no API key: print pre-scan summary, exit
3. Convert pre-scan result to canonical core type (adapter bridge)
4. Run Deep Intel pipeline (3-4 API calls)
5. Print formatted report or JSON

**Output format:**
```
── Vaaman Deep Intel Report ───────────────
Package:        lodash@4.18.1
Type:           library
Legitimacy:     likely-legitimate (85/100)
Signals:        3 active, 5 suppressed
AI latency:     3200ms

Assessment:
  Lodash is a well-known utility library. The child_process hits
  are in legacy Node.js compatibility shims, not postinstall scripts.
  No behavioral chains detected.

Active Signals (3):
  [suspicious-execution] — 3 hit(s)
    child_process.exec in _cloneRegExp.js:12
    child_process.exec in truncate.js:94
    child_process.exec in lodash.js:1482

────────────────────────────────────────────
```

## File Structure

```
packages/deep-intel/
├── src/
│   ├── index.ts                  # Pipeline orchestrator + runDeepIntel()
│   ├── types.ts                  # Internal types
│   ├── intent/
│   │   ├── classifier.ts         # PackageTypeClassifier (AI)
│   │   └── contextualizer.ts     # PrimitiveContextualizer (AI, batched)
│   ├── suppression/
│   │   └── engine.ts             # SuppressionEngine (deterministic, 10 rules)
│   └── legitimacy/
│       └── assessor.ts           # LegitimacyAssessor (AI)
├── package.json
└── tsconfig.json
```

## Dependencies

| Package | Why |
|---------|-----|
| `@vaaman/core` | OpenRouter client, LLM cache, shared types |

No new npm dependencies.

## Key Design Decisions

### AI-Native, Not Agentic
The pipeline structure is fixed. The LLM answers specific questions at predetermined points — it doesn't decide what to investigate. This means:
- Predictable latency (3-4 API calls, ~3-8s total)
- Predictable cost (~500-2000 tokens per call)
- Graceful fallback to deterministic mode on API failure

### Batch Primitive Classification
30 hits = 2 API calls instead of 30. Reduces cost ~15x and latency ~10x.

### Deterministic Suppression Before AI Legitimacy
Filtering known-good patterns deterministically means the legitimacy assessor focuses on the genuinely ambiguous cases. This improves both quality and cost.

### Adapter Bridge
The CLI uses `adaptToCorePreScan()` to bridge between the prescan's internal types and the canonical `@vaaman/core` types. This avoids rewriting the working prescan code while enabling clean integration.

## What the AI Sees vs What Regex Saw

| Scenario | Previous (Regex) | Deep Intel (AI) |
|----------|-----------------|-----------------|
| `eval` in webpack bundle | `hasDynamicExecution(snippet)` → suspicious ⚠ | "This is webpack's bootstrap module loader — normal for bundled output" ✅ |
| `child_process` in lodash | `hasDynamicExecution(snippet)` → suspicious ⚠ | "Legacy Node.js compatibility shim in a well-known utility library" ✅ |
| `fetch` + `eval` in postinstall | `hasRemote + hasDynamic` → payload execution ⚠ (same as above) | "Remote fetch + decode + eval in lifecycle script — near-certain malware" 🔴 |
| `process.env` in config file | `credential harvesting` ⚠ | Suppressed: config files legitimately read env vars ✅ |

## Build & Test

```bash
npm run build    # builds core → deep-intel → cli

# Deterministic mode (no API key needed)
node apps/cli/dist/index.js deep-intel --no-ai lodash

# Full AI analysis (requires OPENROUTER_API_KEY)
OPENROUTER_API_KEY=sk-or-v1-... node apps/cli/dist/index.js deep-intel lodash

# JSON output
node apps/cli/dist/index.js deep-intel --json lodash
```

## Limitations (Phase 2)

- **No behavioral correlation** — install-time strace events not yet integrated into deep-intel. Coming in Phase 4 (Agentic Layer).
- **No ecosystem metadata** — doesn't pull npm registry data (downloads, maintainers, age). Coming in Phase 3 (Trust Engine).
- **No graph memory** — each scan is independent, no cross-scan intelligence. Coming in Phase 5 (Swarm Engine).
- **English-only reasoning** — prompts and outputs are in English. Multi-language support not implemented.

## Next: Phase 3 — Trust Engine

The Trust Engine builds on Deep Intel output to compute a multi-dimensional trust score:
- Ecosystem score (registry metadata)
- Identity score (claims vs reality)
- Behavior score (what happened at install)
- Intent score (Deep Intel synthesis)
- Deception score (discrepancy detection)
- Transparency score (documentation gaps)

---

*Phase 2 complete. Deep Intel operational. AI-native intent classification live.*
