# Phase 3 — Trust Engine (AI-Native)

**Status:** ✅ Complete  
**Duration:** ~1 day  
**Depends on:** Phase 1 (Foundation) + Phase 2 (Deep Intel)

---

## Overview

Phase 3 implements the AI-native Trust Engine — a multi-dimensional trust scoring system that answers: **"Can this software be trusted end-to-end?"**

It synthesizes six dimensions into a single trust grade (A-F), combining ecosystem metadata, AI-powered identity analysis, behavioral signals, and deception detection.

## Architecture

```
PreScanResult + DeepIntelOutput
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 1: Fetch Ecosystem Data                           │
│  npm registry API → metadata (age, downloads, deps, etc.)│
│  deterministic, no AI                                    │
└───────────────────────────┬─────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
┌───────────────┐  ┌───────────────┐  ┌──────────────┐
│  Stage 2a:    │  │  Stage 2b:    │  │  Stage 2c:   │
│  Ecosystem    │  │  Identity     │  │  Capability   │
│  Scoring (AI) │  │  Analysis (AI)│  │  Inference(AI)│
└───────┬───────┘  └───────┬───────┘  └──────┬───────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐
│  Stage 3:     │  │  Stage 4:     │
│  Deception    │  │  Transparency │
│  Detection    │  │  Scoring      │
│  (determinist)│  │  (det+AI)     │
└───────┬───────┘  └───────┬───────┘
        │                  │
        └────────┬─────────┘
                 ▼
        ┌─────────────────┐
        │  Trust Score     │
        │  Aggregator      │
        │  (weighted avg)  │
        └────────┬─────────┘
                 ▼
           TrustEngineOutput
```

## What Was Built

### 1. Ecosystem Scoring (`dimensions/ecosystem.ts`)

**AI call: 1** — analyzes npm registry metadata for trust signals.

Fetches from `https://registry.npmjs.org/<pkg>`:
- Package age, version count, maintainers
- License, repository, homepage
- README presence, keywords
- Dependency counts

AI reasons about contradictory signals:
- High downloads but very new package → bot-inflated
- No README + no license + no repo → throwaway package
- Single maintainer, no other packages → sock puppet account
- Name is typosquat of popular package → malicious

**Why AI:** Simple rules can't distinguish between a genuinely popular new package and a bot-inflated malicious one. The AI considers the full pattern.

### 2. Identity Analysis (`dimensions/identity.ts`)

**AI call: 1** — compares claimed identity with behavioral reality.

Input: package description, keywords, dependencies + Deep Intel output (package type, legitimacy, intent signals)

Output: claimed identity, inferred identity, conflicts, alignment score.

Key signals:
- A package described as "lightweight date formatter" with child_process + network → identity conflict
- Keywords say "React component" but deps include Express + database → framework/library mismatch
- Deep Intel says "library" but behavior shows CLI tool capabilities → type conflict

### 3. Capability Inference (`dimensions/capability.ts`)

**AI call: 1** — compares actual capabilities with legitimate needs for the package type.

Context-aware baseline per type:
| Package Type | Legitimate Capabilities |
|-------------|------------------------|
| cli-tool | child_process, fs, process.env, network |
| build-tool | eval (codegen), fs write, child_process |
| framework | eval (templates), dynamic imports |
| library | Pure computation — no child_process, network, fs |
| dev-tool | child_process, fs |
| runtime-utility | network, fs (if DB/logging) |

Capabilities outside the type's normal range lower the score.

### 4. Deception Detection (`dimensions/deception.ts`)

**Deterministic (~80%)** — five rule-based checks for common deception patterns:

1. Passive type (library, runtime-utility) with lifecycle scripts
2. Postinstall exists but README/description never mentions install behavior
3. Identity conflicts from AI analysis
4. Critical intent signals (payload-execution, credential-harvesting)
5. Claims "no dependencies" but has network/fetch primitives

Score is inverted in aggregation: high deception = low trust.

### 5. Transparency Scoring (`dimensions/transparency.ts`)

**Deterministic base + AI adjustment** — measures documentation quality.

Deterministic checks: README, license, repository, changelog, contributing guide, lifecycle script documentation.

AI adjustment: when gaps exist, AI assesses whether they're normal for the package type or a red flag. Adjusts score ±15.

### 6. Trust Score Aggregator (`scorer.ts`)

Weighted average across six dimensions:

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Identity | 25% | Claims vs reality is the strongest trust signal |
| Intent (Deep Intel) | 25% | AI-classified behavioral intent |
| Capability | 20% | What it CAN do vs what it SHOULD |
| Ecosystem | 15% | Lower — popular packages can be compromised |
| Deception | 10% | Gap between claims and behavior (inverted) |
| Transparency | 5% | Documentation quality (amplifier) |

Grading:
- A: ≥90 — high trust, behaves as expected
- B: ≥75 — good trust, minor flags
- C: ≥55 — moderate concerns, review flags
- D: ≥35 — significant concerns
- F: <35 — likely untrustworthy

## CLI Integration

New command: `vaaman trust <package>`

```bash
vaaman trust lodash              # Full pipeline: pre-scan → deep-intel → trust
vaaman trust lodash --json       # Machine-readable JSON output
vaaman trust lodash --no-ai      # Skip AI, show pre-scan only
```

**Execution flow:**
1. Run pre-scan
2. Run Deep Intel pipeline (package type + intent + legitimacy)
3. Fetch npm ecosystem data
4. Run trust dimensions in parallel (ecosystem, identity, capability)
5. Run dependent dimensions (deception, transparency)
6. Aggregate trust score

**Output:**
```
── Vaaman Trust Report ────────────────────
Package:        lodash@4.18.1
Trust Grade:    B — 78/100
AI latency:     4500ms

Score Breakdown:
  Ecosystem:     ██████████ 100/100
  Identity:      ████████░░ 82/100
  Behavior:      ███████░░░ 70/100
  Intent:        ███████░░░ 70/100
  Deception:     ██░░░░░░░░ 15/100 (high = bad)
  Transparency:  ████████░░ 85/100

Flags (2):
  ▸ [capability] child_process usage in utility library
  ▸ [deception] Legacy compatibility shims not documented

⚡ Moderate trust — review the flags above before deploying.
```

## File Structure

```
packages/trust-engine/
├── src/
│   ├── index.ts                  # TrustEnginePipeline orchestrator + runTrustEngine()
│   ├── types.ts                  # Internal types for all dimensions
│   ├── scorer.ts                 # Weighted trust score aggregator
│   ├── fetcher.ts                # npm registry API data fetcher
│   └── dimensions/
│       ├── ecosystem.ts          # EcosystemAnalyzer (AI)
│       ├── identity.ts           # IdentityAnalyzer (AI)
│       ├── deception.ts          # DeceptionDetector (deterministic)
│       ├── transparency.ts       # TransparencyAnalyzer (deterministic + AI)
│       └── capability.ts         # CapabilityAnalyzer (AI)
├── package.json
└── tsconfig.json
```

## Dependencies

| Package | Why |
|---------|-----|
| `@vaaman/core` | OpenRouter client, LLM cache, shared types |

No new npm dependencies. The npm registry fetch uses the built-in `fetch()` API.

## Key Design Decisions

### Four AI calls, three parallel
Ecosystem, identity, and capability run in parallel (independent). Deception runs after identity (depends on conflicts). Transparency runs last. Total: ~4-6s for the full pipeline.

### AI-native, not agentic
Same pattern as Deep Intel: fixed pipeline structure. The LLM answers specific questions at predetermined points. No autonomous tool use, no loops.

### Deception is mostly deterministic
The LLM already reasons about identity and intent. Deception is a synthesis layer that doesn't need another round-trip. Rules handle 80% of cases.

### Ecosystem data via npm registry
Fetched fresh each scan (no stale cache). The AI reasons about the full metadata picture — not just one signal.

## What the Previous Implementation Got Wrong

The old `trust-engine/` (now archived in `apps/cli/src/trust-engine/`) had:
- 7 analysis engines, all regex-based — zero AI
- Imports from nonexistent `@vaaman/shared-types` package
- Arbitrary weighting with no empirical basis (`.concealmentPenalty`, `.operationalMismatchPenalty`)
- No integration with actual npm package data

The new implementation fixes all of these.

## Limitations (Phase 3)

- **No install-time behavioral integration** — doesn't consume `InstallResult` from strace monitoring. Coming in Phase 4.
- **No historical trust history** — each scan is independent. Coming in Phase 5 (Swarm Engine graph memory).
- **Weekly download count not fetched** — npm registry doesn't expose downloads in the package endpoint. Can be added via npmjs.org API.

## Next: Phase 4 — Agentic Layer

The Agentic Layer introduces true agent behavior:
- BaseAgent class with multi-pass tool loop
- AI Reasoning Agent (replaces rule-based reasoner)
- Tool execution (prescan, behavioral, osv query, graph query)
- Cache management and trigger logic

---

*Phase 3 complete. Trust Engine operational. Multi-dimensional AI trust scoring live.*
