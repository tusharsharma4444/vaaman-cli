# Phase 4 — Agentic Layer

**Status:** ✅ Complete  
**Duration:** ~1 day  
**Depends on:** Phase 1 (Foundation) + Phase 2 (Deep Intel)

---

## Overview

Phase 4 implements the Agentic Layer — the bridge between AI-assisted classification (Deep Intel, Trust Engine) and true autonomous agents (Swarm Engine). It introduces:

1. **BaseAgent** — reusable multi-pass tool loop for any agent
2. **LLM Reasoner** — single-pass AI that replaces the rule-based reasoner
3. **Tool Executor** — bridges agent tool calls to actual Vaaman functions
4. **Prompt Engineering** — the system prompts that make security reasoning grounded

## Architecture

```
┌─────────────────────────────────────────────┐
│  BaseAgent                                   │
│  abstract class: prompt → LLM → tools → loop│
│                                             │
│  ┌───────────────┐  ┌────────────────────┐  │
│  │ LLM Reasoner  │  │ Future: CVE Agent  │  │
│  │ (single-pass) │  │ (multi-pass)       │  │
│  │ no tools      │  │ 3-5 tool calls     │  │
│  └───────────────┘  └────────────────────┘  │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│  Tool Executor                               │
│  Bridges agent tool_calls → Vaaman functions│
│                                             │
│  run_prescan → fetcher.ts                   │
│  run_behavioral → runner.ts                 │
│  query_osv → (Phase 5)                      │
│  query_graph → (Phase 5)                    │
│  score_intent → @vaaman/deep-intel          │
└─────────────────────────────────────────────┘
```

## What Was Built

### 1. BaseAgent (`ai/base-agent.ts`)

Reusable abstract class implementing the multi-pass tool loop:

```typescript
class BaseAgent {
  async run(initialPrompt: string): Promise<AgentResult>
  protected abstract extractOutput(content: string): unknown
  protected async executeTool(name, args): Promise<unknown>
}
```

**Loop pattern:**
1. Seed conversation with initial prompt + system prompt
2. Call OpenRouter with tools enabled
3. If `stop_reason = 'stop'` → agent is done, extract output
4. If `stop_reason = 'tool_calls'` → execute tools, feed results back, loop
5. If `maxRounds` reached → return partial result

**Configurable:**
- `model` — default `claude-sonnet-4-20250514`
- `maxRounds` — default 3, prevents infinite loops
- `temperature` — default 0.1
- `systemPrompt` — subclass provides

### 2. LLM Reasoner (`ai/llm-reasoner.ts`)

Single-pass agent that replaces the rule-based `Reasoner`. All data is collected upfront — no tools needed.

**When it runs:**
- `--ai` flag on install command AND `OPENROUTER_API_KEY` set
- Automatically skipped if no API key (falls back to rule-based)
- Failed AI calls fall back gracefully to rule-based verdict

**Input:**
```typescript
{
  package: { name, version },
  preScan: PreScanResult | null,  // optional context
  events: { count, topEvents },
  chains: string[],
  installDurationMs: number
}
```

**Output:** `AIVerdict` with verdict, confidence, summary, whatItDid, whyItsDangerous, remediation, novelPatterns, intentClassification.

**Cache:** Results cached by `{package}@{version}:v2` in the LLM cache.

**Trigger logic (`shouldUseLLM`):**
```typescript
chains.length > 0          → use AI
preScan.score > 40         → use AI
primitiveHits.length > 5   → use AI
eventCount > 10            → use AI
otherwise                  → rule-based (free, fast)
```

### 3. Tool Executor (`ai/tool-executor.ts`)

Wires agent tool calls to actual Vaaman implementations. Agents call tools by name via OpenRouter's tool_use — the executor dispatches to the real function.

**Wiring pattern:**
```typescript
const executor = getToolExecutor()
  .onPrescan(async (pkg, ver) => preScan({ packageName: pkg, version: ver }))
  .onBehavioral(async (pkg, ver, timeout) => runInstall({ ... }))
  .onOSV(async (pkg, eco) => queryOSV(pkg, eco))
  .onGraph(async (cypher, params) => neo4j.run(cypher, params))
```

**Tool result contract:**
```typescript
interface ToolResult<T> {
  data: T              // structured, summarized
  confidence: number   // 0-100
  flags: string[]      // signals for agent
  summary: string      // 1-sentence for agent context
}
```

Tools return **reasoned data** — never raw strace output or full scan results. This conserves the agent's context window.

### 4. Prompt Builder (`ai/prompt-builder.ts`)

The system prompt that makes Vaaman's AI produce grounded security verdicts:

**Key design elements:**
- **Reasoning process** — explicit steps: classify type → assess legitimate needs → compare → score
- **Legitimacy rules** — specific examples of when a primitive is NOT malicious
- **Anti-hallucination** — "base your verdict ONLY on provided evidence"
- **Confidence calibration** — "if evidence is ambiguous, lower confidence — do not inflate it"
- **Structured output** — exact JSON schema, no preamble, no markdown fences

### 5. Verdict Parser (`ai/verdict-parser.ts`)

Robust JSON parsing with fallback extraction:
1. Strip markdown fences (` ```json `, ` ``` `)
2. Try `JSON.parse` 
3. On failure: extract fields via regex (`"verdict": "DANGEROUS"`)
4. Validate all fields against allowed values
5. Return partial verdict with `parseError: true` if needed

### 6. CLI Integration

```bash
vaaman install lodash --ai    # AI-powered reasoning
vaaman install lodash         # Rule-based (default, no API key needed)
```

When `--ai` is used:
1. Run install with strace monitoring (rule-based reasoner runs first)
2. Run pre-scan for static context (primitives, chains)
3. Call LLM Reasoner with full context
4. Print augmented report with AI verdict

**Report output (with AI):**
```
── VAAMAN SECURITY REPORT ──
  Verdict  🟡  SUSPICIOUS
  Duration     42.3s
  Events       5 monitored
  Signals      2 found

  AI Verdict
  SAFE (confidence: 88%)
  lodash is a well-known utility library. The child_process hits are
  in legacy Node.js compatibility shims, not in postinstall scripts.
  No runtime behavioral anomalies were detected.
  What it did: Read process environment; Used child_process for legacy compat
  Remediation: Package appears safe — no action needed
  model: anthropic/claude-sonnet-4-20250514, latency: 2100ms
```

## File Structure

```
apps/cli/src/ai/
├── index.ts              # Barrel exports
├── base-agent.ts         # Abstract BaseAgent (multi-pass tool loop)
├── llm-reasoner.ts       # LLMReasoner (single-pass) + shouldUseLLM()
├── prompt-builder.ts     # System prompt + buildReasonerPrompt()
├── verdict-parser.ts     # parseVerdict() + fallback extraction
└── tool-executor.ts      # ToolExecutor + getToolExecutor()
```

## Dependencies

No new npm dependencies. Uses `@vaaman/core` (OpenRouter client, types) and `@vaaman/deep-intel` (for score_intent tool).

## Key Design Decisions

### Single-pass for AI Reasoner, Multi-pass for Swarm
The install-time AI reasoner is single-pass because all data is collected before reasoning. Future swarm agents (CVE, exploit, blast) are multi-pass because they need to adaptively decide what to investigate.

### Rule-based is always the fallback
If OpenRouter call fails, confidence < 40, or parse error → fall back to rule-based reasoner. The user always gets a verdict.

### Tool results are reasoned, not raw
Agents receive summarized tool results with `confidence`, `flags`, and `summary` — not raw strace output. This conserves context window and prevents the LLM from wasting tokens parsing raw data.

### Temperature = 0.1 for all security analysis
Security verdicts must be consistent. Higher temperatures produce varied outputs that break JSON parsing and produce inconsistent verdicts on the same input.

## Limitations (Phase 4)

- **CVE Agent not implemented** — the BaseAgent supports multi-pass but no CVE-specific agent exists yet (Phase 5)
- **No graph queries** — `query_graph` function defined but no graph database connected
- **No OSV queries** — `query_osv` tool is defined but client not implemented (Phase 5)
- **No auto-trigger** — `--ai` must be explicit. Auto-trigger based on conditions could be added.

## Next: Phase 5 — Dashboard

The React + Mermaid.js web dashboard for visualizing:
- Scan results and AI verdicts
- Attack chain flowcharts
- Trust score breakdowns
- Swarm agent execution (SSE real-time)

---

*Phase 4 complete. Agentic Layer operational. BaseAgent + AI Reasoner live.*
