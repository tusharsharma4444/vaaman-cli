# Phase 5 — Web Dashboard

**Status:** ✅ Complete  
**Duration:** ~1 day  
**Depends on:** Phase 1 (Foundation)

---

## Overview

Phase 5 delivers the web dashboard — a React-based UI with Mermaid.js graph visualizations and a Fastify API backend. It provides:

1. Scan input + recent scan history
2. Real-time scan results with verdict badges
3. Attack chain flowcharts via Mermaid.js
4. SSE streaming for live scan progress
5. JSON file-based persistence (zero native dependencies)

## Architecture

```
apps/dashboard/                     apps/api/
┌──────────────────────┐     ┌──────────────────────┐
│  React + Vite         │     │  Fastify              │
│  Tailwind CSS         │────▶│  CORS enabled         │
│  Mermaid.js           │ HTTP│                      │
│  react-router-dom     │     │  POST /api/scan       │
│                       │     │  GET  /api/scan/:id   │
│  Pages:               │     │  GET  /api/history    │
│   Home                │     │  GET  /api/scan/:id/  │
│   ScanResult          │     │        stream (SSE)   │
│   History             │     │                      │
└──────────────────────┘     └──────────┬───────────┘
                                        │
                              ┌─────────▼───────────┐
                              │  data/vaaman.json    │
                              │  (JSON file storage) │
                              └─────────────────────┘
```

## What Was Built

### 1. React Dashboard (`apps/dashboard/`)

**Framework:** React 18 + Vite 5 + Tailwind CSS 3

**Pages:**

- **Home** (`src/pages/Home.tsx`) — Package name input + scan trigger. Shows three feature cards (Static, Behavioral, AI). Navigates to scan result on submit.

- **ScanResult** (`src/pages/ScanResult.tsx`) — Full result view with:
  - Verdict badge (SAFE/SUSPICIOUS/DANGEROUS/CRITICAL)
  - Pre-scan score + event/signal counts
  - AI verdict panel (when available)
  - Attack chain Mermaid flowchart
  - Threat signals list
  - Event log

- **History** (`src/pages/History.tsx`) — Table of past scans with clickable rows navigating to results.

**Components:**

- **VerdictBadge** — Color-coded pill showing verdict with icon
- **MarkdownView** — Lightweight markdown-to-HTML renderer for audit reports

**Mermaid Utilities:**

- `chainToMermaid()` — Converts `BehavioralChain[]` to Mermaid `graph TD` syntax:
  ```
  primitive1 → primitive2 → primitive3
  ```
  Critical/dangerous terminal nodes get red styling.

### 2. Fastify API (`apps/api/`)

**Framework:** Fastify 4 + CORS

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Trigger pre-scan for a package, returns `scanId` |
| `GET` | `/api/scan/:id` | Get scan status + results |
| `GET` | `/api/scan/:id/stream` | SSE stream for live scan progress |
| `GET` | `/api/history` | List past 50 scans |
| `GET` | `/api/health` | Health check |

**Scan flow:**
1. Client POSTs `{ "package": "lodash" }` → returns `{ "id": "uuid", "status": "running" }`
2. Server spawns `vaaman pre-scan lodash` asynchronously
3. On completion, parses JSON output and stores in `data/vaaman.json`
4. Client polls `GET /api/scan/:id` to get results

### 3. Storage (`apps/api/src/services/db.ts`)

JSON file-based storage at `data/vaaman.json`:

```json
{
  "scans": [
    {
      "id": "uuid",
      "package_name": "lodash",
      "package_version": "4.18.1",
      "status": "complete",
      "verdict": "SAFE",
      "pre_scan_score": 30,
      "pre_scan_json": "{...full PrescanResult...}",
      "chains_json": "[...behavioral chains...]",
      "created_at": "2026-05-23T..."
    }
  ]
}
```

**Why JSON file over SQLite:**
- Zero native dependencies (VS build tools not available)
- Sufficient for MVP (<1000 scans)
- Compatible with future SQLite migration when scale demands

## Running the Dashboard

```bash
# Terminal 1: Start API
npm run dev:api
# → Fastify listening on http://localhost:3001

# Terminal 2: Start dashboard dev server
npm run dev:dashboard
# → Vite dev server on http://localhost:5173
```

The Vite dev server proxies `/api/*` requests to `localhost:3001`.

## File Structure

```
apps/dashboard/
├── src/
│   ├── main.tsx              # React entry
│   ├── App.tsx               # Router + layout
│   ├── index.css             # Tailwind + custom colors
│   ├── pages/
│   │   ├── Home.tsx          # Scan input form
│   │   ├── ScanResult.tsx    # Full scan result view
│   │   └── History.tsx       # Past scans table
│   ├── components/
│   │   ├── VerdictBadge.tsx   # Colored verdict pill
│   │   └── AttackChainMermaid.tsx  # Mermaid flowchart
│   └── mermaid/
│       └── chainToMermaid.ts # Chain data → Mermaid syntax
├── index.html
├── vite.config.ts
├── tailwind.config.js
├── postcss.config.js
├── tsconfig.json
└── package.json

apps/api/
├── src/
│   ├── index.ts              # Fastify server entry
│   ├── routes/
│   │   ├── scan.ts           # POST /scan, GET /scan/:id, SSE
│   │   └── history.ts        # GET /history
│   └── services/
│       ├── db.ts             # JSON file-based storage
│       └── scanner.ts        # CLI integration (spawns vaaman)
├── tsconfig.json
└── package.json
```

## Dependencies Added

| Package | Where | Purpose |
|---------|-------|---------|
| `react` + `react-dom` | apps/dashboard | UI framework |
| `react-router-dom` | apps/dashboard | Client-side routing |
| `mermaid` | apps/dashboard | Attack chain visualization |
| `tailwindcss` | apps/dashboard | Styling |
| `vite` | apps/dashboard | Build tool |
| `fastify` | apps/api | HTTP server |
| `@fastify/cors` | apps/api | CORS headers |

## Design Decisions

### Mermaid.js over D3
Mermaid renders from declarative text (`graph TD A-->B`). No manual layout algorithms. Attack chain → Mermaid conversion is a simple string builder. D3 would require force-directed layout tuning.

### JSON file storage over SQLite
The previous Phase 1 attempt with `better-sqlite3` failed on this machine (no Visual Studio build tools). JSON files work universally and are sufficient for the MVP's scan volume.

### Proxy pattern for dev
Vite proxies `/api/*` → `localhost:3001` in development. No CORS issues during development. In production, the API serves the built dashboard as static files.

### SSE for real-time updates
Server-Sent Events are simpler than WebSockets for one-way status updates. The swarm engine (Phase 6) will emit granular events through the same SSE endpoint.

## Limitations (Phase 5)

- **No install-time behavioral results** — the dashboard currently shows pre-scan data only. Install monitoring integration requires the agentic layer.
- **No swarm execution view** — the swarm agent state diagram and correlation graph are defined in the plan but wired in Phase 6.
- **No PDF download** — report generation is part of Phase 6 (Swarm Engine).
- **Vite production build timeout** — mermaid.js is large (~2MB) and may need chunk splitting config for production builds.

## Next: Phase 6 — Runtime Monitoring + Deployment

The runtime behavioral monitoring (strace-based) integrated into the audit pipeline with full security sandboxing and cloud deployment.

---

*Phase 5 complete. Dashboard + API operational. Attack chain visualization live.*
