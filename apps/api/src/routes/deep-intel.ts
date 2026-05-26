// Vaaman API — Deep Intel Route
// POST /api/deep-intel — runs pre-scan + AI intent classification
// Emits events via SSE: intel:progress, intel:thinking, intel:result

import type { FastifyInstance } from 'fastify'
import { events } from '../services/events.js'
import { runPreScan } from '../services/scanner.js'
import { adaptToCore, importDeepIntel } from '../services/helpers.js'

export async function deepIntelRoutes(app: FastifyInstance) {
  app.post('/deep-intel', async (request, reply) => {
    const { package: pkg, version } = request.body as { package: string; version?: string }
    if (!pkg) return reply.status(400).send({ error: 'package required' })

    const packageName = `${pkg}${version ? `@${version}` : ''}`
    const scanId = `di-${Date.now()}`

    events.emitEvent('scan:started', { scanId, package: pkg, mode: 'deep-intel' })

    // Stage 1: Pre-scan
    events.emitEvent('scan:progress', { scanId, stage: 'pre-scan', message: 'Running static analysis...', package: pkg })
    const preScan = await runPreScan(pkg)
    if (!preScan) {
      events.emitEvent('scan:complete', { scanId, package: pkg, status: 'failed' })
      return reply.status(500).send({ error: 'Pre-scan failed' })
    }
    events.emitEvent('scan:progress', { scanId, stage: 'pre-scan', message: `${preScan.filesScanned} files, score ${preScan.score}/100`, package: pkg })

    // Stage 2: Deep Intel
    if (!process.env.OPENROUTER_API_KEY) {
      return reply.status(400).send({ error: 'OPENROUTER_API_KEY not set' })
    }

    const runDeepIntelFn = await importDeepIntel()
    if (!runDeepIntelFn) {
      return reply.status(500).send({ error: 'Deep Intel engine not available' })
    }

    events.emitEvent('intel:result', { scanId, stage: 'intel', message: 'Classifying package type and intent via AI...', package: pkg })

    const corePreScan = adaptToCore(preScan)
    const startIntel = Date.now()
    const deepIntel = await runDeepIntelFn(corePreScan)
    const intelLatency = Date.now() - startIntel

    events.emitEvent('intel:result', {
      scanId, stage: 'intel',
      message: deepIntel.packageType,
      package: pkg,
      packageType: deepIntel.packageType,
      legitimacyVerdict: deepIntel.legitimacyVerdict,
      legitimacyScore: deepIntel.legitimacyScore,
      suppressedCount: deepIntel.suppressedCount,
      intentCount: deepIntel.intents?.length ?? 0,
    })

    events.emitEvent('scan:complete', {
      scanId, package: pkg, version: preScan.version,
      verdict: mapRecommendation(preScan.recommendation),
      score: preScan.score,
      mode: 'deep-intel',
      deepIntel: {
        packageType: deepIntel.packageType,
        legitimacyVerdict: deepIntel.legitimacyVerdict,
        legitimacyScore: deepIntel.legitimacyScore,
        intents: deepIntel.intents?.slice(0, 10) ?? [],
        reasoning: deepIntel.reasoning,
        latencyMs: intelLatency,
      },
    })

    return {
      package: pkg,
      version: preScan.version,
      scanId,
      preScanScore: preScan.score,
      preScanHits: preScan.primitiveHits?.length ?? 0,
      preScanChains: preScan.behavioralChains?.length ?? 0,
      deepIntel: {
        packageType: deepIntel.packageType,
        legitimacyVerdict: deepIntel.legitimacyVerdict,
        legitimacyScore: deepIntel.legitimacyScore,
        suppressedCount: deepIntel.suppressedCount,
        intents: deepIntel.intents?.slice(0, 20) ?? [],
        reasoning: deepIntel.reasoning,
        latencyMs: intelLatency,
      },
    }
  })
}

function mapRecommendation(rec: string): string {
  switch (rec) { case 'proceed': return 'SAFE'; case 'caution': return 'SUSPICIOUS'; case 'block': return 'DANGEROUS'; default: return 'SUSPICIOUS'; }
}
