// Vaaman API — Trust Engine Route
// POST /api/trust — runs pre-scan + deep-intel + 6-dimension trust scoring
// Emits events via SSE: trust:computing, trust:result

import type { FastifyInstance } from 'fastify'
import { events } from '../services/events.js'
import { runPreScan } from '../services/scanner.js'
import { adaptToCore, importDeepIntel, importTrustEngine } from '../services/helpers.js'

export async function trustRoutes(app: FastifyInstance) {
  app.post('/trust', async (request, reply) => {
    const { package: pkg, version } = request.body as { package: string; version?: string }
    if (!pkg) return reply.status(400).send({ error: 'package required' })

    const packageName = `${pkg}${version ? `@${version}` : ''}`
    const scanId = `tr-${Date.now()}`

    events.emitEvent('scan:started', { scanId, package: pkg, mode: 'trust' })

    if (!process.env.OPENROUTER_API_KEY) {
      return reply.status(400).send({ error: 'OPENROUTER_API_KEY not set' })
    }

    // Stage 1: Pre-scan
    events.emitEvent('scan:progress', { scanId, stage: 'pre-scan', message: 'Running static analysis...', package: pkg })
    const preScan = await runPreScan(pkg)
    if (!preScan) {
      events.emitEvent('scan:complete', { scanId, package: pkg, status: 'failed' })
      return reply.status(500).send({ error: 'Pre-scan failed' })
    }

    // Stage 2: Deep Intel
    const runDeepIntelFn = await importDeepIntel()
    if (!runDeepIntelFn) return reply.status(500).send({ error: 'Deep Intel not available' })

    events.emitEvent('intel:result', { scanId, stage: 'intel', message: 'AI classifying package type...', package: pkg })
    const corePreScan = adaptToCore(preScan)
    const deepIntel = await runDeepIntelFn(corePreScan)

    events.emitEvent('intel:result', {
      scanId, stage: 'intel',
      message: `${deepIntel.packageType}, legitimacy: ${deepIntel.legitimacyVerdict}`,
      package: pkg, packageType: deepIntel.packageType,
    })

    // Stage 3: Trust Engine
    const runTrustFn = await importTrustEngine()
    if (!runTrustFn) return reply.status(500).send({ error: 'Trust Engine not available' })

    events.emitEvent('trust:result', { scanId, stage: 'trust', message: 'Computing 6-dimension trust score...', package: pkg })
    const startTrust = Date.now()
    const trust = await runTrustFn(corePreScan, deepIntel)

    events.emitEvent('trust:result', {
      scanId, stage: 'trust',
      message: `Grade: ${trust.trust.grade} (${trust.trust.overall}/100)`,
      package: pkg,
      grade: trust.trust.grade,
      score: trust.trust.overall,
      breakdown: trust.trust.breakdown,
      flags: trust.trust.flags?.slice(0, 10) ?? [],
    })

    events.emitEvent('scan:complete', {
      scanId, package: pkg, version: preScan.version,
      mode: 'trust',
      verdict: mapRecommendation(preScan.recommendation),
      trust: { grade: trust.trust.grade, overall: trust.trust.overall, breakdown: trust.trust.breakdown },
    })

    return {
      package: pkg,
      version: preScan.version,
      scanId,
      preScanScore: preScan.score,
      deepIntel: {
        packageType: deepIntel.packageType,
        legitimacyVerdict: deepIntel.legitimacyVerdict,
        legitimacyScore: deepIntel.legitimacyScore,
      },
      trust: {
        overall: trust.trust.overall,
        grade: trust.trust.grade,
        breakdown: trust.trust.breakdown,
        flags: trust.trust.flags?.slice(0, 15) ?? [],
      },
    }
  })
}

function mapRecommendation(rec: string): string {
  switch (rec) { case 'proceed': return 'SAFE'; case 'caution': return 'SUSPICIOUS'; case 'block': return 'DANGEROUS'; default: return 'SUSPICIOUS'; }
}
