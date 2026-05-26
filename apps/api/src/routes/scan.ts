import type { FastifyInstance } from 'fastify'
import { randomUUID } from 'crypto'
import { db } from '../services/db.js'
import { events } from '../services/events.js'
import { runPreScan } from '../services/scanner.js'

export async function scanRoutes(app: FastifyInstance) {
  app.post('/scan', async (request, reply) => {
    const { package: pkg } = request.body as { package: string }
    if (!pkg) return reply.status(400).send({ error: 'package required' })

    const id = randomUUID()
    db.insert(id, pkg)

    events.emitEvent('scan:started', { scanId: id, package: pkg })

    runPreScan(pkg, id).then((result: any) => {
      if (result) {
        const verdict = result.recommendation === 'proceed' ? 'SAFE' : result.recommendation === 'caution' ? 'SUSPICIOUS' : 'DANGEROUS'
        db.updateComplete(id, verdict, result.version, result.score, JSON.stringify(result), JSON.stringify(result.behavioralChains ?? []))
        events.emitEvent('scan:complete', { scanId: id, package: pkg, version: result.version, verdict, score: result.score })
      } else {
        db.updateFailed(id)
        events.emitEvent('scan:complete', { scanId: id, package: pkg, status: 'failed' })
      }
    }).catch(() => {
      db.updateFailed(id)
      events.emitEvent('scan:complete', { scanId: id, package: pkg, status: 'failed' })
    })

    return { id, status: 'running', package: pkg }
  })

  app.get('/scan/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const row = db.get(id)
    if (!row) return reply.status(404).send({ error: 'scan not found' })
    const preScan = row.pre_scan_json ? JSON.parse(row.pre_scan_json) : null
    return {
      id: row.id, package: row.package_name, version: row.package_version,
      status: row.status, verdict: row.verdict ?? 'UNKNOWN', preScanScore: row.pre_scan_score,
      chains: row.chains_json ? JSON.parse(row.chains_json) : [],
      createdAt: row.created_at,
    }
  })
}
