// Vaaman API — Audit Route
// POST /api/audit — takes packageJson, returns immediate scanId + runs audit in background.
// Dashboard navigates to /audit/:id and polls for results or connects to SSE.

import type { FastifyInstance } from 'fastify'
import { randomUUID } from 'crypto'
import { events } from '../services/events.js'
import { runAudit } from '../services/audit-runner.js'
import { db } from '../services/db.js'

export async function auditRoutes(app: FastifyInstance) {
  console.log('[audit] route registered')
  app.post('/audit', async (request, reply) => {
    const body = request.body as { packageJson?: string; dependencies?: Array<{ name: string; version: string }> }
    let deps: Array<{ name: string; version: string }>

    try {
      if (body.packageJson) {
        const pkg = JSON.parse(body.packageJson)
        const all = { ...pkg.dependencies, ...pkg.devDependencies }
        deps = Object.entries(all).map(([name, ver]) => ({ name, version: String(ver).replace(/^[\^~]/, '') }))
      } else if (body.dependencies) {
        deps = body.dependencies
      } else {
        return reply.status(400).send({ error: 'Provide packageJson string or dependencies array' })
      }
    } catch {
      return reply.status(400).send({ error: 'Invalid package.json JSON' })
    }

    if (deps.length === 0) return reply.status(400).send({ error: 'No dependencies found' })

    const scanId = `audit-${Date.now()}`

    events.emitEvent('audit:started', { scanId, packageCount: deps.length, packages: deps.map(d => d.name) })

    // Store in DB so we can poll later
    db.insert(scanId, `project-${deps.length}-pkgs`)

    // Run audit in background
    runAudit(deps, scanId, { batchSize: 3 }).then(({ markdown, json }) => {
      db.updateComplete(scanId, json.overallRisk, 'multi', 0, JSON.stringify(json), JSON.stringify({ markdown }))
      events.emitEvent('audit:complete', { scanId, markdown, json })
    }).catch(err => {
      db.updateFailed(scanId)
      events.emitEvent('audit:complete', { scanId, error: String(err) })
    })

    return reply.send({ scanId, status: 'started', packageCount: deps.length })
  })

  // Get audit result (polling)
  app.get('/audit/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const row = db.get(id)
    if (!row) return reply.status(404).send({ error: 'Audit not found' })

    const preScan = row.pre_scan_json ? JSON.parse(row.pre_scan_json) : null
    const chains = row.chains_json ? JSON.parse(row.chains_json) : null
    const markdown = chains?.markdown || null
    const json = preScan || null

    reply.send({
      id: row.id, status: row.status,
      markdown: markdown || 'Audit in progress...',
      json,
    })
  })
}
