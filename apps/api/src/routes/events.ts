// Vaaman API — SSE Route
// GET /api/events — Server-Sent Events stream for real-time dashboard updates.
// Dashboard connects here to receive all scan, agent, intel, trust, and graph events.

import type { FastifyInstance } from 'fastify'
import { events } from '../services/events.js'

export async function eventsRoute(app: FastifyInstance) {
  app.get('/events', async (request, reply) => {
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    })

    // Send recent events for catch-up
    const recent = events.getRecent(20)
    for (const event of recent) {
      reply.raw.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    }

    // Subscribe to new events
    const handler = (event: any) => {
      reply.raw.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    }

    events.on('event', handler)

    // Keep-alive ping every 15 seconds
    const ping = setInterval(() => {
      reply.raw.write(`: ping\n\n`)
    }, 15000)

    // Cleanup on disconnect
    request.raw.on('close', () => {
      events.off('event', handler)
      clearInterval(ping)
    })
  })
}
