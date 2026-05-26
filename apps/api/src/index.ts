import Fastify from 'fastify'
import cors from '@fastify/cors'
import fastifyStatic from '@fastify/static'
import { join, dirname } from 'path'
import { existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { scanRoutes } from './routes/scan.js'
import { historyRoutes } from './routes/history.js'
import { eventsRoute } from './routes/events.js'
import { deepIntelRoutes } from './routes/deep-intel.js'
import { trustRoutes } from './routes/trust.js'
import { auditRoutes } from './routes/audit.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const app = Fastify({ logger: true })

const corsOrigin = (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',').map(s => s.trim())
await app.register(cors, {
  origin: corsOrigin,
  credentials: true,
})

// API routes — must be registered before static serving
await app.register(scanRoutes, { prefix: '/api' })
await app.register(historyRoutes, { prefix: '/api' })
await app.register(eventsRoute, { prefix: '/api' })
await app.register(deepIntelRoutes, { prefix: '/api' })
await app.register(trustRoutes, { prefix: '/api' })
await app.register(auditRoutes, { prefix: '/api' })

app.get('/api/health', async () => ({
  status: 'ok',
  uptime: process.uptime(),
  env: process.env.NODE_ENV || 'development',
}))

// In production, serve the built dashboard as static files
const dashboardDist = join(__dirname, '..', '..', '..', 'apps', 'dashboard', 'dist')

if (process.env.NODE_ENV === 'production') {
  console.log(`Serving dashboard from: ${dashboardDist}`)
  await app.register(fastifyStatic, { root: dashboardDist, prefix: '/', wildcard: false, decorateReply: false })
  app.setNotFoundHandler((request, reply) => {
    if (request.method === 'GET' && !request.url.startsWith('/api/')) reply.sendFile('index.html')
    else reply.status(404).send({ error: `Route ${request.method} ${request.url} not found` })
  })
}

const port = parseInt(process.env.PORT || '3001')
await app.listen({ port, host: '0.0.0.0' })
console.log(`Vaaman API running on http://0.0.0.0:${port}`)
