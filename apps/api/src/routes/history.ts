import type { FastifyInstance } from 'fastify'
import { db } from '../services/db.js'

export async function historyRoutes(app: FastifyInstance) {
  app.get('/history', async () => {
    return db.list(50)
  })
}
