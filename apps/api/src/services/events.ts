// Vaaman API — Event Bus
// Singleton EventEmitter that all services emit through.
// The SSE route subscribes and pushes events to connected dashboards.
//
// Event types:
//   scan:started    — POST /api/scan received
//   scan:progress   — scanner service progress (stage, message)
//   scan:complete   — scan finished (verdict, score)
//   agent:thinking  — CVE agent reasoning step
//   intel:result    — Deep Intel pipeline output
//   trust:result    — Trust Engine scoring output
//   graph:update    — Swarm graph correlation update

import { EventEmitter } from 'events'

export interface ScanEvent {
  type: string
  timestamp: string
  data: Record<string, unknown>
}

class EventBus extends EventEmitter {
  private history: ScanEvent[] = []
  private maxHistory = 500

  emitEvent(type: string, data: Record<string, unknown> = {}): void {
    const event: ScanEvent = {
      type,
      timestamp: new Date().toISOString(),
      data,
    }
    this.history.push(event)
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(-this.maxHistory)
    }
    this.emit('event', event)
    this.emit(type, data)
  }

  getRecent(limit: number = 50): ScanEvent[] {
    return this.history.slice(-limit)
  }

  getByScanId(scanId: string): ScanEvent[] {
    return this.history.filter(e => e.data.scanId === scanId)
  }
}

export const events = new EventBus()
