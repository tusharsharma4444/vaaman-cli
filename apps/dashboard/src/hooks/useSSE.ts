import { useEffect, useState, useCallback } from 'react'

export interface ScanEvent {
  type: string
  timestamp: string
  data: Record<string, unknown>
}

export function useSSE(apiUrl: string = 'http://localhost:3001') {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [latest, setLatest] = useState<ScanEvent | null>(null)

  const addEvent = useCallback((event: ScanEvent) => {
    setEvents(prev => [...prev.slice(-200), event])
    setLatest(event)
  }, [])

  useEffect(() => {
    const es = new EventSource(`${apiUrl}/api/events`)

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)

    const eventTypes = [
      'scan:started', 'scan:progress', 'scan:complete',
      'agent:thinking', 'intel:result', 'trust:result', 'graph:update',
    ]

    for (const type of eventTypes) {
      es.addEventListener(type, (e: MessageEvent) => {
        try {
          addEvent(JSON.parse(e.data))
        } catch { /* ignore parse errors */ }
      })
    }

    return () => es.close()
  }, [apiUrl, addEvent])

  const clear = useCallback(() => setEvents([]), [])

  // Filter events by scanId
  const forScan = useCallback((scanId: string) =>
    events.filter(e => e.data.scanId === scanId),
    [events])

  return { events, latest, connected, clear, forScan }
}
