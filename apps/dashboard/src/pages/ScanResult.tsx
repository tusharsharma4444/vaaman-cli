import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import VerdictBadge from '../components/VerdictBadge'

interface ScanData {
  id: string
  package: string
  version: string
  status: string
  verdict: string
  preScanScore: number
  aiVerdict?: { verdict: string; confidence: number; summary: string; whatItDid: string[]; remediation: string[] }
  chains?: { name: string; severity: string; description: string; file: string; lineRange: [number, number]; primitives: { primitive: string; line: number }[] }[]
  events?: { type: string; message: string; severity: string }[]
  signals?: { severity: string; message: string }[]
}

export default function ScanResult() {
  const { id } = useParams()
  const [data, setData] = useState<ScanData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`/api/scan/${id}`)
      .then(r => r.json())
      .then(setData)
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="text-center py-12 text-gray-400">Loading scan results...</div>
  if (!data) return <div className="text-center py-12 text-gray-400">Scan not found</div>

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <h1 className="text-2xl font-bold">{data.package}@{data.version}</h1>
        <VerdictBadge verdict={data.verdict} />
        {data.status === 'running' && <span className="text-suspicious animate-pulse">● Running</span>}
      </div>

      {/* Score row */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="text-xs text-gray-500 mb-1">Pre-Scan Score</div>
          <div className="text-2xl font-bold">{data.preScanScore}/100</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="text-xs text-gray-500 mb-1">Events</div>
          <div className="text-2xl font-bold">{data.events?.length ?? 0}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="text-xs text-gray-500 mb-1">Signals</div>
          <div className="text-2xl font-bold">{data.signals?.length ?? 0}</div>
        </div>
      </div>

      {/* AI Verdict */}
      {data.aiVerdict && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-2">AI Verdict</h2>
          <div className="flex items-center gap-2 mb-2">
            <VerdictBadge verdict={data.aiVerdict.verdict} />
            <span className="text-gray-400 text-sm">{data.aiVerdict.confidence}% confidence</span>
          </div>
          <p className="text-gray-300 text-sm mb-2">{data.aiVerdict.summary}</p>
          {data.aiVerdict.whatItDid?.length > 0 && (
            <div className="text-sm text-gray-400 mb-2">
              <strong>What it did:</strong> {data.aiVerdict.whatItDid.join('; ')}
            </div>
          )}
          {data.aiVerdict.remediation?.length > 0 && (
            <div className="text-sm text-gray-400">
              <strong>Remediation:</strong> {data.aiVerdict.remediation.slice(0, 3).join('; ')}
            </div>
          )}
        </div>
      )}

      {/* Attack Chains */}
      {data.chains && data.chains.length > 0 && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-3">Attack Chains ({data.chains.length})</h2>
          {data.chains.map((c: any, i: number) => (
            <div key={i} className="text-sm text-gray-300 py-1 border-b border-gray-800">
              [{c.severity?.toUpperCase()}] {c.name} — {c.description}
            </div>
          ))}
        </div>
      )}

      {/* Signal list */}
      {data.signals && data.signals.length > 0 && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-3">Threat Signals</h2>
          <div className="space-y-1">
            {data.signals.map((s, i) => (
              <div key={i} className={`text-sm p-2 rounded ${s.severity === 'critical' || s.severity === 'dangerous' ? 'bg-red-900/30 text-red-300' : 'bg-yellow-900/30 text-yellow-300'}`}>
                [{s.severity.toUpperCase()}] {s.message}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Event log */}
      {data.events && data.events.length > 0 && (
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <h2 className="text-sm font-semibold text-gray-400 mb-3">Event Log</h2>
          <div className="space-y-1 max-h-60 overflow-y-auto">
            {data.events.slice(0, 30).map((e, i) => (
              <div key={i} className="text-xs text-gray-500 font-mono">
                [{e.type}] {e.message}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
