import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

interface ScanEntry {
  id: string
  package: string
  verdict: string
  preScanScore: number
  createdAt: string
}

export default function History() {
  const [scans, setScans] = useState<ScanEntry[]>([])
  const navigate = useNavigate()

  useEffect(() => {
    fetch('/api/history').then(r => r.json()).then(setScans)
  }, [])

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Scan History</h1>
      {scans.length === 0 ? (
        <div className="text-gray-500 text-center py-12">No scans yet. Run your first scan from the home page.</div>
      ) : (
        <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left p-3">Package</th>
                <th className="text-left p-3">Verdict</th>
                <th className="text-left p-3">Score</th>
                <th className="text-left p-3">Date</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr
                  key={s.id}
                  onClick={() => navigate(`/scan/${s.id}`)}
                  className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer"
                >
                  <td className="p-3 font-mono">{s.package}</td>
                  <td className="p-3">
                    <span className={verdictColor(s.verdict)}>{s.verdict}</span>
                  </td>
                  <td className="p-3">{s.preScanScore}/100</td>
                  <td className="p-3 text-gray-500">{new Date(s.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function verdictColor(v: string): string {
  switch (v) {
    case 'SAFE': case 'safe': return 'text-safe'
    case 'SUSPICIOUS': case 'suspicious': return 'text-suspicious'
    case 'DANGEROUS': case 'dangerous': return 'text-dangerous'
    case 'CRITICAL': case 'critical': return 'text-critical'
    default: return 'text-gray-400'
  }
}
