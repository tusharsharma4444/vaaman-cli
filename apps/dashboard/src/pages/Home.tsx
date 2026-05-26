import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const PLACEHOLDER = `{
  "dependencies": {
    "lodash": "^4.17.21",
    "axios": "^1.7.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0"
  }
}`

export default function Home() {
  const [pkgJson, setPkgJson] = useState('')
  const [singlePkg, setSinglePkg] = useState('')
  const [mode, setMode] = useState<'single' | 'multi'>('single')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleScan() {
    setLoading(true)

    if (mode === 'single' && singlePkg.trim()) {
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: singlePkg.trim() }),
        })
        const data = await res.json()
        navigate(`/live/${data.id}`)
      } catch { setLoading(false) }
      return
    }

    if (mode === 'multi' && pkgJson.trim()) {
      try {
        JSON.parse(pkgJson)
      } catch (parseErr: any) {
        alert(`Invalid JSON: ${parseErr.message}`)
        setLoading(false)
        return
      }

      try {
        const res = await fetch('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ packageJson: pkgJson }),
        })

        if (!res.ok) {
          const errText = await res.text().catch(() => 'Unknown error')
          alert(`API Error (${res.status}): ${errText.slice(0, 200)}`)
          setLoading(false)
          return
        }

        const data = await res.json()
        if (!data.scanId) {
          alert('API returned no scanId — check if Docker is running')
          setLoading(false)
          return
        }
        navigate(`/audit/${data.scanId}`)
      } catch (err: any) {
        if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
          alert('Cannot connect to API — is Docker running? Run: docker compose up -d')
        } else {
          alert(`Connection error: ${err.message}`)
        }
        setLoading(false)
      }
      return
    }
    setLoading(false)
  }

  return (
    <div className="max-w-4xl mx-auto pt-8">
      <h1 className="text-3xl font-bold mb-2">▲ VAAMAN</h1>
      <p className="text-gray-400 mb-6">Supply chain security — scan single packages or entire projects</p>

      {/* Mode toggle */}
      <div className="flex gap-1 mb-6 bg-gray-900 rounded-lg p-1 w-fit">
        <button
          onClick={() => setMode('single')}
          className={`px-4 py-1.5 rounded text-sm font-medium ${mode === 'single' ? 'bg-brand text-white' : 'text-gray-400 hover:text-white'}`}
        >Single Package</button>
        <button
          onClick={() => setMode('multi')}
          className={`px-4 py-1.5 rounded text-sm font-medium ${mode === 'multi' ? 'bg-brand text-white' : 'text-gray-400 hover:text-white'}`}
        >Full Project</button>
      </div>

      {/* Single package mode */}
      {mode === 'single' && (
        <div className="flex gap-2 mb-8">
          <input
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-brand"
            placeholder="npm package name (e.g. lodash, express, @scope/pkg)"
            value={singlePkg}
            onChange={e => setSinglePkg(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          <button
            onClick={handleScan}
            disabled={loading || !singlePkg.trim()}
            className="bg-brand hover:bg-orange-600 text-white font-medium px-6 py-3 rounded-lg disabled:opacity-50"
          >
            {loading ? '...' : 'Scan'}
          </button>
        </div>
      )}

      {/* Multi package mode */}
      {mode === 'multi' && (
        <div className="space-y-4">
          <textarea
            className="w-full h-64 bg-gray-800 border border-gray-700 rounded-lg p-4 text-green-400 font-mono text-sm placeholder-gray-500 focus:outline-none focus:border-brand resize-y"
            placeholder={PLACEHOLDER}
            value={pkgJson}
            onChange={e => setPkgJson(e.target.value)}
          />
          <div className="flex gap-2">
            <button
              onClick={() => setPkgJson(PLACEHOLDER)}
              className="text-xs text-gray-500 hover:text-gray-300 px-2 py-1"
            >Load example</button>
            <button
              onClick={handleScan}
              disabled={loading || !pkgJson.trim()}
              className="bg-brand hover:bg-orange-600 text-white font-medium px-6 py-3 rounded-lg disabled:opacity-50 ml-auto"
            >
              {loading ? 'Analyzing...' : 'Analyze Project'}
            </button>
          </div>
          <div className="text-xs text-gray-500">
            Paste a package.json — Vaaman will pre-scan, AI-classify, trust-score, and CVE-analyze every dependency
          </div>
        </div>
      )}

      {/* Pipeline overview */}
      <div className="mt-8 grid grid-cols-5 gap-2 text-center text-xs">
        {[
          ['1. Pre-Scan', 'Static tarball analysis'],
          ['2. Deep Intel', 'AI intent classification'],
          ['3. Trust Engine', '6-dimension scoring'],
          ['4. OSV.dev', 'CVE analysis'],
          ['5. Runtime', 'strace behavioral monitor'],
        ].map(([title, desc]) => (
          <div key={title} className="bg-gray-900 rounded-lg p-3 border border-gray-800">
            <div className="text-brand font-bold">{title}</div>
            <div className="text-gray-500 mt-0.5">{desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
