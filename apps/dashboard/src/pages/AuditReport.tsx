import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'

export default function AuditReport() {
  const { id } = useParams()
  const [markdown, setMarkdown] = useState('')
  const [status, setStatus] = useState<'loading' | 'done'>('loading')
  const [json, setJson] = useState<any>(null)

  useEffect(() => {
    if (!id) return
    const poll = setInterval(async () => {
      try {
        const res = await fetch(`/api/audit/${id}`)
        const data = await res.json()
        if (data.markdown && data.markdown !== 'Audit in progress...') {
          setMarkdown(data.markdown)
          setJson(data.json)
          setStatus('done')
          clearInterval(poll)
        }
      } catch { /* */ }
    }, 3000)
    return () => clearInterval(poll)
  }, [id])

  const copyMarkdown = () => { navigator.clipboard.writeText(markdown) }
  const downloadMarkdown = () => {
    const blob = new Blob([markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `vaaman-audit-${id}.md`; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold text-white">▲ VAAMAN — Audit Report</h1>
        <div className="flex gap-2">
          <button onClick={copyMarkdown} disabled={!markdown}
            className="bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs px-3 py-1.5 rounded border border-gray-700 disabled:opacity-40">
            📋 Copy Markdown
          </button>
          <button onClick={downloadMarkdown} disabled={!markdown}
            className="bg-brand hover:bg-orange-600 text-white text-xs px-3 py-1.5 rounded disabled:opacity-40">
            ⬇ Download .md
          </button>
        </div>
      </div>

      {json && (
        <div className="flex gap-3 mb-4 text-xs">
          <span className="bg-gray-900 border border-gray-800 rounded px-2 py-1">
            Packages: <b className="text-white">{json.packages?.length ?? json.packageCount}</b>
          </span>
          <span className={`rounded px-2 py-1 border ${json.overallRisk === 'CRITICAL' ? 'bg-red-900/30 border-red-800 text-red-400' : json.overallRisk === 'DANGEROUS' ? 'bg-orange-900/30 border-orange-800 text-orange-400' : json.overallRisk === 'SUSPICIOUS' ? 'bg-yellow-900/30 border-yellow-800 text-yellow-400' : 'bg-green-900/30 border-green-800 text-green-400'}`}>
            <b>{json.overallRisk}</b>
          </span>
          {json.criticalCount > 0 && <span className="text-red-400">🔴 {json.criticalCount} critical</span>}
          {json.dangerousCount > 0 && <span className="text-orange-400">🟠 {json.dangerousCount} dangerous</span>}
          {json.suspiciousCount > 0 && <span className="text-yellow-400">🟡 {json.suspiciousCount} suspicious</span>}
          {json.safeCount > 0 && <span className="text-green-400">🟢 {json.safeCount} safe</span>}
        </div>
      )}

      {status === 'loading' && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <div className="animate-pulse text-suspicious text-lg mb-2">● Auditing packages...</div>
          <div className="text-gray-500 text-sm">Running pre-scan, behavioral monitoring, OSV queries, AI auditor, and summarizer.</div>
          <div className="text-gray-600 text-xs mt-2">This may take 1-3 minutes depending on package count.</div>
        </div>
      )}

      {status === 'done' && markdown && (
        <div className="bg-gray-950 border border-gray-800 rounded-lg p-6 overflow-x-auto">
          <MarkdownView content={markdown} />
        </div>
      )}
    </div>
  )
}

function MarkdownView({ content }: { content: string }) {
  // Simple markdown → HTML converter
  const html = content
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-bold text-gray-200 mt-4 mb-1">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-white mt-6 mb-2 border-b border-gray-800 pb-1">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="text-2xl font-bold text-white mt-4 mb-4">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<b class="text-white">$1</b>')
    .replace(/\*(.+?)\*/g, '<i>$1</i>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-800 text-green-400 px-1 py-0.5 rounded text-xs font-mono">$1</code>')
    .replace(/^- (.+)$/gm, '<li class="text-gray-300 text-sm ml-4">• $1</li>')
    .replace(/\n\n/g, '<br/><br/>')
    .replace(/\n/g, '<br/>')

  return <div dangerouslySetInnerHTML={{ __html: html }} className="text-sm leading-relaxed text-gray-300" />
}
