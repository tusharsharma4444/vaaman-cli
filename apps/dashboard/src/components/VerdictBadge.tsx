interface Props {
  verdict: string
}

export default function VerdictBadge({ verdict }: Props) {
  const colors: Record<string, string> = {
    SAFE: 'bg-safe/20 text-safe border-safe/30',
    SUSPICIOUS: 'bg-suspicious/20 text-suspicious border-suspicious/30',
    DANGEROUS: 'bg-dangerous/20 text-dangerous border-dangerous/30',
    CRITICAL: 'bg-critical/20 text-critical border-critical/30',
  }

  const icons: Record<string, string> = {
    SAFE: '✓', SUSPICIOUS: '⚠', DANGEROUS: '✗', CRITICAL: '✗',
  }

  const color = colors[verdict] ?? 'bg-gray-800 text-gray-400 border-gray-700'
  const icon = icons[verdict] ?? '?'

  return (
    <span className={`inline-flex items-center gap-1 px-3 py-0.5 rounded-full text-xs font-semibold border ${color}`}>
      {icon} {verdict}
    </span>
  )
}
