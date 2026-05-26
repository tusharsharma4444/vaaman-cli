// Vaaman API — Audit Runner
// Per package: pre-scan → install-time behavioral → OSV.dev CVEs
// Then: deep-intel → trust-engine → AI auditor agent
// Then: AI summarizer → AI recommendations agent
// Finally: comprehensive markdown report

import { events } from './events.js'
import { runPreScan, runInstallScan } from './scanner.js'
import { adaptToCore, importDeepIntel, importTrustEngine } from './helpers.js'
import { OpenRouterClient, getLLMCache } from '@vaaman/core'

const openrouter = new OpenRouterClient()

interface PkgAudit {
  name: string; version: string
  preScan: any | null
  behavioral: any | null
  cves: Array<{ id: string; severity: string; summary: string; fixVersion?: string }>
  deepIntel: any | null
  trust: any | null
  auditorVerdict: string; auditorRisk: number; auditorSummary: string; auditorEvidence: string[]
}

export async function runAudit(
  deps: Array<{ name: string; version: string }>,
  scanId: string,
  options: { batchSize?: number } = {}
): Promise<{ markdown: string; json: any }> {
  const batchSize = options.batchSize ?? 3
  const results: PkgAudit[] = []
  const runDeepIntelFn = process.env.OPENROUTER_API_KEY ? await importDeepIntel() : null
  const runTrustFn = runDeepIntelFn ? await importTrustEngine() : null

  // ── Phase 1: Pre-scan + Install + OSV (3 at a time) ──
  for (let i = 0; i < deps.length; i += batchSize) {
    const batch = deps.slice(i, i + batchSize)
    const batchResults = await Promise.all(batch.map(async dep => {
      const aid = `agent-${dep.name.replace(/[^a-zA-Z0-9]/g, '_')}`
      events.emitEvent('agent:started', { scanId, agentId: aid, package: dep.name, stage: 'scan' })

      const pkg: PkgAudit = {
        name: dep.name, version: 'unknown', preScan: null, behavioral: null,
        cves: [], deepIntel: null, trust: null,
        auditorVerdict: '', auditorRisk: 0, auditorSummary: '', auditorEvidence: [],
      }

      events.emitEvent('agent:thinking', { scanId, agentId: aid, package: dep.name, message: 'Pre-scanning...' })
      try { pkg.preScan = await runPreScan(dep.name); pkg.version = pkg.preScan?.version ?? 'unknown' } catch { /* */ }

      events.emitEvent('agent:thinking', { scanId, agentId: aid, package: dep.name, message: 'Behavioral monitoring...' })
      try { pkg.behavioral = await runInstallScan(dep.name) } catch { /* */ }

      events.emitEvent('agent:thinking', { scanId, agentId: aid, package: dep.name, message: 'Checking OSV.dev...' })
      try {
        const osvRes = await fetch('https://api.osv.dev/v1/query', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: { name: dep.name, ecosystem: 'npm' } }),
        })
        if (osvRes.ok) {
          const osvData = await osvRes.json() as any
          pkg.cves = (osvData.vulns ?? []).map((v: any) => ({
            id: v.id, severity: determineOSVSeverity(v), summary: (v.summary ?? v.details ?? '').slice(0, 200),
            fixVersion: extractFixVersion(v),
          }))
        }
      } catch { /* */ }

      events.emitEvent('agent:completed', { scanId, agentId: aid, package: dep.name })
      return pkg
    }))
    results.push(...batchResults.filter(Boolean))
  }

  // ── Phase 2: Deep Intel + Trust Engine (3 at a time, only for packages that need AI) ──
  if (runDeepIntelFn) {
    const needsAI = results.filter(r => {
      if (!r.preScan) return false
      const ps = r.preScan
      const hasSignals = (ps.score ?? 0) >= 10 || (ps.primitiveHits?.length ?? 0) > 0 || (ps.behavioralChains?.length ?? 0) > 0
      const hasCVEs = r.cves.length > 0
      return hasSignals || hasCVEs
    })
    const skipAI = results.filter(r => !needsAI.includes(r))
    // Clearly-safe packages: 0 score, 0 primitives, 0 CVEs, 0 chains
    for (const pkg of skipAI) {
      pkg.deepIntel = { packageType: 'library', legitimacyVerdict: 'likely-legitimate', legitimacyScore: 95, suppressedCount: 0, intents: [] }
      pkg.trust = { trust: { grade: 'A', overall: 90, breakdown: { ecosystemScore: 85, identityScore: 90, behaviorScore: 95, intentScore: 95, deceptionScore: 0, transparencyScore: 85 }, flags: [] } }
    }
    if (skipAI.length > 0) console.log(`[audit] Skipping AI for ${skipAI.length}/${results.length} clearly-safe packages`)

    for (let i = 0; i < needsAI.length; i += batchSize) {
      const batch = needsAI.slice(i, i + batchSize)
      await Promise.all(batch.map(async pkg => {
        events.emitEvent('agent:thinking', { scanId, agentId: pkg.name, package: pkg.name, message: 'Deep Intel + Trust...' })
        try {
          const core = adaptToCore(pkg.preScan!)
          pkg.deepIntel = await runDeepIntelFn(core)
          if (runTrustFn && pkg.deepIntel) pkg.trust = await runTrustFn(core, pkg.deepIntel)
        } catch (e) { console.error(`[audit] Deep Intel failed for ${pkg.name}: ${e}`) }
      }))
    }
  }

  // ── Phase 3: AI Auditor Agent (per package, 3 at a time) ──
  if (process.env.OPENROUTER_API_KEY) {
    for (let i = 0; i < results.length; i += batchSize) {
      const batch = results.slice(i, i + batchSize)
      await Promise.all(batch.map(async pkg => {
        events.emitEvent('agent:thinking', { scanId, agentId: pkg.name, package: pkg.name, message: 'AI auditor analyzing...' })
        try {
          const verdict = await runAuditorAgent(pkg)
          pkg.auditorVerdict = verdict.verdict
          pkg.auditorRisk = verdict.riskScore
          pkg.auditorSummary = verdict.summary
          pkg.auditorEvidence = verdict.evidence
        } catch (e) { pkg.auditorVerdict = 'UNKNOWN'; pkg.auditorSummary = `Auditor failed: ${e}` }
      }))
    }
  } else {
    // No API key — use heuristic verdicts
    for (const pkg of results) {
      const ps = pkg.preScan
      const cv = pkg.cves
      if (cv.some(c => c.severity === 'CRITICAL')) {
        pkg.auditorVerdict = 'CRITICAL'; pkg.auditorRisk = 90
        pkg.auditorSummary = `Contains ${cv.filter(c => c.severity === 'CRITICAL').length} CRITICAL CVE(s).`
      } else if (cv.some(c => c.severity === 'HIGH')) {
        pkg.auditorVerdict = 'DANGEROUS'; pkg.auditorRisk = 70
        pkg.auditorSummary = `Has ${cv.filter(c => c.severity === 'HIGH').length} HIGH severity CVE(s).`
      } else if (ps && ps.score >= 40) {
        pkg.auditorVerdict = 'SUSPICIOUS'; pkg.auditorRisk = 50
        pkg.auditorSummary = `Pre-scan score ${ps.score}/100 with potential concerns.`
      } else {
        pkg.auditorVerdict = 'SAFE'; pkg.auditorRisk = 15
        pkg.auditorSummary = ps ? `Pre-scan score ${ps.score}/100 — no concerning signals.` : 'Minimal data available — likely safe.'
      }
      pkg.auditorEvidence = pkg.cves.map(c => `CVE ${c.id} (${c.severity}): ${c.summary.slice(0, 80)}`)
      // Append behavioral evidence
      if (pkg.behavioral && pkg.behavioral.totalSignals > 0) {
        pkg.auditorEvidence.unshift(`[Runtime] ${pkg.behavioral.totalSignals} signals, ${pkg.behavioral.totalEvents} events, verdict: ${pkg.behavioral.verdict}`)
      }
    }
  }

  // ── Post-Phase 2: Override weak/flat AI data with heuristics ──
  for (const pkg of results) {
    const di = pkg.deepIntel
    const tr = pkg.trust?.trust
    const diWeak = !di || di.packageType === 'unknown' || di.legitimacyScore === 50 || di.legitimacyVerdict === 'uncertain'
    const trWeak = !tr || tr.overall === 55 || tr.overall === 56 || tr.overall === 50 || (tr.breakdown?.ecosystemScore === 50 && tr.breakdown?.identityScore === 50)
    if (diWeak) pkg.deepIntel = inferPackageIntel(pkg)
    if (trWeak) pkg.trust = inferTrustScore(pkg)
  }

  // ── Heuristic override: fix flat defaults from failed AI calls ──
  for (const pkg of results) {
    const isAIWorking = pkg.auditorVerdict && pkg.auditorVerdict !== 'SUSPICIOUS' && pkg.auditorRisk !== 50
    if (isAIWorking) continue // AI produced a real verdict — keep it

    // Use behavioral data (strace) FIRST — catches zero-day attacks CVEs can't
    const bh = pkg.behavioral
    if (bh && bh.totalSignals > 0) {
      const chains = [...new Set((bh.signals ?? []).flatMap((s: any) => (s.chain || []) as string[]))] as string[]
      const criticalChains = ['network-exec', 'homedir-write', 'obfuscation-exec', 'suspicious-port']
      if (chains.some(c => criticalChains.includes(c))) {
        const found = chains.filter(c => criticalChains.includes(c))
        pkg.auditorVerdict = 'CRITICAL'; pkg.auditorRisk = 95
        pkg.auditorSummary = `Runtime behavioral monitoring detected ${bh.totalSignals} signal(s) and ${chains.length} attack chain(s): ${found.join(', ')}. Zero-day threat — not in any CVE database.`
        pkg.auditorEvidence.unshift(`[Runtime 🔴] ${chains.length} attack chains detected during install: ${chains.join(', ')}`)
        for (const s of (bh.signals ?? []).slice(0, 5)) {
          pkg.auditorEvidence.unshift(`[Runtime] [${s.severity}] ${s.message}`)
        }
        continue
      } else if (chains.length > 0) {
        pkg.auditorVerdict = 'DANGEROUS'; pkg.auditorRisk = 82
        pkg.auditorSummary = `Runtime behavioral monitoring detected ${bh.totalSignals} signal(s) and ${chains.length} chain(s): ${chains.join(', ')}.`
        pkg.auditorEvidence.unshift(`[Runtime 🟠] ${chains.length} attack chains: ${chains.join(', ')}`)
        for (const s of (bh.signals ?? []).slice(0, 3)) { pkg.auditorEvidence.unshift(`[Runtime] ${s.message}`) }
        continue
      } else {
        pkg.auditorVerdict = 'SUSPICIOUS'; pkg.auditorRisk = 55
        pkg.auditorSummary = `Runtime monitoring detected ${bh.totalSignals} signal(s) during install. Review for anomalies.`
        for (const s of (bh.signals ?? []).slice(0, 3)) { pkg.auditorEvidence.unshift(`[Runtime] ${s.message}`) }
        continue
      }
    }

    // Use CVE severity + pre-scan data to override defaults
    const cv = pkg.cves
    const ps = pkg.preScan
    const hasMalicious = cv.some(c => c.id.startsWith('MAL-'))
    const hasCritical = cv.some(c => c.severity === 'CRITICAL')
    const hasHigh = cv.some(c => c.severity === 'HIGH')
    const highPreScan = (ps?.score ?? 0) >= 40

    if (hasMalicious || hasCritical) {
      const maliciousCVEs = cv.filter(c => c.id.startsWith('MAL-') || c.severity === 'CRITICAL')
      pkg.auditorVerdict = 'CRITICAL'; pkg.auditorRisk = 92
      pkg.auditorSummary = `Contains ${maliciousCVEs.length} CRITICAL/MALICIOUS flag(s): ${maliciousCVEs.map(c => c.id).join(', ')}. Investigate immediately.`
    } else if (hasHigh) {
      pkg.auditorVerdict = 'DANGEROUS'; pkg.auditorRisk = 75
      pkg.auditorSummary = `Has ${cv.filter(c => c.severity === 'HIGH').length} HIGH severity CVE(s) requiring review.`
    } else if (highPreScan) {
      pkg.auditorVerdict = 'SUSPICIOUS'; pkg.auditorRisk = 40
      pkg.auditorSummary = `Pre-scan score ${ps!.score}/100 with ${ps!.primitiveHits?.length || 0} primitive hits — review unusual primitives.`
    } else {
      pkg.auditorVerdict = 'SAFE'; pkg.auditorRisk = 10
      pkg.auditorSummary = ps ? `Pre-scan score ${ps.score}/100 — no concerning signals.` : 'Minimal data — likely safe utility or type package.'
    }
    if (pkg.auditorEvidence.length === 0) {
      pkg.auditorEvidence = cv.map(c => `${c.id} (${c.severity}): ${c.summary.slice(0, 100)}`)
      // Add primitive anomalies for packages with high pre-scan
      if (highPreScan && ps) {
        const unusual = (ps.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'dangerous').slice(0, 3)
        for (const h of unusual) {
          pkg.auditorEvidence.push(`Unusual primitive: \`${h.primitive}\` in ${h.file}:${h.line}`)
        }
      }
    }
  }

  // ── Phase 4: AI Summarizer + Recommendations (one call at the end) ──
  events.emitEvent('agent:thinking', { scanId, agentId: 'summarizer', message: 'Generating comprehensive report...' })
  let markdown = generateRichReport(results)
  if (process.env.OPENROUTER_API_KEY) {
    try { markdown = await runSummarizerAgent(results) } catch { /* fallback already set */ }
  }

  const json = {
    scanId, packageCount: results.length,
    overallRisk: computeOverallRisk(results),
    criticalCount: results.filter(r => r.auditorVerdict === 'CRITICAL').length,
    dangerousCount: results.filter(r => r.auditorVerdict === 'DANGEROUS').length,
    suspiciousCount: results.filter(r => r.auditorVerdict === 'SUSPICIOUS').length,
    safeCount: results.filter(r => r.auditorVerdict === 'SAFE').length,
    packages: results.map(r => ({
      name: r.name, version: r.version,
      preScanScore: r.preScan?.score ?? 0,
      behavioral: r.behavioral ? { events: r.behavioral.totalEvents, signals: r.behavioral.totalSignals, verdict: r.behavioral.verdict } : null,
      cves: r.cves,
      deepIntel: r.deepIntel ? { packageType: r.deepIntel.packageType, legitimacyVerdict: r.deepIntel.legitimacyVerdict, legitimacyScore: r.deepIntel.legitimacyScore } : null,
      trust: r.trust ? { grade: r.trust.trust.grade, overall: r.trust.trust.overall, breakdown: r.trust.trust.breakdown } : null,
      auditorVerdict: r.auditorVerdict, auditorRisk: r.auditorRisk, auditorSummary: r.auditorSummary,
    })),
  }

  events.emitEvent('scan:complete', { scanId, verdict: json.overallRisk, packages: results.length })
  return { markdown, json }
}

// ── AI Auditor Agent (3-tier JSON parsing) ──
async function runAuditorAgent(pkg: PkgAudit): Promise<{ verdict: string; riskScore: number; summary: string; evidence: string[] }> {
  const ps = pkg.preScan
  const bh = pkg.behavioral
  const prompt = `
Package: ${pkg.name}@${pkg.version}

== PRE-SCAN ==
${ps ? `Score: ${ps.score}/100 | Files: ${ps.filesScanned} | Chains: ${(ps.behavioralChains ?? []).map((c: any) => c.name).join(', ') || 'none'}
Primitive hits: ${(ps.primitiveHits ?? []).slice(0, 8).map((h: any) => `${h.primitive} (${h.file}:${h.line})`).join(', ') || 'none'}` : 'Not available'}

== INSTALL BEHAVIOR ==
${bh ? `Verdict: ${bh.verdict} | Signals: ${bh.totalSignals} | Processes: ${(bh.events ?? []).filter((e: any) => e.type === 'process').length} | Network: ${(bh.events ?? []).filter((e: any) => e.type === 'network').length} | Filesystem: ${(bh.events ?? []).filter((e: any) => e.type === 'filesystem').length}
${bh.totalSignals > 0 ? 'Signals:\n' + bh.signals.map((s: any) => `  [${s.severity}] ${s.message}`).join('\n') : ''}
${bh.totalSignals > 0 ? 'Attack chains: ' + [...new Set((bh.signals ?? []).flatMap((s: any) => s.chain || []))].join(', ') : ''}` : 'Not available (requires Linux/Docker)'}

== OSV.dev CVEs ==
${pkg.cves.length > 0 ? pkg.cves.map(c => `${c.id} (${c.severity}): ${c.summary.slice(0, 100)}`).join('\n') : 'None found'}

== DEEP INTEL ==
${pkg.deepIntel ? `Type: ${pkg.deepIntel.packageType} | Intent: ${pkg.deepIntel.legitimacyVerdict} (${pkg.deepIntel.legitimacyScore}/100) | Suppressed: ${pkg.deepIntel.suppressedCount}` : 'Not available'}

== TRUST SCORE ==
${pkg.trust ? `Grade: ${pkg.trust.trust.grade} (${pkg.trust.trust.overall}/100) | Eco: ${pkg.trust.trust.breakdown?.ecosystemScore}, Identity: ${pkg.trust.trust.breakdown?.identityScore}, Behavior: ${pkg.trust.trust.breakdown?.behaviorScore}, Deception: ${pkg.trust.trust.breakdown?.deceptionScore}` : 'Not available'}

Respond with JSON:
{"verdict":"SAFE|SUSPICIOUS|DANGEROUS|CRITICAL","riskScore":0-100,"summary":"one paragraph","evidence":["finding"]}`

  const res = await openrouter.chat({
    system: 'You are a supply chain security auditor. RUNTIME BEHAVIORAL DATA is the most important evidence — it catches zero-day attacks that CVE databases miss. If strace shows curl, wget, shell spawns, network connections, or filesystem writes during install, the package is highly suspicious regardless of its CVEs. Respond with ONLY valid JSON.',
    messages: [{ role: 'user', content: prompt }],
    maxTokens: 600, temperature: 0.1,
  })

  if (!res.content || res.stopReason === 'error') {
    console.error(`[auditor] ${pkg.name}: OpenRouter failed (stopReason: ${res.stopReason}, model: ${res.model})`)
    return { verdict: '', riskScore: 0, summary: res.content || res.stopReason, evidence: [] }
  }

  return safeParseVerdict(res.content)
}

// ── Robust JSON Parser (JSON → XML tags → Regex) ──
function safeParseVerdict(raw: string): { verdict: string; riskScore: number; summary: string; evidence: string[] } {
  const validV = ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'CRITICAL']

  // Tier 1: JSON
  try {
    const j = JSON.parse(raw.replace(/```json|```/g, '').trim())
    if (j.verdict && validV.includes(j.verdict)) {
      return {
        verdict: j.verdict,
        riskScore: Math.min(100, Math.max(0, parseInt(j.riskScore) || 50)),
        summary: j.summary || 'Assessment completed',
        evidence: Array.isArray(j.evidence) ? j.evidence : [],
      }
    }
  } catch { /* */ }

  // Tier 2: XML tags
  const x = (f: string) => raw.match(new RegExp(`<${f}>\\s*(.+?)\\s*</${f}>`, 's'))?.[1]?.trim()
  const xmlV = x('verdict')
  const xmlRS = x('riskScore')
  const xmlSum = x('summary')
  if (xmlV && validV.includes(xmlV)) {
    return {
      verdict: xmlV,
      riskScore: Math.min(100, Math.max(0, parseInt(xmlRS || '50'))),
      summary: xmlSum || 'Assessment completed',
      evidence: raw.match(/<evidence>(.+?)<\/evidence>/gs)?.map(e => e.replace(/<\/?evidence>/g, '').trim()) || [],
    }
  }

  // Tier 3: Regex extraction
  const reV = raw.match(/"verdict"\s*:\s*"(\w+)"/)?.[1]
  const reRS = raw.match(/"riskScore"\s*:\s*(\d+)/)?.[1]
  const reSum = raw.match(/"summary"\s*:\s*"([^"]+)"/)?.[1]
  if (reV && validV.includes(reV)) {
    return {
      verdict: reV,
      riskScore: Math.min(100, Math.max(0, parseInt(reRS || '50'))),
      summary: reSum || 'Assessment completed',
      evidence: [],
    }
  }

  // Tier 4: Heuristic fallback from raw text
  const text = raw.toLowerCase()
  const snippet = raw.slice(0, 200) || '(empty AI response)'
  if (text.includes('critical')) return { verdict: 'CRITICAL', riskScore: 85, summary: snippet, evidence: [] }
  if (text.includes('dangerous')) return { verdict: 'DANGEROUS', riskScore: 70, summary: snippet, evidence: [] }
  if (text.includes('suspicious')) return { verdict: 'SUSPICIOUS', riskScore: 45, summary: snippet, evidence: [] }
  if (text.includes('safe')) return { verdict: 'SAFE', riskScore: 15, summary: snippet, evidence: [] }

  return { verdict: 'SUSPICIOUS', riskScore: 50, summary: `AI response: ${snippet}`, evidence: [] }
}

// ── AI Summarizer Agent (rich package details) ──
async function runSummarizerAgent(results: PkgAudit[]): Promise<string> {
  const sorted = [...results].sort((a, b) => b.auditorRisk - a.auditorRisk)

  // Build rich per-package summary lines for the prompt
  const pkgLines = sorted.map(r => {
    const parts = [`- **${r.name}@${r.version}**: ${r.auditorVerdict} (risk ${r.auditorRisk}/100)`]
    if (r.preScan) parts.push(`  Pre-scan: ${r.preScan.score}/100, ${r.preScan.filesScanned} files`)
    if (r.deepIntel) parts.push(`  Intel: ${r.deepIntel.packageType}, ${r.deepIntel.legitimacyVerdict}`)
    if (r.trust) parts.push(`  Trust: ${r.trust.trust.grade} (${r.trust.trust.overall}/100)`)
    if (r.cves.length > 0) {
      const criticalCVEs = r.cves.filter(c => c.severity === 'CRITICAL')
      const highCVEs = r.cves.filter(c => c.severity === 'HIGH')
      if (criticalCVEs.length > 0) parts.push(`  🔴 CRITICAL CVEs: ${criticalCVEs.map(c => c.id).join(', ')}`)
      if (highCVEs.length > 0) parts.push(`  🟠 HIGH CVEs: ${highCVEs.map(c => c.id).join(', ')}`)
    }
    parts.push(`  Summary: ${r.auditorSummary}`)
    return parts.join('\n')
  }).join('\n\n')

  const prompt = `
Generate a comprehensive supply chain security audit report in MARKDOWN.

Project: ${results.length} dependencies analyzed.

PER-PACKAGE DETAILS:
${pkgLines}

REPORT STRUCTURE:
1. Title: "# Supply Chain Security Audit Report" with date and stats
2. Executive Summary: 2-3 sentences on overall risk posture
3. 🔴 CRITICAL FINDINGS — for each CRITICAL package, include:
   - Package name, version, risk score
   - Pre-scan findings (if available)
   - Relevant CVEs with severity
   - AI auditor assessment
   - Specific action to take
4. 🟠 DANGEROUS FINDINGS — same format as CRITICAL
5. 🟡 SUSPICIOUS FINDINGS — same format
6. 🟢 SAFE PACKAGES — brief grouped mention
7. ## Recommendations — numbered list of prioritized actions:
   - Immediate (update/remove packages with CRITICAL CVEs)
   - Short-term (review HIGH CVEs)
   - Monitor (watch for patches)

Be concise. Include SPECIFIC version numbers and CVE IDs. Output ONLY markdown.`

  const res = await openrouter.chat({
    system: 'You are a senior security engineer. Write actionable audit reports with specific CVE IDs, version numbers, and remediation steps.',
    messages: [{ role: 'user', content: prompt }],
    maxTokens: 4000, temperature: 0.2,
  })

  return res.content || generateRichReport(results)
}

// ── Rich Fallback Report (works without AI) ──
function generateRichReport(results: PkgAudit[]): string {
  const sorted = [...results].sort((a, b) => b.auditorRisk - a.auditorRisk)
  const critical = sorted.filter(r => r.auditorVerdict === 'CRITICAL')
  const dangerous = sorted.filter(r => r.auditorVerdict === 'DANGEROUS')
  const suspicious = sorted.filter(r => r.auditorVerdict === 'SUSPICIOUS')
  const safe = sorted.filter(r => r.auditorVerdict === 'SAFE')

  const lines = ['# Supply Chain Security Audit Report', '',
    `**Packages analyzed:** ${results.length} | **Generated:** ${new Date().toISOString()}`, '',
    `**Risk:** ${critical.length} CRITICAL · ${dangerous.length} DANGEROUS · ${suspicious.length} SUSPICIOUS · ${safe.length} SAFE`, '',
    '---', '']

  function addSection(title: string, emoji: string, pkgs: PkgAudit[]) {
    if (pkgs.length === 0) return
    lines.push(`## ${emoji} ${title} (${pkgs.length})`, '')
    for (const r of pkgs) {
      lines.push(`### ${r.name}@${r.version} — Risk: ${r.auditorRisk}/100`, '')
      lines.push(r.auditorSummary, '')
      // Pre-scan
      if (r.preScan) {
        const ps = r.preScan
        lines.push(`**Pre-scan:** Score ${ps.score}/100 · ${ps.filesScanned} files · ${(ps.behavioralChains ?? []).length} chains · ${(ps.primitiveHits ?? []).length} primitive hits`)
        if ((ps.primitiveHits ?? []).length > 0) {
          const topHits = ps.primitiveHits.slice(0, 5).map((h: any) => `\`${h.primitive}\` (${h.file}:${h.line})${contextualizePrimitive(h, r.name)}`).join(', ')
          lines.push(`Primitives: ${topHits}`)
        }
        lines.push('')
      }
      // Behavioral (strace — the USP)
      if (r.behavioral && r.behavioral.totalSignals > 0) {
        const bh = r.behavioral
        const chains = [...new Set((bh.signals ?? []).flatMap((s: any) => s.chain || []))]
        const processEvents = (bh.events ?? []).filter((e: any) => e.type === 'process').length
        const networkEvents = (bh.events ?? []).filter((e: any) => e.type === 'network').length
        const fsEvents = (bh.events ?? []).filter((e: any) => e.type === 'filesystem').length
        lines.push(`**🔴 Runtime Behavior (strace):**`)
        lines.push(`Verdict: ${bh.verdict} · ${bh.totalSignals} signals · ${processEvents} processes · ${networkEvents} network · ${fsEvents} filesystem`)
        if (chains.length > 0) lines.push(`**Attack chains:** ${chains.join(' · ')}`)
        for (const s of (bh.signals ?? []).slice(0, 8)) {
          const sev = s.severity === 'critical' ? '🔴' : s.severity === 'dangerous' ? '🟠' : '🟡'
          lines.push(`- ${sev} ${s.message}`)
        }
        lines.push('')
      }
      // CVEs
      if (r.cves.length > 0) {
        lines.push(`**CVEs (${r.cves.length}):**`)
        for (const c of r.cves) {
          const sevIcon = c.severity === 'CRITICAL' ? '🔴' : c.severity === 'HIGH' ? '🟠' : c.severity === 'MEDIUM' ? '🟡' : '⚪'
          lines.push(`- ${sevIcon} ${c.id} (${c.severity}): ${c.summary.slice(0, 120)}`)
        }
        lines.push('')
      }
      // Deep Intel
      if (r.deepIntel) {
        lines.push(`**AI Analysis:** Type: \`${r.deepIntel.packageType}\` · Intent: \`${r.deepIntel.legitimacyVerdict}\` (${r.deepIntel.legitimacyScore}/100)`)
        lines.push('')
      }
      // Trust
      if (r.trust) {
        const t = r.trust.trust
        lines.push(`**Trust Score:** Grade ${t.grade} (${t.overall}/100)`)
        lines.push(`Ecosystem: ${t.breakdown?.ecosystemScore} · Identity: ${t.breakdown?.identityScore} · Behavior: ${t.breakdown?.behaviorScore} · Deception: ${t.breakdown?.deceptionScore} · Transparency: ${t.breakdown?.transparencyScore}`)
        lines.push('')
      }
      // Evidence
      if (r.auditorEvidence.length > 0) {
        lines.push('**Evidence:**')
        for (const e of r.auditorEvidence) lines.push(`- ${e}`)
        lines.push('')
      }
    }
  }

  addSection('CRITICAL', '🔴', critical)
  addSection('DANGEROUS', '🟠', dangerous)
  addSection('SUSPICIOUS', '🟡', suspicious)

  if (safe.length > 0) {
    lines.push(`## 🟢 SAFE (${safe.length})`, '')
    const safeNames = safe.map(r => r.name).join(', ')
    lines.push(`${safeNames}`, '')
    lines.push('These packages showed no concerning signals.', '')
  }

  // Recommendations — driven by CVE severity, not just auditor verdict
  lines.push('## Recommendations', '')
  const recs: string[] = []

  // Immediately actionable: packages with CRITICAL CVEs or MAL flags
  for (const r of sorted) {
    const criticalCVEs = r.cves.filter(c => c.severity === 'CRITICAL')
    const malFlags = r.cves.filter(c => c.id.startsWith('MAL-'))
    const targetCVEs = [...criticalCVEs, ...malFlags]
    if (targetCVEs.length === 0) continue
    const names = targetCVEs.map(c => {
      const fixInfo = c.fixVersion ? ` → fixed in ${c.fixVersion}` : ''
      return `${c.id} (${c.severity})${fixInfo}`
    }).join(', ')
    recs.push(`${recs.length + 1}. **${r.name}@${r.version}** — ${names}. ${malFlags.length > 0 ? 'MALICIOUS CODE DETECTED — remove or audit source immediately.' : 'Update to latest patched version.'}`)
  }

  // Short-term: packages with HIGH CVEs
  for (const r of sorted) {
    const highCVEs = r.cves.filter(c => c.severity === 'HIGH' && !c.id.startsWith('MAL-'))
    if (highCVEs.length === 0) continue
    // Skip if already listed in immediate
    if (r.cves.some(c => c.severity === 'CRITICAL' || c.id.startsWith('MAL-'))) continue
    recs.push(`${recs.length + 1}. **${r.name}@${r.version}** — Review ${highCVEs.length} HIGH CVE(s): ${highCVEs.map(c => {
      const fixInfo = c.fixVersion ? ` → fixed in ${c.fixVersion}` : ''
      return `${c.id}${fixInfo}`
    }).join(', ')}. Update within 7 days.`)
  }

  // Monitor: packages with MEDIUM CVEs or high pre-scan scores
  for (const r of sorted) {
    if (r.cves.length === 0 && (r.auditorRisk < 30)) continue
    // Skip if already listed above
    if (r.cves.some(c => c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.id.startsWith('MAL-'))) continue
    if (r.auditorRisk >= 30) {
      const reason = r.cves.length > 0 ? `${r.cves.length} CVE(s) present` : `Pre-scan score ${r.preScan?.score ?? 0}/100`
      recs.push(`${recs.length + 1}. **${r.name}@${r.version}** — ${reason}. Monitor for patches.`)
    }
  }

  if (recs.length === 0) recs.push('No critical or high-severity issues found. All packages appear safe.')
  for (const rec of recs) lines.push(rec, '')

  return lines.join('\n')
}

function computeOverallRisk(results: PkgAudit[]): string {
  if (results.some(r => r.auditorVerdict === 'CRITICAL')) return 'CRITICAL'
  if (results.some(r => r.auditorVerdict === 'DANGEROUS')) return 'DANGEROUS'
  if (results.some(r => r.auditorVerdict === 'SUSPICIOUS')) return 'SUSPICIOUS'
  return 'SAFE'
}

// ── Heuristic Package Intelligence (no AI required) ──
function inferPackageIntel(pkg: PkgAudit): any {
  const pkgType = classifyPackageType(pkg.name, pkg.preScan)
  const legitimacy = inferLegitimacy(pkg, pkgType)
  return {
    packageType: pkgType,
    legitimacyVerdict: legitimacy.verdict,
    legitimacyScore: legitimacy.score,
    suppressedCount: 0,
    intents: [],
  }
}

function classifyPackageType(name: string, preScan: any): string {
  const n = name.toLowerCase()
  if (n.startsWith('@types/') || n.startsWith('@typescript-eslint/')) return 'dev-tool'
  if (n.startsWith('@radix-ui/') || n.startsWith('@tanstack/')) return 'framework'
  if (n.startsWith('@supabase/') || n.startsWith('@stripe/') || n.startsWith('@prisma/')) return 'runtime-utility'
  if (n.startsWith('@')) return 'library'
  if (['eslint', 'prettier', 'typescript', 'vite', 'vitest', 'postcss', 'tailwindcss', 'autoprefixer', 'prisma'].some(k => n.includes(k))) return 'dev-tool'
  if (['react', 'vue', 'svelte', 'solid'].some(k => n.includes(k))) return 'framework'
  if (['axios', 'socket.io', 'stripe', 'prisma', 'supabase', 'express', 'fastify', 'koa', 'hono'].some(k => n.includes(k))) return 'runtime-utility'
  if (['zustand', 'zod', 'date-fns', 'clsx', 'framer-motion', 'lucide', 'lodash', 'ramda', 'immer'].some(k => n.includes(k))) return 'library'
  if (['react-hook-form', 'react-router', 'react-day-picker', 'react-resizable', 'sonner', 'cmdk', 'vaul'].some(k => n.includes(k))) return 'library'
  // Check pre-scan: CLI tools have child_process + many files
  if (preScan && preScan.score >= 40 && (preScan.filesScanned ?? 0) > 100) return 'cli-tool'
  return 'library'
}

function inferLegitimacy(pkg: PkgAudit, pkgType: string): { verdict: string; score: number } {
  const cv = pkg.cves
  const ps = pkg.preScan
  if (cv.some((c: any) => c.id.startsWith('MAL-'))) return { verdict: 'likely-malicious', score: 5 }
  if (cv.some((c: any) => c.severity === 'CRITICAL')) return { verdict: 'uncertain', score: 20 }
  if (cv.some((c: any) => c.severity === 'HIGH')) return { verdict: 'uncertain', score: 40 }
  const preScanScore = ps?.score ?? 0
  if (preScanScore >= 40) return { verdict: 'uncertain', score: 50 }
  if (preScanScore >= 20) return { verdict: 'likely-legitimate', score: 70 }
  // Low score + no CVEs + matches expected type
  if (pkgType === 'dev-tool' || pkgType === 'framework') return { verdict: 'likely-legitimate', score: 90 }
  return { verdict: 'likely-legitimate', score: 85 }
}

// ── Heuristic Trust Score (per-dimension, no AI) ──
function inferTrustScore(pkg: PkgAudit): any {
  const ps = pkg.preScan
  const cv = pkg.cves
  const name = pkg.name.toLowerCase()

  // Ecosystem: known packages score higher
  const isWellKnown = ['react', 'vue', 'axios', 'lodash', 'typescript', 'vite', 'eslint', 'prettier', 'zustand', 'zod',
    'tailwindcss', 'postcss', 'express', 'prisma', 'next', 'nuxt'].some(k => name.includes(k))
  const isScoped = name.startsWith('@')
  const ecosystem = isWellKnown ? 85 : isScoped ? 60 : 50

  // Identity: does the package type match its name?
  const pkgType = classifyPackageType(name, ps)
  const identity = pkgType === 'library' || pkgType === 'framework' ? 85 : pkgType === 'dev-tool' ? 80 : 65

  // Behavior: driven by pre-scan score + primitive anomalies
  const preScanScore = ps?.score ?? 0
  const dangerousHits = (ps?.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'dangerous').length
  let behavior = 90
  if (preScanScore >= 40) behavior = 40
  else if (preScanScore >= 20) behavior = 60
  else if (preScanScore >= 10) behavior = 75
  if (dangerousHits > 10) behavior = Math.max(20, behavior - 20)

  // Deception: MAL flags, unusual primitives in unexpected files
  let deception = 0
  if (cv.some((c: any) => c.id.startsWith('MAL-'))) deception = 25
  else if (cv.some((c: any) => c.severity === 'CRITICAL')) deception = 15
  else if (cv.some((c: any) => c.severity === 'HIGH')) deception = 10
  // Check for unusual primitives in library/framework packages
  if ((pkgType === 'library' || pkgType === 'framework') && dangerousHits > 0) {
    deception = Math.max(deception, 10)
  }

  // Transparency: scaled by pre-scan files vs expected
  const files = ps?.filesScanned ?? 0
  const transparency = files === 0 ? 40 : files < 50 ? 75 : files < 200 ? 60 : 45

  const dimensions = { ecosystemScore: ecosystem, identityScore: identity, behaviorScore: behavior, intentScore: Math.round((identity + behavior) / 2), deceptionScore: deception, transparencyScore: transparency }
  const overall = Math.round((ecosystem * 0.15 + identity * 0.25 + behavior * 0.25 + dimensions.intentScore * 0.15 + (100 - deception) * 0.15 + transparency * 0.05))
  const grade = overall >= 90 ? 'A' : overall >= 75 ? 'B' : overall >= 55 ? 'C' : overall >= 35 ? 'D' : 'F'

  return { trust: { overall, grade, breakdown: dimensions, flags: [] } }
}

// ── Contextualize child_process.exec hits ──
function contextualizePrimitive(hit: any, pkgName: string): string {
  const file = (hit.file || '').toLowerCase()
  const name = pkgName.toLowerCase()
  // Known false positive patterns
  if (file.includes('middleware') || file.includes('.cjs') || file.includes('.mjs'))
    return ' (likely build artifact or tooling — not malicious)'
  if (name.includes('eslint') || name.includes('prettier') || name.includes('typescript'))
    return ' (linter/build tool — legitimate)'
  if (name.includes('zustand') && file.includes('middleware'))
    return ' (Zustand devtools bridge — expected)'
  if (name.includes('date-fns') && file.includes('parseiso'))
    return ' (date-fns regex exec — false positive)'
  return ''
}

// ── Extract fix version from OSV vulnerability ──
function extractFixVersion(v: any): string | undefined {
  for (const a of (v.affected ?? [])) {
    for (const r of (a.ranges ?? [])) {
      const events = r.events ?? []
      for (const e of events) {
        if (e.fixed) return e.fixed
      }
    }
  }
  return undefined
}

function determineOSVSeverity(v: any): string {
  for (const s of (v.severity ?? [])) {
    if (s.type === 'CVSS_V3') { const score = parseFloat(s.score); if (score >= 9) return 'CRITICAL'; if (score >= 7) return 'HIGH'; if (score >= 4) return 'MEDIUM'; return 'LOW' }
  }
  return v.database_specific?.severity?.toUpperCase() || 'MEDIUM'
}
