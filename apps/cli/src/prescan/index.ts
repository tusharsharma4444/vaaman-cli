// ─────────────────────────────────────────────
// Vaaman AI — Pre-Scan Orchestrator
// Main entry point. Coordinates:
//   fetcher → extractor → script-scanner → ast-scanner → chain-detector → scoring
// ─────────────────────────────────────────────

import { fetchTarball } from './fetcher.js';
import { extractTarball } from './extractor.js';
import { scanLifecycleScripts } from './script-scanner.js';
import { scanTarballEntries } from './ast-scanner.js';
import { detectChains, chainScoreContribution } from './chain-detector.js';
import type { DetectedChain } from './chain-detector.js';
import type { PreScanInput, PreScanResult, Recommendation } from './types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

// ── Scoring Constants ─────────────────────────

const SCORE_WEIGHTS = {
  lifecycle: {
    dangerous: 35,
    suspicious: 15,
    safe: 0,
  },
  primitive: {
    dangerous: 20,
    suspicious: 8,
  },
  // Primitives alone are capped low — chains carry the real weight
  primitiveMax: 30,
};

// ── Recommendation Thresholds ─────────────────

function scoreToRecommendation(score: number): Recommendation {
  if (score >= 60) return 'block';
  if (score >= 25) return 'caution';
  return 'proceed';
}

// ── Score Calculator ──────────────────────────

function calculateScore(
  lifecycleScripts: PreScanResult['lifecycleScripts'],
  primitiveHits: PreScanResult['primitiveHits'],
  chains: DetectedChain[]
): number {
  let score = 0;

  // Lifecycle script scoring
  for (const script of lifecycleScripts) {
    score += SCORE_WEIGHTS.lifecycle[script.riskLevel];
  }

  // Primitive hit scoring (capped lower now — chains are the real signal)
  let primitiveScore = 0;
  for (const hit of primitiveHits) {
    if (hit.riskLevel === 'dangerous') {
      primitiveScore += SCORE_WEIGHTS.primitive.dangerous;
    } else if (hit.riskLevel === 'suspicious') {
      primitiveScore += SCORE_WEIGHTS.primitive.suspicious;
    }
  }
  score += Math.min(primitiveScore, SCORE_WEIGHTS.primitiveMax);

  // Chain scoring — this is where correlated behavior gets weight
  score += chainScoreContribution(chains);

  return Math.min(score, 100);
}

// ── JSON Save ─────────────────────────────────

function saveResultJson(result: PreScanResult): string {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const jsonDir = path.resolve(__dirname, '..', 'json');

  if (!fs.existsSync(jsonDir)) {
    fs.mkdirSync(jsonDir, { recursive: true });
  }

  // Filename: <package>@<version>-prescan-<timestamp>.json
  const safeName = result.package.replace(/\//g, '+');  // scoped packages: @scope/pkg → @scope+pkg
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `${safeName}@${result.version}-prescan-${timestamp}.json`;
  const filePath = path.join(jsonDir, filename);

  fs.writeFileSync(filePath, JSON.stringify(result, null, 2), 'utf-8');
  console.log(`[prescan] JSON saved → ${filePath}`);

  return filePath;
}

// ── Main Orchestrator ─────────────────────────

export async function preScan(input: PreScanInput): Promise<PreScanResult> {
  const startTime = Date.now();
  const { packageName, version } = input;

  console.log(`[prescan] Starting pre-scan for ${packageName}${version ? `@${version}` : ''}`);

  // Step 1: Fetch tarball
  const { version: resolvedVersion, tarballBuffer } = await fetchTarball(packageName, version);
  console.log(`[prescan] Fetched tarball for ${packageName}@${resolvedVersion} (${tarballBuffer.length} bytes)`);

  // Step 2: Extract in memory
  const entries = await extractTarball(tarballBuffer);
  console.log(`[prescan] Extracted ${entries.length} scannable files`);

  // Step 3: Scan lifecycle scripts
  const packageJsonEntry = entries.find(
    (e) => e.path === 'package.json' || e.path.endsWith('/package.json')
  );
  const lifecycleScripts = packageJsonEntry
    ? scanLifecycleScripts(packageJsonEntry.content)
    : [];

  if (lifecycleScripts.length > 0) {
    console.log(`[prescan] Found ${lifecycleScripts.length} lifecycle script(s)`);
  }

  // Step 4: AST primitive scan
  const primitiveHits = scanTarballEntries(entries);
  console.log(`[prescan] Found ${primitiveHits.length} primitive hit(s) across JS files`);

  // Step 5: Chain detection — correlate primitives into behavioral patterns
  const chains = detectChains(primitiveHits);
  if (chains.length > 0) {
    console.log(`[prescan] Detected ${chains.length} behavioral chain(s)`);
  }

  // Step 6: Score and recommend
  const preScanScore = calculateScore(lifecycleScripts, primitiveHits, chains);
  const recommendation = scoreToRecommendation(preScanScore);

  const result: PreScanResult = {
    package: packageName,
    version: resolvedVersion,
    resolvedAt: new Date().toISOString(),
    preScanScore,
    filesScanned: entries.length,
    lifecycleScripts,
    primitiveHits,
    chains,
    recommendation,
    scanDurationMs: Date.now() - startTime,
  };

  console.log(
    `[prescan] Done. Score: ${preScanScore}/100 → ${recommendation.toUpperCase()} (${result.scanDurationMs}ms)`
  );

  // Step 7: Save JSON result
  const savedPath = saveResultJson(result);
  console.log(`[prescan] Result saved → ${savedPath}`);

  return result;
}

// ── CLI-Friendly Summary Printer ─────────────

export function printPreScanSummary(result: PreScanResult): void {
  const c = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    green: '\x1b[32m',
    bold: '\x1b[1m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
    dim: '\x1b[2m',
  };

  const recommendationColor = {
    block: c.red,
    caution: c.yellow,
    proceed: c.green,
  };

  const severityColor = {
    critical: c.red,
    dangerous: c.red,
    suspicious: c.yellow,
  };

  console.log(`\n${c.bold}── Vaaman Pre-Scan Report ──────────────────${c.reset}`);
  console.log(`${c.cyan}Package:${c.reset}        ${result.package}@${result.version}`);
  console.log(`${c.cyan}Score:${c.reset}          ${result.preScanScore}/100`);
  console.log(
    `${c.cyan}Recommendation:${c.reset} ${recommendationColor[result.recommendation]}${c.bold}${result.recommendation.toUpperCase()}${c.reset}`
  );
  console.log(`${c.cyan}Files scanned:${c.reset}  ${result.filesScanned}`);
  console.log(`${c.cyan}Scan time:${c.reset}      ${result.scanDurationMs}ms`);

  // ── Chains section — shown first, most important ──
  if (result.chains.length > 0) {
    console.log(`\n${c.bold}Behavioral Chains Detected:${c.reset}`);
    for (const chain of result.chains) {
      const color = severityColor[chain.severity];
      console.log(`\n  ${color}${c.bold}[${chain.severity.toUpperCase()}] ${chain.name}${c.reset}`);
      console.log(`  ${c.dim}${chain.description}${c.reset}`);
      console.log(`  ${c.cyan}File:${c.reset} ${chain.file} (lines ${chain.lineRange.start}–${chain.lineRange.end})`);
      console.log(`  ${c.cyan}Primitives:${c.reset} ${chain.hits.map((h) => `${h.primitive}:${h.line}`).join(' → ')}`);
    }
  }

  // ── Lifecycle scripts ──
  if (result.lifecycleScripts.length > 0) {
    console.log(`\n${c.bold}Lifecycle Scripts:${c.reset}`);
    for (const script of result.lifecycleScripts) {
      const color =
        script.riskLevel === 'dangerous' ? c.red
          : script.riskLevel === 'suspicious' ? c.yellow
            : c.green;
      console.log(`  ${color}[${script.riskLevel.toUpperCase()}]${c.reset} ${script.name}`);
      console.log(`  ${c.dim}${script.content.slice(0, 120)}${script.content.length > 120 ? '...' : ''}${c.reset}`);
      for (const reason of script.reasons) {
        console.log(`    ↳ ${reason}`);
      }
    }
  }

  // ── Primitive hits — shown last, supporting detail ──
  if (result.primitiveHits.length > 0) {
    console.log(`\n${c.bold}Primitive Hits (top 10):${c.reset}`);
    const topHits = result.primitiveHits.slice(0, 10);
    for (const hit of topHits) {
      const color = hit.riskLevel === 'dangerous' ? c.red : c.yellow;
      console.log(
        `  ${color}[${hit.riskLevel.toUpperCase()}]${c.reset} ${hit.primitive} in ${c.dim}${hit.file}:${hit.line}${c.reset}`
      );
    }
    if (result.primitiveHits.length > 10) {
      console.log(`  ${c.dim}... and ${result.primitiveHits.length - 10} more${c.reset}`);
    }
  }

  console.log(`\n${c.bold}────────────────────────────────────────────${c.reset}\n`);
}