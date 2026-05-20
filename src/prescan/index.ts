// ─────────────────────────────────────────────
// Vaaman AI — Pre-Scan Orchestrator
// Main entry point. Coordinates:
//   fetcher → extractor → script-scanner → ast-scanner → scoring
// ─────────────────────────────────────────────

import { fetchTarball } from './fetcher.js';
import { extractTarball } from './extractor.js';
import { scanLifecycleScripts } from './script-scanner.js';
import { scanTarballEntries } from './ast-scanner.js';
import type { PreScanInput, PreScanResult, Recommendation } from './types.js';

// ── Scoring Constants ─────────────────────────

const SCORE_WEIGHTS = {
  // Lifecycle script risk contributions
  lifecycle: {
    dangerous: 35,
    suspicious: 15,
    safe: 0,
  },
  // Primitive hit risk contributions (per hit, capped)
  primitive: {
    dangerous: 20,
    suspicious: 8,
  },
  // Max contribution from primitives (prevents runaway scores)
  primitiveMax: 50,
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
  primitiveHits: PreScanResult['primitiveHits']
): number {
  let score = 0;

  // Lifecycle script scoring
  for (const script of lifecycleScripts) {
    score += SCORE_WEIGHTS.lifecycle[script.riskLevel];
  }

  // Primitive hit scoring (capped)
  let primitiveScore = 0;
  for (const hit of primitiveHits) {
    if (hit.riskLevel === 'dangerous') {
      primitiveScore += SCORE_WEIGHTS.primitive.dangerous;
    } else if (hit.riskLevel === 'suspicious') {
      primitiveScore += SCORE_WEIGHTS.primitive.suspicious;
    }
  }
  score += Math.min(primitiveScore, SCORE_WEIGHTS.primitiveMax);

  return Math.min(score, 100); // cap at 100
}

// ── Main Orchestrator ─────────────────────────

/**
 * Runs the full pre-scan pipeline for a package.
 *
 * Steps:
 *  1. Fetch tarball from npm registry
 *  2. Extract all JS/JSON files in memory
 *  3. Scan package.json lifecycle scripts
 *  4. Run AST-based primitive scan on all JS files
 *  5. Score and produce final PreScanResult
 */
export async function preScan(input: PreScanInput): Promise<PreScanResult> {
  const startTime = Date.now();
  const { packageName, version } = input;

  console.log(`[prescan] Starting pre-scan for ${packageName}${version ? `@${version}` : ''}`);

  // ── Step 1: Fetch tarball ──────────────────
  const { version: resolvedVersion, tarballBuffer } = await fetchTarball(packageName, version);
  console.log(`[prescan] Fetched tarball for ${packageName}@${resolvedVersion} (${tarballBuffer.length} bytes)`);

  // ── Step 2: Extract in memory ──────────────
  const entries = await extractTarball(tarballBuffer);
  console.log(`[prescan] Extracted ${entries.length} scannable files`);

  // ── Step 3: Scan lifecycle scripts ────────
  const packageJsonEntry = entries.find(
    (e) => e.path === 'package.json' || e.path.endsWith('/package.json')
  );

  const lifecycleScripts = packageJsonEntry
    ? scanLifecycleScripts(packageJsonEntry.content)
    : [];

  if (lifecycleScripts.length > 0) {
    console.log(`[prescan] Found ${lifecycleScripts.length} lifecycle script(s)`);
  }

  // ── Step 4: AST primitive scan ────────────
  const primitiveHits = scanTarballEntries(entries);
  console.log(`[prescan] Found ${primitiveHits.length} primitive hit(s) across JS files`);

  // ── Step 5: Score and recommend ───────────
  const preScanScore = calculateScore(lifecycleScripts, primitiveHits);
  const recommendation = scoreToRecommendation(preScanScore);

  const result: PreScanResult = {
    package: packageName,
    version: resolvedVersion,
    resolvedAt: new Date().toISOString(),
    preScanScore,
    filesScanned: entries.length,
    lifecycleScripts,
    primitiveHits,
    recommendation,
    scanDurationMs: Date.now() - startTime,
  };

  console.log(
    `[prescan] Done. Score: ${preScanScore}/100 → ${recommendation.toUpperCase()} (${result.scanDurationMs}ms)`
  );

  return result;
}

// ── CLI-Friendly Summary Printer ─────────────

export function printPreScanSummary(result: PreScanResult): void {
  const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    green: '\x1b[32m',
    bold: '\x1b[1m',
    cyan: '\x1b[36m',
  };

  const recommendationColor = {
    block: colors.red,
    caution: colors.yellow,
    proceed: colors.green,
  };

  console.log(`\n${colors.bold}── Vaaman Pre-Scan Report ──────────────────${colors.reset}`);
  console.log(`${colors.cyan}Package:${colors.reset}        ${result.package}@${result.version}`);
  console.log(`${colors.cyan}Score:${colors.reset}          ${result.preScanScore}/100`);
  console.log(
    `${colors.cyan}Recommendation:${colors.reset} ${recommendationColor[result.recommendation]}${colors.bold}${result.recommendation.toUpperCase()}${colors.reset}`
  );
  console.log(`${colors.cyan}Files scanned:${colors.reset}  ${result.filesScanned}`);
  console.log(`${colors.cyan}Scan time:${colors.reset}      ${result.scanDurationMs}ms`);

  if (result.lifecycleScripts.length > 0) {
    console.log(`\n${colors.bold}Lifecycle Scripts:${colors.reset}`);
    for (const script of result.lifecycleScripts) {
      const color =
        script.riskLevel === 'dangerous'
          ? colors.red
          : script.riskLevel === 'suspicious'
            ? colors.yellow
            : colors.green;
      console.log(`  ${color}[${script.riskLevel.toUpperCase()}]${colors.reset} ${script.name}`);
      console.log(`    Script: ${script.content.slice(0, 120)}${script.content.length > 120 ? '...' : ''}`);
      for (const reason of script.reasons) {
        console.log(`    ↳ ${reason}`);
      }
    }
  }

  if (result.primitiveHits.length > 0) {
    console.log(`\n${colors.bold}Primitive Hits (top 10):${colors.reset}`);
    const topHits = result.primitiveHits.slice(0, 10);
    for (const hit of topHits) {
      const color = hit.riskLevel === 'dangerous' ? colors.red : colors.yellow;
      console.log(
        `  ${color}[${hit.riskLevel.toUpperCase()}]${colors.reset} ${hit.primitive} in ${hit.file}:${hit.line}`
      );
    }
    if (result.primitiveHits.length > 10) {
      console.log(`  ... and ${result.primitiveHits.length - 10} more`);
    }
  }

  console.log(`\n${colors.bold}────────────────────────────────────────────${colors.reset}\n`);
}


