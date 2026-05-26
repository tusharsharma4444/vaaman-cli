// ─────────────────────────────────────────────
// Vaaman AI — Chain Detector
// Detects co-located primitive combinations
// that indicate malicious behavior patterns.
//
// Core insight: a single primitive is noise.
// Two related primitives in the same file
// within proximity = a behavioral chain.
// ─────────────────────────────────────────────

import type { PrimitiveHit } from './types.js';

// ── Chain Types ───────────────────────────────

export type ChainSeverity = 'suspicious' | 'dangerous' | 'critical';

export interface DetectedChain {
    id: string;               // e.g. 'credential-harvest'
    name: string;             // human-readable name
    description: string;      // what this chain means
    severity: ChainSeverity;
    file: string;             // file where chain was detected
    hits: PrimitiveHit[];     // the specific hits that form this chain
    lineRange: {
        start: number;
        end: number;
    };
}

// ── Chain Rules ───────────────────────────────

interface ChainRule {
    id: string;
    name: string;
    description: string;
    severity: ChainSeverity;
    // All of these primitives must appear in the same file
    requires: string[];
    // At least one of these must appear (optional — if empty, only requires matters)
    anyOf?: string[];
    // Max line distance between the first and last hit (default: 100)
    proximityLines?: number;
}

const CHAIN_RULES: ChainRule[] = [
    {
        id: 'remote-payload',
        name: 'Remote Payload Execution',
        description: 'Fetches remote content and executes it directly — classic supply chain loader pattern',
        severity: 'critical',
        requires: ['fetch', 'eval'],
        proximityLines: 50,
    },
    {
        id: 'obfuscated-exec',
        name: 'Obfuscated Payload Execution',
        description: 'Decodes a base64 payload and evaluates it — strongly indicates hidden malicious code',
        severity: 'critical',
        requires: ["Buffer.from(..., 'base64')", 'eval'],
        proximityLines: 30,
    },
    {
        id: 'credential-harvest',
        name: 'Credential Harvesting',
        description: 'Reads environment variables and sends them over the network — exfiltration pattern',
        severity: 'dangerous',
        requires: ['process.env', 'fetch'],
        proximityLines: 100,
    },
    {
        id: 'env-exfil-shell',
        name: 'Environment Exfiltration via Shell',
        description: 'Reads env vars and executes shell commands — could be exfiltrating secrets via subprocess',
        severity: 'dangerous',
        requires: ['process.env'],
        anyOf: ["require('child_process')", 'child_process.exec'],
        proximityLines: 100,
    },
    {
        id: 'shell-exec-chain',
        name: 'Shell Execution Chain',
        description: 'Requires child_process and immediately invokes exec/spawn — direct command execution',
        severity: 'dangerous',
        requires: ["require('child_process')", 'child_process.exec'],
        proximityLines: 30,
    },
    {
        id: 'b64-network',
        name: 'Base64 + Network Activity',
        description: 'Decodes base64 data and makes network requests — possible encoded C2 communication',
        severity: 'dangerous',
        requires: ["Buffer.from(..., 'base64')", 'fetch'],
        proximityLines: 50,
    },
    {
        id: 'indirect-eval',
        name: 'Indirect Code Execution',
        description: 'Uses Function() constructor as an indirect eval — common obfuscation technique',
        severity: 'suspicious',
        requires: ['Function() constructor'],
        proximityLines: 999,
    },
];

// ── Chain Detector ────────────────────────────

/**
 * Groups primitive hits by file path.
 */
function groupByFile(hits: PrimitiveHit[]): Map<string, PrimitiveHit[]> {
    const groups = new Map<string, PrimitiveHit[]>();
    for (const hit of hits) {
        const existing = groups.get(hit.file) ?? [];
        existing.push(hit);
        groups.set(hit.file, existing);
    }
    return groups;
}

/**
 * Checks if a set of hits satisfies a chain rule's primitive requirements.
 * Returns the matching hits if satisfied, null otherwise.
 */
function matchChainRule(
    rule: ChainRule,
    fileHits: PrimitiveHit[]
): PrimitiveHit[] | null {
    const proximity = rule.proximityLines ?? 100;

    // Find hits for each required primitive
    const requiredMatches: PrimitiveHit[] = [];
    for (const requiredPrimitive of rule.requires) {
        const match = fileHits.find((h) => h.primitive === requiredPrimitive);
        if (!match) return null; // missing a required primitive — no chain
        requiredMatches.push(match);
    }

    // Check anyOf — at least one must match
    let anyOfMatches: PrimitiveHit[] = [];
    if (rule.anyOf && rule.anyOf.length > 0) {
        const match = fileHits.find((h) => rule.anyOf!.includes(h.primitive));
        if (!match) return null; // none of the anyOf matched
        anyOfMatches = [match];
    }

    const allMatches = [...requiredMatches, ...anyOfMatches];

    // Deduplicate by file+line (a hit can satisfy multiple rules)
    const unique = allMatches.filter(
        (hit, idx, arr) =>
            arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
    );

    // Check proximity — all matching hits must be within N lines of each other
    const lines = unique.map((h) => h.line).sort((a, b) => a - b);
    const lineSpan = lines[lines.length - 1] - lines[0];

    if (lineSpan > proximity) return null;

    return unique;
}

/**
 * Main chain detection function.
 * Takes all primitive hits from the AST scanner and returns
 * detected behavioral chains.
 */
export function detectChains(hits: PrimitiveHit[]): DetectedChain[] {
    const chains: DetectedChain[] = [];
    const byFile = groupByFile(hits);

    for (const [file, fileHits] of byFile) {
        for (const rule of CHAIN_RULES) {
            const matchingHits = matchChainRule(rule, fileHits);
            if (!matchingHits) continue;

            const lines = matchingHits.map((h) => h.line).sort((a, b) => a - b);

            chains.push({
                id: rule.id,
                name: rule.name,
                description: rule.description,
                severity: rule.severity,
                file,
                hits: matchingHits,
                lineRange: {
                    start: lines[0],
                    end: lines[lines.length - 1],
                },
            });
        }
    }

    // Sort by severity: critical first, then dangerous, then suspicious
    const severityOrder: Record<ChainSeverity, number> = {
        critical: 0,
        dangerous: 1,
        suspicious: 2,
    };

    return chains.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

// ── Chain Score Contribution ──────────────────

/**
 * Returns the score contribution from detected chains.
 * Chains add significantly more weight than individual hits
 * because they represent correlated behavior, not isolated primitives.
 */
export function chainScoreContribution(chains: DetectedChain[]): number {
    const weights: Record<ChainSeverity, number> = {
        critical: 40,
        dangerous: 25,
        suspicious: 10,
    };

    let score = 0;
    for (const chain of chains) {
        score += weights[chain.severity];
    }

    // Cap chain contribution at 80 — leaves room for lifecycle scripts
    return Math.min(score, 80);
}