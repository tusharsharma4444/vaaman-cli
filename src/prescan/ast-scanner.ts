// ─────────────────────────────────────────────
// Vaaman AI — AST Primitive Scanner
// Uses acorn to parse JS and detect dangerous
// primitives via AST traversal (not just regex)
// ─────────────────────────────────────────────

import * as acorn from 'acorn';
import type { Node, CallExpression, MemberExpression, Identifier, Literal } from 'acorn';
import type { PrimitiveHit, RiskLevel, TarballEntry } from './types';

// ── Primitive Detection Rules ──────────────────

interface PrimitiveRule {
  label: string;
  risk: RiskLevel;
  // Called with the AST node — returns true if this is a match
  match: (node: Node) => boolean;
}

const PRIMITIVE_RULES: PrimitiveRule[] = [
  // eval(...)
  {
    label: 'eval',
    risk: 'dangerous',
    match: (node) =>
      node.type === 'CallExpression' &&
      (node as CallExpression).callee.type === 'Identifier' &&
      ((node as CallExpression).callee as Identifier).name === 'eval',
  },

  // Function('...')(...) — indirect eval
  {
    label: 'Function() constructor',
    risk: 'dangerous',
    match: (node) =>
      node.type === 'NewExpression' &&
      (node as any).callee?.type === 'Identifier' &&
      (node as any).callee?.name === 'Function',
  },

  // child_process.exec / execSync / spawn / spawnSync
  {
    label: 'child_process.exec',
    risk: 'dangerous',
    match: (node) => {
      if (node.type !== 'CallExpression') return false;
      const callee = (node as CallExpression).callee;
      if (callee.type !== 'MemberExpression') return false;
      const member = callee as MemberExpression;
      const prop = member.property as Identifier;
      return ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(prop.name ?? '');
    },
  },

  // require('child_process')
  {
    label: "require('child_process')",
    risk: 'dangerous',
    match: (node) => {
      if (node.type !== 'CallExpression') return false;
      const call = node as CallExpression;
      if (call.callee.type !== 'Identifier') return false;
      if ((call.callee as Identifier).name !== 'require') return false;
      const arg = call.arguments[0];
      return arg?.type === 'Literal' && (arg as Literal).value === 'child_process';
    },
  },

  // Buffer.from(..., 'base64') — obfuscated payload decoding
  {
    label: "Buffer.from(..., 'base64')",
    risk: 'dangerous',
    match: (node) => {
      if (node.type !== 'CallExpression') return false;
      const call = node as CallExpression;
      if (call.callee.type !== 'MemberExpression') return false;
      const member = call.callee as MemberExpression;
      const obj = member.object as Identifier;
      const prop = member.property as Identifier;
      if (obj.name !== 'Buffer' || prop.name !== 'from') return false;
      const secondArg = call.arguments[1];
      return secondArg?.type === 'Literal' && (secondArg as Literal).value === 'base64';
    },
  },

  // fetch(...) — outbound network call
  {
    label: 'fetch',
    risk: 'suspicious',
    match: (node) =>
      node.type === 'CallExpression' &&
      (node as CallExpression).callee.type === 'Identifier' &&
      ((node as CallExpression).callee as Identifier).name === 'fetch',
  },

  // process.env.SOMETHING — direct access pattern
  {
    label: 'process.env',
    risk: 'suspicious',
    match: (node) => {
      // Match: process.env (MemberExpression where object=process, property=env)
      if (node.type !== 'MemberExpression') return false;
      const member = node as MemberExpression;
      const obj = member.object;
      if (obj.type !== 'Identifier') return false;
      if ((obj as Identifier).name !== 'process') return false;
      const prop = member.property;
      if (prop.type !== 'Identifier') return false;
      return (prop as Identifier).name === 'env';
    },
  },

  // atob / btoa — base64 encode/decode (browser & Node 16+)
  {
    label: 'atob/btoa',
    risk: 'suspicious',
    match: (node) =>
      node.type === 'CallExpression' &&
      (node as CallExpression).callee.type === 'Identifier' &&
      ['atob', 'btoa'].includes(((node as CallExpression).callee as Identifier).name),
  },
];

// ── AST Walker ────────────────────────────────

/**
 * Recursively walks every node in an AST.
 * Calls visitor for each node encountered.
 */
function walk(node: Node | null | undefined, visitor: (n: Node) => void): void {
  if (!node || typeof node !== 'object') return;

  visitor(node);

  for (const key of Object.keys(node)) {
    const child = (node as any)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item.type === 'string') {
          walk(item, visitor);
        }
      }
    } else if (child && typeof child.type === 'string') {
      walk(child, visitor);
    }
  }
}

// ── Line Number Utility ───────────────────────

/**
 * Converts a character offset (acorn's `start`) to a 1-based line number.
 */
function offsetToLineCol(source: string, offset: number): { line: number; column: number } {
  const lines = source.slice(0, offset).split('\n');
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

/**
 * Extracts ±2 lines of context around a given line number.
 */
function extractContext(source: string, lineNumber: number): string {
  const lines = source.split('\n');
  const start = Math.max(0, lineNumber - 2);
  const end = Math.min(lines.length - 1, lineNumber + 1);
  return lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join('\n');
}

// ── Main Scanner ──────────────────────────────

/**
 * Scans a single JS file's source string using acorn AST.
 * Returns all primitive hits found.
 */
function scanFileSource(filePath: string, source: string): PrimitiveHit[] {
  const hits: PrimitiveHit[] = [];

  let ast: acorn.Program;
  try {
    ast = acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
  } catch {
    // If module parse fails, try script mode (CommonJS)
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        allowHashBang: true,
      });
    } catch {
      // Unparseable file — skip AST scan (regex scan may still catch things)
      return hits;
    }
  }

  walk(ast as Node, (node) => {
    for (const rule of PRIMITIVE_RULES) {
      if (rule.match(node)) {
        const { line, column } = offsetToLineCol(source, (node as any).start ?? 0);
        hits.push({
          file: filePath,
          line,
          column,
          primitive: rule.label,
          context: extractContext(source, line),
          riskLevel: rule.risk,
        });
      }
    }
  });

  return hits;
}

// ── Batch Scanner ─────────────────────────────

const JS_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);

// ── File-Level Suppression ────────────────────
// Even after path suppression in extractor, some framework internals
// slip through via non-standard paths. Suppress by filename pattern.

const SUPPRESSED_FILE_PATTERNS = [
  /webpack[._-]/i,          // webpack runtime/chunks
  /rollup[._-]/i,           // rollup bundles
  /chunk\.\w+\.js$/i,       // generic chunk files (e.g. chunk.abc123.js)
  /\d+\.js$/,               // numbered chunks (e.g. 1444.js, 2212.js) — build output
  /vendor\./i,              // vendor bundles
  /polyfill/i,              // polyfill files
  /runtime\./i,             // runtime files
];

function isSuppressedFile(filePath: string): boolean {
  const filename = filePath.split('/').pop() ?? filePath;
  return SUPPRESSED_FILE_PATTERNS.some((pattern) => pattern.test(filename));
}

/**
 * Scans all JS files extracted from a tarball.
 * Skips .ts, .json (handled elsewhere), minified files.
 */
export function scanTarballEntries(entries: TarballEntry[]): PrimitiveHit[] {
  const allHits: PrimitiveHit[] = [];

  for (const entry of entries) {
    const ext = getExtension(entry.path);
    if (!JS_EXTENSIONS.has(ext)) continue;

    // Skip build artifacts and framework chunks — high noise, low signal
    if (isSuppressedFile(entry.path)) continue;

    // Skip likely minified files — they produce massive false positives
    if (isLikelyMinified(entry.content)) continue;

    const hits = scanFileSource(entry.path, entry.content);
    allHits.push(...hits);
  }

  return allHits;
}

function getExtension(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  return lastDot === -1 ? '' : filePath.slice(lastDot).toLowerCase();
}

/**
 * Heuristic: if average line length > 500 chars, likely minified.
 * Minified files make AST scanning noisy and slow.
 */
function isLikelyMinified(source: string): boolean {
  const lines = source.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length === 0) return false;
  const totalChars = lines.reduce((sum, l) => sum + l.length, 0);
  return totalChars / lines.length > 500;
}