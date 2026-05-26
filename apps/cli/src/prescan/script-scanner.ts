// ─────────────────────────────────────────────
// Vaaman AI — Lifecycle Script Scanner
// Analyzes postinstall / preinstall / install
// scripts from package.json for malicious patterns
// ─────────────────────────────────────────────

import type { LifecycleScript, RiskLevel } from './types.js';

// Scripts that execute during npm install — highest risk surface
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'prepublish'];

interface ScriptRule {
  pattern: RegExp;
  reason: string;
  risk: RiskLevel;
}

// Ordered from most to least severe
const SCRIPT_RULES: ScriptRule[] = [
  // DANGEROUS — direct execution of remote content
  {
    pattern: /curl\s+.+\|\s*(bash|sh|node|python)/i,
    reason: 'Downloads and executes remote code via curl pipe',
    risk: 'dangerous',
  },
  {
    pattern: /wget\s+.+\|\s*(bash|sh|node|python)/i,
    reason: 'Downloads and executes remote code via wget pipe',
    risk: 'dangerous',
  },
  {
    pattern: /eval\s*\(/i,
    reason: 'Uses eval() in lifecycle script',
    risk: 'dangerous',
  },
  {
    pattern: /require\s*\(\s*['"`]child_process['"`]\s*\)/i,
    reason: 'Requires child_process in lifecycle script',
    risk: 'dangerous',
  },
  {
    pattern: /node\s+-e\s+/i,
    reason: 'Executes inline Node.js code via node -e',
    risk: 'dangerous',
  },
  {
    pattern: /python\s*-c\s+/i,
    reason: 'Executes inline Python code',
    risk: 'dangerous',
  },
  {
    pattern: /Buffer\.from\s*\(.+,\s*['"`]base64['"`]\s*\)/i,
    reason: 'Decodes base64 payload in lifecycle script',
    risk: 'dangerous',
  },

  // SUSPICIOUS — not necessarily malicious but unusual
  {
    pattern: /https?:\/\//i,
    reason: 'Makes outbound HTTP request in lifecycle script',
    risk: 'suspicious',
  },
  {
    pattern: /process\.env/i,
    reason: 'Accesses environment variables in lifecycle script',
    risk: 'suspicious',
  },
  {
    pattern: /fs\.(write|append|unlink|rm)/i,
    reason: 'Writes or deletes files in lifecycle script',
    risk: 'suspicious',
  },
  {
    pattern: /\$\(.*\)/,
    reason: 'Uses shell command substitution',
    risk: 'suspicious',
  },
  {
    pattern: /chmod\s+[0-7]{3,4}/i,
    reason: 'Changes file permissions in lifecycle script',
    risk: 'suspicious',
  },
  {
    pattern: /~\/\.|\/\.ssh|\/\.bashrc|\/\.profile|\/\.zshrc/i,
    reason: 'Accesses home directory or shell config files',
    risk: 'suspicious',
  },
];

/**
 * Parses and scans all lifecycle scripts from a package.json content string.
 * Returns structured LifecycleScript results.
 */
export function scanLifecycleScripts(packageJsonContent: string): LifecycleScript[] {
  let pkg: Record<string, unknown>;

  try {
    pkg = JSON.parse(packageJsonContent);
  } catch {
    return []; // malformed package.json — handled upstream
  }

  const scripts = (pkg.scripts ?? {}) as Record<string, string>;
  const results: LifecycleScript[] = [];

  for (const hook of LIFECYCLE_HOOKS) {
    const content = scripts[hook];
    if (!content || typeof content !== 'string') continue;

    const { riskLevel, reasons } = assessScript(content);

    results.push({
      name: hook,
      content,
      riskLevel,
      reasons,
    });
  }

  return results;
}

/**
 * Scores a single script string against all rules.
 * Takes the highest risk level found.
 */
function assessScript(script: string): { riskLevel: RiskLevel; reasons: string[] } {
  const reasons: string[] = [];
  let highestRisk: RiskLevel = 'safe';

  for (const rule of SCRIPT_RULES) {
    if (rule.pattern.test(script)) {
      reasons.push(rule.reason);

      if (rule.risk === 'dangerous') {
        highestRisk = 'dangerous';
      } else if (rule.risk === 'suspicious' && highestRisk !== 'dangerous') {
        highestRisk = 'suspicious';
      }
    }
  }

  return { riskLevel: highestRisk, reasons };
}
