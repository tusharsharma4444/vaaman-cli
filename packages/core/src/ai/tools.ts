// @vaaman/core — Tool definitions for agentic use
// Tools are called by swarm agents via OpenRouter's tool_use mechanism.
// Every tool returns reasoned data — not raw data — to conserve agent context window.
//
// These definitions are shared: all agents get all tools, the agent decides
// at runtime which to invoke based on its investigation.

import type { ToolDefinition } from './openrouter.js'

export const VAAMAN_TOOLS: ToolDefinition[] = [
  {
    name: 'run_prescan',
    description: 'Download and statically analyze an npm package tarball before install. Returns lifecycle scripts (preinstall, postinstall, install), AST primitive hits (eval, child_process, fetch, etc.), correlated behavioral chains, and a pre-scan risk score (0-100).',
    input_schema: {
      type: 'object',
      properties: {
        packageName: {
          type: 'string',
          description: 'npm package name (e.g. "lodash", "@scope/pkg")',
        },
        version: {
          type: 'string',
          description: 'Semver version or "latest" (default: latest)',
        },
      },
      required: ['packageName'],
    },
  },
  {
    name: 'run_behavioral',
    description: 'Run npm install inside a sandbox under strace monitoring and return real-time behavioral events (process spawns, network connections, filesystem writes) and detected attack chains. This is the most expensive tool — it actually executes the package.',
    input_schema: {
      type: 'object',
      properties: {
        packageName: {
          type: 'string',
          description: 'npm package name to install and monitor',
        },
        version: {
          type: 'string',
          description: 'Semver version (default: latest)',
        },
        timeoutMs: {
          type: 'number',
          description: 'Max install duration in ms (default: 60000)',
        },
      },
      required: ['packageName'],
    },
  },
  {
    name: 'query_osv',
    description: 'Fetch all known CVEs (Common Vulnerabilities and Exposures) for a package from the OSV.dev open-source vulnerability database. Returns normalized CVE objects with install-time exploitability classification.',
    input_schema: {
      type: 'object',
      properties: {
        packageName: {
          type: 'string',
          description: 'Package name to query',
        },
        ecosystem: {
          type: 'string',
          enum: ['npm', 'PyPI', 'crates.io', 'Go'],
          description: 'Package ecosystem (default: npm)',
        },
      },
      required: ['packageName'],
    },
  },
  {
    name: 'score_intent',
    description: 'Run the Deep Intel intent classifier on a set of findings. Classifies each behavior as compiler-utility, framework-internal, operational-legitimate, suspicious-execution, payload-execution, or credential-harvesting. Returns contextual intent analysis.',
    input_schema: {
      type: 'object',
      properties: {
        findings: {
          type: 'array',
          description: 'Array of findings to classify (primitive hits, events, or chains)',
        },
      },
      required: ['findings'],
    },
  },
  {
    name: 'query_graph',
    description: 'Query the Neo4j threat graph for prior scan data. Find cross-package correlations, shared attack chains, and blast radius patterns. Use Cypher query language.',
    input_schema: {
      type: 'object',
      properties: {
        cypher: {
          type: 'string',
          description: 'Cypher query to execute against the threat graph',
        },
        params: {
          type: 'object',
          description: 'Query parameters (optional)',
        },
      },
      required: ['cypher'],
    },
  },
]
