#!/usr/bin/env node
// src/index.ts
// Vaaman CLI entry point.
// Usage: vaaman install [npm install args]

import { Command } from 'commander'
import * as path from 'path'
import { runInstall } from './runner.js'
import {
  printHeader,
  printReport,
  printError,
  printWarning,
} from './reporter.js'

const program = new Command()

program
  .name('vaaman')
  .description('AI-native supply chain security — watches npm install for backdoor activity')
  .version('0.1.0')

program
  .command('install [packages...]')
  .description('Run npm install with live behavioral monitoring')
  .option('--no-block', 'Do not block install on critical findings (warn only)')
  .option('-v, --verbose', 'Show all monitored events, not just suspicious ones')
  .option('--interval <ms>', 'Monitor polling interval in milliseconds', '200')
  .option('--cwd <path>', 'Working directory for npm install', process.cwd())
  .action(async (packages: string[], opts) => {
    const cwd = path.resolve(opts.cwd)
    const block: boolean = opts.block !== false  // --no-block sets to false
    const verbose: boolean = !!opts.verbose
    const intervalMs = parseInt(opts.interval, 10)

    // Extra args to pass through to npm install
    const npmArgs = packages.length > 0 ? packages : []

    printHeader(
      npmArgs.length > 0
        ? npmArgs.join(' ')
        : '(from package.json)'
    )

    // Check we're on Linux for full monitoring
    if (process.platform !== 'linux') {
      printWarning(
        'Full monitoring requires Linux. ' +
        'On macOS/Windows, only process-level monitoring is available.'
      )
    }

    try {
      const { exitCode, scanResult } = await runInstall({
        args: npmArgs,
        cwd,
        block,
        verbose,
        intervalMs,
      })

      // Always print the full report
      printReport(scanResult)

      // Exit with npm's exit code, unless we blocked
      if (scanResult.blocked) {
        process.exit(1)
      } else {
        process.exit(exitCode)
      }

    } catch (err) {
      printError(err instanceof Error ? err.message : String(err))
      process.exit(1)
    }
  })

// Default command — if someone runs `vaaman` with no subcommand
program
  .command('*', { hidden: true })
  .action(() => {
    program.help()
  })

// If no args, show help
if (process.argv.length < 3) {
  program.help()
}

program.parse(process.argv)
