// src/reporter.ts
// Beautiful, information-dense terminal output for Vaaman.
// Designed to be readable at a glance — security output should never be noisy.
import chalk from 'chalk';
// ─── Theme ────────────────────────────────────────────────────────────────────
const theme = {
    brand: chalk.hex('#FF6B35'), // Vaaman orange
    dim: chalk.gray,
    critical: chalk.hex('#FF2D55').bold,
    dangerous: chalk.hex('#FF9500').bold,
    suspicious: chalk.hex('#FFD60A'),
    clean: chalk.hex('#30D158').bold,
    info: chalk.hex('#64D2FF'),
    muted: chalk.hex('#8E8E93'),
    bold: chalk.white.bold,
};
// ─── Helpers ──────────────────────────────────────────────────────────────────
function levelIcon(level) {
    switch (level) {
        case 'critical': return '🔴';
        case 'dangerous': return '🟠';
        case 'suspicious': return '🟡';
        case 'clean': return '🟢';
    }
}
function levelColor(level) {
    switch (level) {
        case 'critical': return theme.critical;
        case 'dangerous': return theme.dangerous;
        case 'suspicious': return theme.suspicious;
        case 'clean': return theme.clean;
    }
}
function formatDuration(ms) {
    if (ms < 1000)
        return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
}
function divider(char = '─', width = 60) {
    return theme.muted(char.repeat(width));
}
// ─── Live Event Printer ───────────────────────────────────────────────────────
// Called in real-time as events come in during monitoring
export function printLiveEvent(event) {
    const time = theme.muted(new Date(event.timestamp).toISOString().slice(11, 23));
    const icons = {
        process: '⚙',
        network: '🌐',
        filesystem: '📁',
    };
    const icon = icons[event.type];
    const typeLabel = theme.info(event.type.padEnd(10));
    console.log(`  ${time} ${icon} ${typeLabel} ${event.detail}`);
}
export function printLiveSignal(signal) {
    const icon = levelIcon(signal.level);
    const color = levelColor(signal.level);
    console.log(`\n  ${icon} ${color(signal.level.toUpperCase())} — ${signal.reason}\n`);
}
// ─── Header ───────────────────────────────────────────────────────────────────
export function printHeader(packages) {
    console.log();
    console.log(theme.brand.bold('  ▲ VAAMAN') + theme.muted(' — supply chain monitor'));
    console.log(divider());
    console.log(theme.muted(`  Scanning: `) + theme.bold(packages));
    console.log(theme.muted(`  Watching: processes · network · filesystem`));
    console.log(divider());
    console.log();
}
// ─── Install Output Header ────────────────────────────────────────────────────
export function printInstallStart() {
    console.log(theme.muted('  ┌─ npm install output ') + theme.muted('─'.repeat(38)));
}
export function printInstallEnd() {
    console.log(theme.muted('  └─ end npm output ') + theme.muted('─'.repeat(41)));
    console.log();
}
// ─── Live Monitoring Header ───────────────────────────────────────────────────
export function printMonitoringStart() {
    console.log();
    console.log(theme.muted('  ┌─ monitoring ') + theme.muted('─'.repeat(45)));
}
export function printMonitoringEnd() {
    console.log(theme.muted('  └─ scan complete ') + theme.muted('─'.repeat(42)));
}
// ─── Final Report ─────────────────────────────────────────────────────────────
export function printReport(result) {
    console.log();
    console.log(divider('═'));
    console.log(theme.brand.bold('  VAAMAN SECURITY REPORT'));
    console.log(divider('═'));
    console.log();
    // Verdict
    const verdictColor = levelColor(result.verdict);
    const verdictIcon = levelIcon(result.verdict);
    console.log(`  Verdict  ${verdictIcon}  ${verdictColor(result.verdict.toUpperCase())}`);
    console.log(`  Duration     ${formatDuration(result.duration)}`);
    console.log(`  Events       ${result.events.length} monitored`);
    console.log(`  Signals      ${result.signals.length} found`);
    if (result.blocked) {
        console.log(`  Action   ${theme.critical('INSTALL BLOCKED')}`);
    }
    console.log();
    // Summary
    console.log(`  ${theme.bold('Summary')}`);
    console.log(`  ${result.summary}`);
    console.log();
    // Signals breakdown
    if (result.signals.length > 0) {
        console.log(divider());
        console.log(`  ${theme.bold('Threat Signals')}`);
        console.log();
        // Group by level
        const order = ['critical', 'dangerous', 'suspicious', 'clean'];
        for (const level of order) {
            const levelSignals = result.signals.filter(s => s.level === level);
            if (levelSignals.length === 0)
                continue;
            for (const signal of levelSignals) {
                const icon = levelIcon(signal.level);
                const color = levelColor(signal.level);
                console.log(`  ${icon} ${color(signal.level.padEnd(10))}  ${signal.reason}`);
                if (signal.chain && signal.chain.length > 0) {
                    console.log(`              ${theme.muted('chain: ' + signal.chain.join(' → '))}`);
                }
            }
            console.log();
        }
    }
    // Attack chains
    const chainSet = new Set(result.signals.flatMap(s => s.chain ?? []));
    if (chainSet.size > 0) {
        console.log(divider());
        console.log(`  ${theme.bold('Attack Chains Detected')}`);
        console.log();
        for (const chain of chainSet) {
            console.log(`  ${theme.critical('▸')} ${chain}`);
        }
        console.log();
    }
    // Events log (if there are any)
    if (result.events.length > 0) {
        console.log(divider());
        console.log(`  ${theme.bold('Event Log')}`);
        console.log();
        for (const event of result.events.slice(0, 20)) {
            const time = theme.muted(new Date(event.timestamp).toISOString().slice(11, 23));
            const typeLabel = theme.info(`[${event.type}]`.padEnd(14));
            console.log(`  ${time} ${typeLabel} ${event.detail}`);
        }
        if (result.events.length > 20) {
            console.log(theme.muted(`  ... and ${result.events.length - 20} more events`));
        }
        console.log();
    }
    // Footer
    console.log(divider('═'));
    if (result.verdict === 'clean') {
        console.log(theme.clean('  ✓ Install appears clean. No backdoor activity detected.'));
    }
    else if (result.verdict === 'suspicious') {
        console.log(theme.suspicious('  ⚠ Suspicious activity detected. Review signals above.'));
    }
    else if (result.verdict === 'dangerous') {
        console.log(theme.dangerous('  ✗ Dangerous behavior detected. Investigate before proceeding.'));
    }
    else if (result.verdict === 'critical') {
        console.log(theme.critical('  ✗ CRITICAL THREAT DETECTED. This install should not be trusted.'));
    }
    console.log(divider('═'));
    console.log();
}
// ─── Block Message ────────────────────────────────────────────────────────────
export function printBlocked(reason) {
    console.log();
    console.log(divider('═'));
    console.log(theme.critical('  ✗ INSTALL BLOCKED BY VAAMAN'));
    console.log(divider('═'));
    console.log();
    console.log(`  ${theme.bold('Reason:')} ${reason}`);
    console.log();
    console.log(theme.muted('  The npm install process has been terminated.'));
    console.log(theme.muted('  Run with --no-block to allow installs even on critical findings.'));
    console.log();
    console.log(divider('═'));
    console.log();
}
// ─── Error Messages ───────────────────────────────────────────────────────────
export function printError(msg) {
    console.error(`\n  ${theme.critical('error')} ${msg}\n`);
}
export function printWarning(msg) {
    console.warn(`\n  ${theme.suspicious('warn')} ${msg}\n`);
}
//# sourceMappingURL=reporter.js.map