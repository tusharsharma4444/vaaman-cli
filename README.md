# Vaaman

**Real-time supply chain attack detection for npm.**

Vaaman wraps `npm install` and watches what packages actually do at the OS level — live, as it happens. Not CVE databases. Not static rules. Actual behavior.

```
vaaman install 9router
```

```
  ▲ VAAMAN — supply chain monitor
────────────────────────────────────────────────────────────
  Scanning: 9router
  Watching: processes · network · filesystem
────────────────────────────────────────────────────────────

  ┌─ npm install output ─────────────────────────────────────
  19:38:30.702 ⚙ process    Unknown process during install: prebuild-install
  🟡 SUSPICIOUS — Unknown process spawned from hidden runtime directory

  19:38:30.788 📁 filesystem File write outside project directory: /etc/ssl/openssl.cnf
  🟡 SUSPICIOUS — Writing to system path during install

  19:38:41.458 ⚙ process    Remote download tool: wget — https://example.com
  🟠 DANGEROUS — Remote download detected mid-install

  added 11 packages in 49s
  └─ end npm output ─────────────────────────────────────────

  Verdict  🟠  DANGEROUS
  Attack chains: curl-exec
  Signals: 1 dangerous · 3 suspicious

  ✗ Dangerous behavior detected. Investigate before proceeding.
```

---

## Why this exists

Every existing tool fails the same way:

- **npm audit** — only knows about CVEs. A brand new malicious package has none.
- **Snyk / Dependabot** — database-driven. Zero-day supply chain attacks bypass them entirely.
- **Semgrep / ESLint** — scans your code, not your dependencies' code.

None of them watch what a package **actually does** when it installs.

Vaaman does.

---

## How it works

When you run `vaaman install`, it:

1. Wraps `npm install` with `strace` — intercepting every OS-level syscall
2. Watches three layers simultaneously:
   - **Processes** — every binary spawned during install
   - **Network** — every outbound connection
   - **Filesystem** — every file written outside `node_modules`
3. Correlates events into attack chains in real time
4. Prints a full threat report when install completes

The key insight: `strace` hooks at the kernel level via `execve()` syscalls. It cannot miss a process spawn — even ones that die in under 10 milliseconds. Polling `/proc` cannot do this. CVE databases cannot do this.

---

## Attack chains detected

| Chain | Pattern | Verdict |
|-------|---------|---------|
| `network-exec` | Download + execute | 🔴 Critical |
| `obfuscation-exec` | base64 decode + execute | 🔴 Critical |
| `homedir-write` | Writing to ~/.bashrc, ~/.ssh | 🔴 Critical |
| `suspicious-port` | Connection to known C2 port | 🔴 Critical |
| `curl-exec` | Remote download tool spawned | 🟠 Dangerous |
| `shell-spawn` | Shell spawned in postinstall | 🟠 Dangerous |
| `env-harvest` | Outbound on non-standard port | 🟡 Suspicious |

A single wget call is dangerous. A wget piped into sh is critical. Chains matter more than individual signals.

---

## Requirements

- **Linux** — monitoring uses /proc and strace
- **Node.js** 18+
- **strace** — apt-get install -y strace

> Windows/macOS users: use Docker. This is where CI/CD runs anyway.

---

## Quickstart with Docker

```bash
git clone https://github.com/your-username/vaaman
cd vaaman
docker build -t vaaman .
docker run -it vaaman bash
```

Inside the container:

```bash
vaaman install <package-name>
vaaman install <package-name> --verbose
vaaman install <package-name> --no-block
```

---

## Local setup (Linux)

```bash
git clone https://github.com/your-username/vaaman
cd vaaman
npm install
npm run build
npm link
apt-get install -y strace
```

---

## What it won't catch (yet)

- **Runtime-only attacks** — malicious code that runs inside your app, not at install time (e.g. event-stream 2018)
- **Dead C2 servers** — if the attacker's server is offline, wget runs but fails silently
- **Encrypted payloads** — static bytes with no install-time behavior

These require a static pre-scan layer — reading package contents before install runs. That is next on the roadmap.

---

## Architecture

```
vaaman install
    |
src/index.ts       CLI — flags, orchestration
    |
src/runner.ts      Spawns: strace -f -e execve -- npm install
    |
src/monitor/
  strace.ts        Parses execve stream — every process spawn
  network.ts       /proc/net/tcp — outbound connections
  filesystem.ts    /proc/<pid>/fd — writes outside node_modules
    |
src/ai/
  reasoner.ts      Events -> attack chains -> verdict
    |
src/reporter.ts    Terminal output
```

---

## Roadmap

- [ ] Static pre-scan — read package tarball before install
- [ ] Block mode — kill install on critical signal
- [ ] GitHub Action — CI/CD integration
- [ ] macOS support via dtrace
- [ ] eBPF backend — no strace dependency
- [ ] LLM reasoning layer for novel patterns
- [ ] Package reputation scoring

---

## Status

v0.1.0 — proof of concept. Core behavioral monitoring works. Tested against real suspicious packages. Use in sandboxed environments.

PRs welcome.