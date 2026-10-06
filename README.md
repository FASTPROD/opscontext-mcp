# OpsContext for AI Agents

**AI that doesn't break what it can't see.**

Claude Code, Cursor, and Copilot write code without seeing your servers, so they suggest the wrong port, restart the wrong service, deploy into the wrong env. OpsContext gives them eyes on what's actually running, plus a tamper-evident log of every change they make, with an outside time stamp when SealHour is on. Free core, no signup, runs entirely on your machine.

> Previously published as `@compr/contextengine-mcp`. The 2.0 rename reflects what the project actually does: Claude Code sees the **code**, OpsContext sees the **infra that runs it**.

[![npm](https://img.shields.io/npm/v/@compr/opscontext-mcp)](https://www.npmjs.com/package/@compr/opscontext-mcp)
[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-blue.svg)](https://www.npmjs.com/package/@compr/opscontext-mcp)
[![VS Code](https://img.shields.io/badge/VS%20Code-Extension-007ACC?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=css-llc.contextengine)

OpsContext is an [MCP](https://modelcontextprotocol.io) server. It runs locally, snapshots your live infra (PM2 processes, nginx config, Docker containers, git status, cron jobs, redacted env), and exposes it via tools your AI coding agents (Claude Code, Cursor, Copilot, Windsurf, OpenClaw) can call in real time. No telemetry, no code uploads: no record, no file and no code ever leaves your machine. The two things that can leave are listed under [Privacy & Data Security](#privacy--data-security).

> **🌐 Browser Capture (Phase 1, shipped 2026-06):** OpsContext now records prompts, assistant responses and tool calls from **Claude.ai**, **ChatGPT.com**, *and* your **Claude Code** terminal sessions in the same hash-chained audit log. Since 2.9.0 a prompt or a response is kept as its length and a keyed fingerprint, never its words; commands are kept with credentials redacted. Cross-surface drift detection becomes possible (e.g. catch when a model says one thing in the browser and another in the terminal). See [Step 3](#3-capture-browser--claude-code-events-optional) below.

## Why

Claude Code already reads your `CLAUDE.md`, `copilot-instructions.md`, and source files. It has hooks, skills, and native memory. It does not — and structurally cannot — see what's running on your servers. Live process state, nginx routes, port conflicts across fleets, git working-tree drift across 30+ repos — that's the operational context AI agents lack.

OpsContext fills that gap, plus two compliance layers regulated industries demand from any agent stack:

1. **Operational visibility (the moat)** — collectors for PM2 / nginx / Docker / git / cron / .env (redacted) / composer / systemd. Cross-project + check_ports + fleet HTML scoring. Claude Code can't see this; we feed it cleanly.
2. **Tamper-evident audit log, with an outside time stamp when SealHour is on (compliance)**: hash-chained JSONL at `~/.contextengine/audit.log`. Every state change recorded with `prev_hash`/`hash`. The chain is checked from the inside; [SealHour](#sealhour-an-outside-time-stamp-for-the-audit-chain), off until you turn it on, adds a date from outside your machine. Designed to produce evidence aligned with [SOC 2 CC7.2 (change monitoring)](docs/compliance/cc7.2.md) and [ISO 27001 A.12.4.1 (event logging)](docs/compliance/a.12.4.1.md). **These are evidence artifacts, not a certification.** OpsContext is not itself certified for SOC 2 or ISO 27001; the audit log helps *your* org's auditor satisfy *those* controls.
3. **Policy-as-code hooks (enforcement)** — declarative `.contextengine/policy.json` for secret patterns (with `paths` scoping), diff-aware doc coverage (replaces the workaround-y 4-hour staleness gate), deploy-verify hosts, and signed bypass tokens. Runs as a pre-commit hook layer alongside gitleaks.

Plus the persistent-memory + search features carried forward from the contextengine era:

- 🔍 **Hybrid Search** — keyword (BM25) ships always; semantic re-ranking is opt-in
- 🧠 **Semantic Search (optional)** — `all-MiniLM-L6-v2` runs locally on CPU, no API keys. Install with `npm install @huggingface/transformers` (~250MB, native onnxruntime). BM25 alone is plenty for most workspaces; turn semantic on when you have many similar projects and want fuzzy matches.
- 📁 **Auto-discover** — finds `copilot-instructions.md`, `CLAUDE.md`, `.cursorrules`, `AGENTS.md` across all projects
- 💻 **Code Parsing** — extracts functions, classes, interfaces from TS/JS/Python source files
- ⚙️ **Operational Intelligence** — collects git, Docker, PM2, nginx, cron, package.json data
- 🔒 **Local-only**: no record, no file and no code ever leaves your machine
- ⚡ **Instant startup** — keyword search ready immediately, embeddings load in background
- 💾 **Session Persistence** — AI agents can save/restore context across conversations
- 💡 **Learning Store** — permanent operational rules that auto-surface in search results
- 🛡️ **Protocol Firewall** — progressive enforcement that ensures agents commit, document, and save learnings
- 🧩 **MCP native** — works with any MCP-compatible client (VS Code, Claude, Cursor, OpenClaw)

### What OpsContext is NOT

- **Not a replacement for Claude Code, Cursor, or your IDE assistant.** It runs *alongside* them as their ops/compliance backend. Code context = their job. Infra context + audit + policy = ours.
- **Not a code quality tool** — it checks project structure (CI, tests, Docker, docs) and validates content depth, but won't tell you if your code is good. An A+ score means "well-organized for AI agents," not "production-ready."
- **Not required for tiny / solo projects** — agents read `copilot-instructions.md` natively, and the audit log + policy gates earn their keep when there's more than one developer to coordinate or a compliance officer to answer to.
- **Not worth chasing 100% score** — invest in your PIPELINES.md and SKILLS docs instead of score-chasing. Those prevent costly mistakes; the score keeps you honest.

## Quick Start

### 1. Scaffold config (optional)

```bash
npx @compr/opscontext-mcp init
```

Detects your project type, creates `contextengine.json` + `.github/copilot-instructions.md` template.

### 2. Add to your MCP client

**VS Code (recommended — per-project setup)**

Create `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "contextengine": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@compr/opscontext-mcp"]
    }
  }
}
```

This activates ContextEngine when the workspace is open. Add this file to each project that needs it.

> **Note:** VS Code deprecated MCP configuration in user `settings.json`. Use `.vscode/mcp.json` per workspace instead.

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ContextEngine": {
      "command": "npx",
      "args": ["-y", "@compr/opscontext-mcp"]
    }
  }
}
```

**Cursor** — add to MCP settings:

```json
{
  "mcpServers": {
    "ContextEngine": {
      "command": "npx",
      "args": ["-y", "@compr/opscontext-mcp"]
    }
  }
}
```

**OpenClaw** — add ContextEngine as an MCP server in your OpenClaw config, or use the bundled skill:

```bash
# Option 1: Copy the skill to your OpenClaw workspace
cp -r node_modules/@compr/opscontext-mcp/skills/contextengine ~/.openclaw/workspace/skills/

# Option 2: Add as MCP server in openclaw.json
```

```json
{
  "mcpServers": {
    "contextengine": {
      "command": "npx",
      "args": ["-y", "@compr/opscontext-mcp"],
      "env": { "CONTEXTENGINE_WORKSPACES": "~/Projects" }
    }
  }
}
```

### 3. Capture browser + Claude Code events (optional)

Phase-1 browser capture wires Claude.ai / ChatGPT.com / Claude Code into the same hash-chained audit log the MCP server already writes to. Three small commands; each one is independent.

**3a. Generate the browser extension secret**

```bash
npx @compr/opscontext-mcp init-extension-secret
```

Writes a 32-byte hex token to `~/.contextengine/extension-secret` (mode `0600`). The Chrome extension authenticates to your local MCP server with this secret — nobody else on your network can post events.

Verify:
```bash
ls -la ~/.contextengine/extension-secret    # → -rw------- (0600)
```

Then load the unpacked extension and paste the secret into its Options page. Full install steps (build, load unpacked, paste secret): [chrome-extension/README.md](chrome-extension/README.md). *(Chrome Web Store listing coming.)*

**3b. Auto-start the local server (macOS)**

```bash
npx @compr/opscontext-mcp install-autostart
```

Installs a LaunchAgent so OpsContext binds `127.0.0.1:7842` on every login — that's the port the browser extension and the Claude Code hook both post to.

Verify:
```bash
curl http://127.0.0.1:7842/health           # → {"ok":true,...}
```

Companion commands: `uninstall-autostart`, `autostart-status`.

**3c. Wire Claude Code terminal sessions**

```bash
npm i -g @compr/opscontext-mcp && opscontext install-claude-hook
```

(Prefer the global install here: the hook scripts keep absolute paths to the CLI, and an `npx` cache copy can be pruned.)

Adds `UserPromptSubmit`, `PostToolUse`, and `SessionStart` hook entries to `~/.claude/settings.json` so every Claude Code prompt (kept as a length and a keyed fingerprint, not its words) and tool call (credentials redacted) lands in the same audit log as the browser events, plus a `Stop` entry: the **session gate** (2.7.0). A Claude Code turn cannot end while the repo's OpsContext session is older than the last commit; the agent is told which session to save, which session doc to update, and how far the agent docs are behind. No more "did you save the session?" at the end of a day. Details: `npx @compr/opscontext-mcp session-gate --help`.

Verify:
```bash
npx @compr/opscontext-mcp watch --once       # → tails recent events; should show claude_code_* kinds after one prompt
```

**3d. Lock the agent out of your secrets files**

```bash
opscontext secrets-lock            # check only: one PASS / FAIL line per item, writes nothing
opscontext secrets-lock --apply    # in your own terminal, never from inside a chat
```

Outcome: Claude Code's own file tools (Read, Edit, Write) refuse the agent your credentials file, `.env` files, `secrets/` folders and `.p12` certificates, in every repo on the machine, and the agent cannot loosen its own settings. A secret you paste into one of those files while a chat is open no longer lands in the chat log. Commands the agent runs in Bash are not covered until Claude Code's sandbox is on: tested on fake files, a `cat` of a file under `secrets/` still printed it. The check reports the sandbox as "part C". `opscontext servers` and the project score say whether the lock is in place; the check also tells you whether the sandbox is on and whether your Claude Code builds are new enough.

### 4. Pin your config (recommended)

If you have a `contextengine.json` with custom sources, add this to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
export CONTEXTENGINE_CONFIG="$HOME/path/to/contextengine.json"
```

Without this, ContextEngine falls back to auto-discovery (finds `copilot-instructions.md` etc.) but won't load your explicit sources, code dirs, or custom patterns.

That's it. ContextEngine auto-discovers your docs in `~/Projects`.

## 📦 VS Code Extension

ContextEngine has a **free VS Code extension** that provides proactive enforcement — no MCP setup required:

[![Install Extension](https://img.shields.io/badge/Install-VS%20Code%20Marketplace-007ACC?logo=visualstudiocode&style=for-the-badge)](https://marketplace.visualstudio.com/items?itemName=css-llc.contextengine)

- **📊 Value meter** — shows what ContextEngine saved you this session: learnings recalled, learnings saved, estimated time saved. Falls back to git status when no MCP session is active
- **📈 Live stats dashboard** — click ℹ️ to see real-time session metrics (tool calls, recalls, nudges, truncations, time saved)
- **@contextengine chat** — `/status`, `/commit`, `/search`, `/remind`, `/sync` in Copilot Chat
- **Escalating notifications** — warns when files accumulate without commits
- **Terminal watcher** — monitors commands with smart classification (git, deploy, database, python, build, test), credential redaction in logs, and stuck-pattern detection (alerts after 3+ consecutive failures)
- **One-click commit** — commit all changes across all repos

The extension reads live metrics from the MCP server (via `~/.contextengine/session-stats.json`). For search, learnings, sessions, and scoring — it uses the MCP server (`npx @compr/opscontext-mcp`).

## ⭐ PRO Features

OpsContext is **source-available with a free tier**. The free tier covers everything agents need — search, memory, sessions, and compliance enforcement. PRO adds **team and ops intelligence** across multiple projects. Licensed under [BSL-1.1](LICENSE), which is *not* OSI-approved open source (converts to AGPL-3.0 on 2030-02-22). See [docs/about.md](docs/about.md) for the full publisher disclosure and licensing intent.

| Feature | Free | PRO |
|---------|------|-----|
| Hybrid search (keyword + semantic) | ✅ | ✅ |
| Persistent learnings | ✅ | ✅ |
| Session save/load | ✅ | ✅ |
| End-of-session enforcement | ✅ | ✅ |
| Protocol Firewall (agent compliance) | ✅ | ✅ |
| VS Code extension (git monitor, chat) | ✅ | ✅ |
| **Project health score (A+ to F)** | — | ✅ |
| **Compliance audit** | — | ✅ |
| **Port conflict detection** | — | ✅ |
| **Multi-project discovery** | — | ✅ |
| **HTML score reports** | — | ✅ |

### Pricing

| Plan | Price | Machines | SealHour |
|------|-------|----------|----------|
| **Pro** | CHF 2/mo | 2 | until its pilot ends on 1 December 2026; after that, by moving to Team |
| **Team** | CHF 12/mo | 5 | included |
| **Enterprise** | CHF 36/mo | 10 | included |

→ **[Get PRO](https://api.compr.ch/contextengine/pricing)** · Annual plans save 17%

```bash
# Activate after purchase
npx @compr/opscontext-mcp activate
```

### SealHour: an outside time stamp for the audit chain

[SealHour](https://sealhour.com) seals your work every hour, so you can prove later that it existed by then: an outside time stamp from an official European provider, written into Bitcoin. A date, not ownership.

On its own the audit chain is checked from the inside: it shows a record that was changed, not when the chain was written. With SealHour on, the log is tamper-evident, with an outside time stamp.

- **Team and Enterprise.** Sealed every hour by SealHour: an outside time stamp from an official European provider, written into Bitcoin.
- **Off until you turn it on.** `npx @compr/opscontext-mcp anchor enable` shows what would leave your machine and starts nothing without your yes.
- **What leaves.** Once an hour, OpsContext sends SealHour a checkpoint of your audit chain: a few 32-byte fingerprints, the number of records and the time, and, if you choose, one fingerprint for all your repositories with their number; with your licence key. As with any web request, the receiver also sees this machine's address and the time, so it learns the hours you were active. Nothing else leaves: no record, no file, no code, no name. You can stop it any time.
- **What comes back.** A signed receipt for each checkpoint; SealHour keeps the checkpoint too, so a lost or rewritten disk does not lose the proof. At minute 2 of the next hour SealHour seals the checkpoints of the hour together, has that seal stamped by the official provider and writes it into Bitcoin. Your checkpoint is included in the stamped hour, verifiable by anyone: `anchor export-evidence <from> <to>` writes the proofs of a period into a folder anyone can check without OpsContext and without SealHour.
- **Who has it.** SealHour is included in OpsContext Team and Enterprise, and open to every licence while its pilot lasts. The pilot ends on 1 December 2026 at 00:00 UTC: 30 November is its last day. After the pilot, Pro reaches SealHour by moving to Team. Without a licence, a pilot code made on your machine (random: it names no one) takes the place of the licence key while the pilot lasts.
- **Interim mode.** `anchor enable --interim` asks two free public time stamp services directly, in place of the SealHour service: an outside date; not the official European stamp, not Bitcoin, no SealHour receipt. Only one 32-byte fingerprint of each checkpoint leaves, and no licence key.

```bash
npx @compr/opscontext-mcp anchor status    # one line: the last seal, its receipt, what is queued
npx @compr/opscontext-mcp anchor verify    # recompute every checkpoint from this machine's log; check every receipt, proof and stamp
npx @compr/opscontext-mcp anchor disable   # stop: nothing leaves any more, what was made is kept
```

## CLI Usage (no MCP required)

ContextEngine also works as a **standalone CLI tool** — no MCP client setup needed:

```bash
# Search across all your project knowledge
npx @compr/opscontext-mcp search "docker nginx"
npx @compr/opscontext-mcp search "rate limiting" -n 10

# List all indexed sources
npx @compr/opscontext-mcp list-sources

# Discover and analyze all projects
npx @compr/opscontext-mcp list-projects

# AI-readiness score — no argument scores the CURRENT project only
npx @compr/opscontext-mcp score
npx @compr/opscontext-mcp score ContextEngine          # by project name
npx @compr/opscontext-mcp score ~/Projects/PLANK.io    # or by path

# Score every discovered project (writes a SCORE.md into each — opt in explicitly)
npx @compr/opscontext-mcp score --all
npx @compr/opscontext-mcp score --all --no-save        # scan without writing

# Visual HTML report (opens in browser)
npx @compr/opscontext-mcp score --html
npx @compr/opscontext-mcp score ContextEngine --html

# List permanent learnings (optionally by category)
npx @compr/opscontext-mcp list-learnings
npx @compr/opscontext-mcp list-learnings security

# Run compliance audit across all projects
npx @compr/opscontext-mcp audit

# Verify the tamper-evident audit log, archived segments included
npx @compr/opscontext-mcp audit-verify

# SealHour: an outside time stamp for the audit chain (shows what would leave, starts nothing without a yes)
npx @compr/opscontext-mcp anchor enable

# Multi-agent token, cost and capacity report from Claude Code's own transcripts
npx @compr/opscontext-mcp cost

# Stream drift / loop / stuck-tool alerts from the audit log
npx @compr/opscontext-mcp watch

# Bulk-import learnings from a Markdown or JSON file
npx @compr/opscontext-mcp import-learnings rules.md -c deployment

# Scaffold config for a new project
npx @compr/opscontext-mcp init

# Show all commands
npx @compr/opscontext-mcp help
```

CLI mode uses keyword search (BM25) which is instant — no model loading required.

## Tools (16)

| Tool | Description | Tier |
|------|-------------|------|
| `search_context` | Hybrid keyword+semantic search with mode selector | Free |
| `list_sources` | Show all indexed sources with chunk counts | Free |
| `reindex` | Force full re-index of all sources | Free |
| `save_session` | Save key-value entry to a named session | Free |
| `load_session` | Load all entries from a named session | Free |
| `list_sessions` | List all saved sessions | Free |
| `end_session` | Pre-flight checklist — uncommitted changes + doc freshness | Free |
| `save_learning` | Save a permanent operational rule — auto-surfaces in search | Free |
| `list_learnings` | List all permanent learnings, optionally by category | Free |
| `delete_learning` | Remove a learning by ID | Free |
| `activate` | Activate a PRO license on this machine | Free |
| `activation_status` | Check current license status | Free |
| `list_projects` | Discover and analyze all projects (tech stack, git, docker) | PRO |
| `check_ports` | Scan all projects for port conflicts | PRO |
| `run_audit` | Compliance agent — git, hooks, .env, Docker, PM2, versions | PRO |
| `score_project` | AI-readiness scoring 0-100% with letter grades (A+ to F) | PRO |

Retired in 2.17.0, unused: `read_source`, `delete_session`, `audit_verify`, `drift_status`, `agent_cost`
and `import_learnings`. The command line keeps what they did: `audit-verify` (evidence aligned with
[SOC 2 CC7.2](docs/compliance/cc7.2.md) and [ISO 27001 A.12.4.1](docs/compliance/a.12.4.1.md), not a
certification), `watch`, `cost` and `import-learnings`.

All tools are wrapped by the **Protocol Firewall** — a built-in enforcement layer that ensures agents save learnings, persist sessions, and commit code. No action needed from users; it's automatic.

## Configuration

ContextEngine works **zero-config** — it auto-discovers documentation files in `~/Projects`.

For full control, create a `contextengine.json`:

```json
{
  "sources": [
    { "name": "Team Runbook", "path": "./docs/RUNBOOK.md" },
    { "name": "Architecture", "path": "./docs/ARCHITECTURE.md" }
  ],
  "workspaces": ["~/Projects"],
  "patterns": [
    ".github/copilot-instructions.md",
    "CLAUDE.md",
    ".cursorrules",
    "AGENTS.md"
  ],
  "codeDirs": ["src"]
}
```

The `adapters` key was retired in 2.17.0 with the plug-in adapters: a config that still lists some gets one
line on stderr saying they are ignored, and no adapter code is loaded.

### Auto-discovered patterns

| Pattern | Description |
|---------|-------------|
| `.github/copilot-instructions.md` | GitHub Copilot project instructions |
| `.github/instructions/copilot-instructions.md` | VS Code instructions folder format |
| `.github/SKILLS.md` | Team skills inventory |
| `CLAUDE.md` | Claude Code project instructions |
| `.cursorrules` | Cursor AI rules |
| `.cursor/rules` | Cursor AI rules (folder format) |
| `AGENTS.md` | Multi-agent instructions |
| `CONTEXT_MAP.md` | File-to-concern mapping for agents |

### Config resolution order

Which **config file** is read (both the search corpus and the project fleet):

| Priority | Source |
|----------|--------|
| 1 | `CONTEXTENGINE_CONFIG` env var |
| 2 | `./contextengine.json` |
| 3 | `~/.contextengine.json` |

Which **project fleet** is scanned — this is what `score --all`, `audit`, `list_projects`
and `check_ports` operate on:

| Priority | Source |
|----------|--------|
| 1 | `CONTEXTENGINE_WORKSPACES` env var (colon-separated) |
| 2 | `workspaces` in the config file |
| 3 | `~/Projects` auto-discover |

**The env var wins.** It is set per-invocation, so it is the most specific statement of
intent — and it is what the MCP config blocks in this README set. Use it to scope a run:

```bash
CONTEXTENGINE_WORKSPACES=/tmp/sandbox npx @compr/opscontext-mcp score --all
```

> Note: the **search corpus** (`search`, `reindex`, `list-sources`) still prefers the config
> file's `workspaces` over the env var. If you rely on the env var to scope indexing, set
> `CONTEXTENGINE_CONFIG` to a config without `workspaces`, or unset `workspaces` there.

## How It Works

```
Your Project Files           ContextEngine              AI Agent
+-----------------+    +-------------------+    +---------------+
| copilot-        |    | 1. Parse & chunk  |    | GitHub        |
|  instructions   |--->| 2. Embed vectors  |<-->|  Copilot      |
| CLAUDE.md       |    | 3. Hybrid search  |    | Claude        |
| source code     |    | 4. Return top-k   |    | Cursor        |
| git/docker/pm2  |    | 5. Persist state  |    | Windsurf      |
+-----------------+    +-------------------+    +---------------+
                            stdio (MCP)
```

1. **Parse** — chunks markdown + extracts functions from source code
2. **Embed** — sentence embeddings run locally on CPU (no API keys)
3. **Search** — hybrid keyword + semantic scoring
4. **Collect** — operational data from git, package.json, Docker, PM2, nginx
5. **Audit** — compliance checks, port conflicts, AI-readiness scoring

## Scoring

The `score` command evaluates project AI-readiness across **documentation, infrastructure, code quality, and security** — producing a letter grade from A+ to F.

**Grade scale:** A+ (90%+) · A (80%+) · B (70%+) · C (60%+) · D (50%+) · F (<50%)

### What gets scored, and what gets written

`score` writes a `SCORE.md` into each project it scores. Because that is a write into your
repositories, the scope is never inferred:

| Command | Scores | Writes `SCORE.md` to |
|---|---|---|
| `score` | the project you are standing in (walks up to the repo root) | that one project |
| `score <name>` / `score <path>` | that one project | that one project |
| `score --all` | every discovered project | **every** discovered project |
| any of the above `--no-save` | as above | nothing |

A project argument may be a **name** (`PLANK.io`) or a **path** (`~/Projects/PLANK.io`,
`../PLANK.io`, or an absolute path). A path also works for projects outside your configured
workspaces.

### Project Naming & Structure Tips

The scorer discovers projects from your configured `workspaces` directories (default: `~/Projects`).
Each subdirectory is treated as a separate project. For best results:

- **Use descriptive folder names** — the folder name becomes the project name in reports
- **Keep one project per directory** — monorepos should have a root `copilot-instructions.md`
- **Real files over symlinks** — each project should have its own configs with project-specific content
- **Install your tools** — a linting config without the linter installed doesn't count as linting

## Architecture

TypeScript monorepo — MCP server + CLI + search engine + operational collectors.

See the [npm package](https://www.npmjs.com/package/@compr/opscontext-mcp) for installation and usage.

## Development

```bash
npm install @compr/opscontext-mcp
npx @compr/opscontext-mcp help
```

## Requirements

- Node.js 18+
- No API keys needed — embeddings run locally

## Contributing

Feedback, feature requests, and bug reports welcome — email [yannick@compr.ch](mailto:yannick@compr.ch).

If you're using ContextEngine, we'd love to hear about it.

## Privacy & Data Security

**ContextEngine runs 100% on your machine. Your code, your data, your rules.**

Everything happens locally: search, scoring, learnings, sessions, embeddings. No record, no file and no code is ever sent to an external server. Two things can leave, both listed below: the licence check (PRO only), and, only if you turn it on, SealHour's hourly checkpoint (fingerprints, numbers and a time).

### What stays on your machine (always)

| Data | Storage | Leaves your machine? |
|---|---|---|
| Project files & source code | Read locally, never stored externally | ❌ Never |
| Learnings (operational rules) | `~/.contextengine/learnings.json` | ❌ Never |
| Sessions (decisions, progress) | `~/.contextengine/sessions/` | ❌ Never |
| Session stats (value meter) | `~/.contextengine/session-stats.json` | ❌ Never |
| Search index & embeddings | In-memory + `~/.contextengine/embeddings.bin` (vectors) and `~/.contextengine/index/` (shared index) | ❌ Never |
| Git history & branches | Local `git` commands | ❌ Never |
| Dependencies & package.json | Read locally | ❌ Never |
| .env variable names | Read locally (values are never read) | ❌ Never |

### What the activation server receives (PRO only)

| Data | When | Purpose |
|---|---|---|
| License key (`CE-XXXX-...`) | Activation + daily heartbeat | Validate subscription |
| Machine ID (SHA-256 hash) | Activation + daily heartbeat | Enforce machine limit |
| Email | Activation only | Tie the licence to an account |
| Package version | Activation only | Recorded with your activation, so support knows which version a machine runs |
| Platform/arch (e.g., `darwin/arm64`) | Activation only | Compatibility check |
| Licence bundle version | Daily heartbeat | Compatibility marker carried in the signed licence |

That is the complete list. The activation request sends exactly six fields and the heartbeat exactly three — enforced by a lock comment in `src/activation.ts` that forbids adding a seventh field reflecting usage.

**The server never receives:** project names, file contents, learnings, sessions, git history, dependencies, code, .env variables, or anything about your actual work.

**Until you turn SealHour on, these are the only two network calls the tool makes.** `activate` and `heartbeat`, both in `src/activation.ts`.

### What SealHour receives (only if you turn it on)

Off by default. `npx @compr/opscontext-mcp anchor enable` shows this list on your screen and starts nothing without your yes; `anchor disable` stops it.

| Data | When | Who receives it |
|---|---|---|
| A checkpoint of your audit chain: a few 32-byte fingerprints, the number of records and the time | Once an hour, while OpsContext runs and only if the chain grew | SealHour (`api.sealhour.com`) |
| One fingerprint for all your workspace repositories, and their number | With the checkpoint, only if you said yes to the code question | SealHour |
| Your licence key, or without a licence a pilot code made on your machine (random: it names no one) | With the checkpoint | SealHour, which asks the OpsContext licence server whether the key may seal |
| This machine's address and the time | As with any web request | SealHour |

Once an hour, OpsContext sends SealHour a checkpoint of your audit chain: a few 32-byte fingerprints, the number of records and the time, and, if you choose, one fingerprint for all your repositories with their number; with your licence key. As with any web request, the receiver also sees this machine's address and the time, so it learns the hours you were active. Nothing else leaves: no record, no file, no code, no name. You can stop it any time.

During the pilot, everything SealHour receives is kept and nothing is deleted. How long it is kept afterwards will be written on [SealHour's privacy page](https://sealhour.com/privacy.html) before the first paid use.

**In interim mode** (`anchor enable --interim`) the checkpoint stays on your machine: one 32-byte fingerprint of it goes to each of two free public time stamp services, named on the enable screen, with this machine's address and the time. No licence key.

SealHour's calls are in `src/anchor-service.ts`, the interim mode's in `src/anchor-tsa.ts`. Nothing else in the codebase opens a connection to another machine: verify it yourself with `grep -rlE 'fetch\(|from "https?"' src/`, which lists those two files, `src/activation.ts`, and `src/http-server.ts` (the local event port, bound to 127.0.0.1).

### What's obfuscated, and what isn't

One file in the published package is deliberately unreadable: `dist/rubric.js`, which holds the scoring thresholds (what earns which points). Those values are commercial IP under [BSL-1.1](LICENSE), and knowing them exactly makes an AI-readiness score easy to game by padding files to hit a number rather than doing the work.

**What that hides: values. What it does not hide: behaviour.** No code path, network call, file access, or data flow is concealed anywhere in this package. The scoring logic itself, every collector, the search ranker, and both network calls above ship as readable JavaScript — and the full source is public at [FASTPROD/ContextEngine](https://github.com/FASTPROD/opscontext-mcp). If a privacy claim on this page were false, the code that broke it would be right there to find.

### Why this matters

Most AI coding tools (Copilot, Cursor, Codeium) send your code to external servers for processing. ContextEngine takes the opposite approach: **embeddings run locally on CPU**, search runs locally, and all persistent state stays in `~/.contextengine/` on your disk. Unless you turn SealHour on, the only network call is a lightweight license check for PRO users.

## License

BSL-1.1 (Business Source License) — see [LICENSE](LICENSE).

You may use ContextEngine for any purpose, including production, **except** offering it as a hosted/managed service competing with ContextEngine PRO/Team/Enterprise.

Converts to AGPL-3.0 on February 22, 2030.

For commercial licensing: [yannick@compr.ch](mailto:yannick@compr.ch)

---

## Publisher

**OpsContext is built by PROD LLC**, an operating brand of **CSS LLC** (Cross Stream Solutions Sàrl), a Swiss company incorporated in 2005. The engineering team works under the FASTPROD name, which is also the GitHub organisation hosting this repository.

The VS Code Marketplace lists the extension under the legal-parent publisher ID `css-llc`; the npm package is published under the `@compr` scope. Both belong to the same entity.

PROD LLC also operates these products. The full, current list is on **[compr.fr](https://compr.fr)**.

| Product | What it does | Site |
|---|---|---|
| **CROWLR** | Recruitment software: applicant tracking for companies, a job app for candidates, live event sensing | [admin.crowlr.com](https://admin.crowlr.com) · [app.crowlr.com](https://app.crowlr.com) · [crowlr.io](https://www.crowlr.io) |
| **KONIVE** | AI career agent: salary negotiation and job matching | [konive.com](https://konive.com) |
| **INVOC** | Grocery scanner app for shoppers, brand monitoring for food companies | [invoc.io](https://invoc.io) |
| **INVOC.me** | Demand forecasting shared by operations, sales and finance | [invoc.me](https://invoc.me) |
| **PLANK** | Hyperlocal social app for iOS and Android | [plank.io](https://plank.io) |
| **compR** | Company site, and candidate credibility scoring | [compr.fr](https://compr.fr) · [compr.app](https://compr.app) |

Contact: [yannick@compr.ch](mailto:yannick@compr.ch). Full corporate disclosure at [docs/about.md](https://github.com/FASTPROD/opscontext-mcp/blob/main/docs/about.md).
