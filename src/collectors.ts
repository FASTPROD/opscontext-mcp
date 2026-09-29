import { execSync } from "child_process";
import { readFileSync, existsSync, readdirSync, statSync, openSync, fstatSync, readSync, closeSync } from "fs";
import { resolve, join, basename, dirname } from "path";
import { homedir } from "os";
import type { Chunk } from "./ingest.js";

/**
 * Operational data collectors — the unique moat of ContextEngine.
 *
 * Each collector gathers data from a specific operational source
 * (git, package managers, environment, shell history, running services,
 * server configs, scheduled tasks) and returns Chunk[] in the same
 * format as the Markdown parser so they integrate seamlessly into
 * keyword + semantic search.
 *
 * Design principles:
 * - All collectors are **read-only** and **safe** — no writes, no side effects
 * - A collector never crashes the server: a source it cannot run or read yields no chunks AND a
 *   call to `onFail(collector, reason)`, so the caller can count "N collector(s) failed (pm2: not
 *   found)". [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] (src/agents.ts), widened here on 2026-09-29:
 *   exec() returned "" on every failure, so collectPM2() gave the same [] with pm2 absent, failing
 *   or empty, and a reader of the sources list was told "no PM2 processes" about a box with no pm2
 *   (E2E_REVIEW_2026-09 C6-4). "Absent" stays silent (no .git, no package.json, no crontab for the
 *   user); "could not" is reported.
 * - Sensitive values (.env passwords, tokens) are **redacted**
 * - Each collector operates on a project directory path
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** What a collector reports when it could not run or read its source. */
export type CollectorFailure = (collector: string, reason: string) => void;

type Run = { ok: true; out: string } | { ok: false; error: string };

/** Run a shell command: its trimmed stdout, or the first line of what it said on stderr. */
function run(cmd: string, cwd?: string): Run {
  try {
    const out = execSync(cmd, {
      cwd,
      encoding: "utf-8",
      timeout: 10_000,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    return { ok: true, out };
  } catch (err) {
    const e = err as { stderr?: string | Buffer; message?: string };
    const stderr = e.stderr ? String(e.stderr).trim().split("\n")[0] : "";
    return { ok: false, error: stderr || e.message || "failed" };
  }
}

/** Run a shell command, return stdout or "" on failure: for decorations only (a branch name, a
 *  diff stat). A source that stands or falls on the result uses run(). */
function exec(cmd: string, cwd?: string): string {
  const r = run(cmd, cwd);
  return r.ok ? r.out : "";
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The last `count` lines of a file, read without a shell, from at most its last 256 KB. */
export function readLastLines(path: string, count: number): string {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    const len = Math.min(size, 256 * 1024);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    const lines = buf.toString("utf-8").split("\n");
    if (len < size) lines.shift(); // the first line was cut by the window
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    return lines.slice(-count).join("\n");
  } finally {
    closeSync(fd);
  }
}

/** Check if a command exists (cmd is a constant at every call site, CLAUDE.md rule 4) */
function commandExists(cmd: string): boolean {
  return run(`command -v ${cmd}`).ok;
}

// [LOCKED] [ENV-MASK-IS-LINE-BOUND] - 2026-09-25
// [NEVER] let this pattern cross a newline, or look for the secret word anywhere but in the name
//         (the part before the first "=").
// WHY: the old pattern `^(.*(?:...KEY|TOKEN...)[^=]*=\s*).+$` let `[^=]*` and `\s*` run over line
//      ends. A value that itself contained "key", "token", "auth" or "secret" (case-insensitive)
//      matched there, the match ran on to the next line's "=", and that next line was masked
//      while the real value stayed in clear. Two FLASK_SECRET_KEY values sat unmasked in the shared
//      index this way; `SMTP_PASS` was never masked at all (E2E_REVIEW_2026-09 A6-3). An agent's
//      screen hid the bug: the output guard redacted the value on display, not the tool.
// FIX: the name is `[^=\r\n]*` on both sides of the secret word, spaces after "=" are `[ \t]*`, and
//      PASS joins the word list (it also covers PASSWORD). Over-masking a config value in search
//      costs nothing; under-masking hands a password to every agent.
export function redactSensitive(content: string): string {
  const sensitivePatterns =
    /^([^=\r\n]*(?:PASS|SECRET|KEY|TOKEN|CREDENTIAL|AUTH|PRIVATE|ENCRYPT)[^=\r\n]*=[ \t]*)\S[^\r\n]*$/gim;
  return content.replace(sensitivePatterns, "$1[REDACTED]");
}

// ---------------------------------------------------------------------------
// 1. Git Log Collector
// ---------------------------------------------------------------------------

/**
 * Collect recent git history for a project directory.
 * Produces chunks with commit messages, authors, dates — gives AI
 * context about recent changes and development velocity.
 */
export function collectGitLog(projectDir: string, sourceName: string, onFail?: CollectorFailure): Chunk[] {
  if (!existsSync(join(projectDir, ".git"))) return [];

  // Recent 50 commits, one-line format with hash, date, author, message
  const log = run(
    `git --no-pager log --oneline --format="%h|%ai|%an|%s" -50`,
    projectDir
  );
  if (!log.ok) {
    // a repository with no commit yet is a real empty; anything else (a .git git cannot read) is a failure
    if (!/does not have any commits/i.test(log.error)) onFail?.("git", `${sourceName}: ${log.error}`);
    return [];
  }

  const lines = log.out.split("\n").filter(Boolean);
  if (lines.length === 0) return [];

  // Current branch + remote info
  const branch = exec("git branch --show-current", projectDir) || "unknown";
  const remotes = exec("git remote -v", projectDir);
  const status = exec("git --no-pager diff --stat HEAD~1..HEAD", projectDir);

  const chunks: Chunk[] = [];

  // Summary chunk
  chunks.push({
    source: `${sourceName} — git`,
    section: "## Git Overview",
    content: [
      `Branch: ${branch}`,
      `Commits shown: ${lines.length}`,
      remotes ? `\nRemotes:\n${remotes}` : "",
      status ? `\nLast commit changes:\n${status}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    lineStart: 1,
    lineEnd: 1,
  });

  // Batch commits into groups of 10 for searchable chunks
  for (let i = 0; i < lines.length; i += 10) {
    const batch = lines.slice(i, i + 10);
    const formatted = batch
      .map((line) => {
        const [hash, date, author, ...msgParts] = line.split("|");
        return `${hash} ${date?.split(" ")[0]} ${author}: ${msgParts.join("|")}`;
      })
      .join("\n");

    chunks.push({
      source: `${sourceName} — git`,
      section: `## Git Log (${i + 1}-${Math.min(i + 10, lines.length)})`,
      content: formatted,
      lineStart: i + 1,
      lineEnd: Math.min(i + 10, lines.length),
    });
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// 2. Package.json Collector (Node.js projects)
// ---------------------------------------------------------------------------

/**
 * Collect dependency and script info from package.json.
 * Critical for version agent + understanding project capabilities.
 */
export function collectPackageJson(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const pkgPath = join(projectDir, "package.json");
  if (!existsSync(pkgPath)) return [];

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const chunks: Chunk[] = [];

    // Project identity
    chunks.push({
      source: `${sourceName} — package.json`,
      section: "## Package Identity",
      content: [
        `Name: ${pkg.name || "unnamed"}`,
        `Version: ${pkg.version || "0.0.0"}`,
        pkg.description ? `Description: ${pkg.description}` : "",
        pkg.license ? `License: ${pkg.license}` : "",
        pkg.engines
          ? `Engines: ${JSON.stringify(pkg.engines)}`
          : "",
        pkg.type ? `Module type: ${pkg.type}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      lineStart: 1,
      lineEnd: 1,
    });

    // Scripts
    if (pkg.scripts && Object.keys(pkg.scripts).length > 0) {
      chunks.push({
        source: `${sourceName} — package.json`,
        section: "## npm Scripts",
        content: Object.entries(pkg.scripts)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }

    // Dependencies (names + versions, no code)
    const deps = pkg.dependencies || {};
    const devDeps = pkg.devDependencies || {};
    if (Object.keys(deps).length > 0) {
      chunks.push({
        source: `${sourceName} — package.json`,
        section: "## Dependencies",
        content: Object.entries(deps)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }
    if (Object.keys(devDeps).length > 0) {
      chunks.push({
        source: `${sourceName} — package.json`,
        section: "## Dev Dependencies",
        content: Object.entries(devDeps)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }

    return chunks;
  } catch (err) {
    onFail?.("package.json", `${sourceName}: ${errText(err)}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 3. Composer.json Collector (PHP projects)
// ---------------------------------------------------------------------------

/**
 * Collect dependency info from composer.json (Laravel, Symfony, etc.).
 */
export function collectComposerJson(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const composerPath = join(projectDir, "composer.json");
  if (!existsSync(composerPath)) return [];

  try {
    const composer = JSON.parse(readFileSync(composerPath, "utf-8"));
    const chunks: Chunk[] = [];

    chunks.push({
      source: `${sourceName} — composer.json`,
      section: "## Composer Package",
      content: [
        `Name: ${composer.name || "unnamed"}`,
        composer.description ? `Description: ${composer.description}` : "",
        composer.type ? `Type: ${composer.type}` : "",
        composer.license ? `License: ${composer.license}` : "",
        composer.require?.php ? `PHP: ${composer.require.php}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      lineStart: 1,
      lineEnd: 1,
    });

    const deps = composer.require || {};
    if (Object.keys(deps).length > 0) {
      chunks.push({
        source: `${sourceName} — composer.json`,
        section: "## PHP Dependencies",
        content: Object.entries(deps)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }

    const devDeps = composer["require-dev"] || {};
    if (Object.keys(devDeps).length > 0) {
      chunks.push({
        source: `${sourceName} — composer.json`,
        section: "## PHP Dev Dependencies",
        content: Object.entries(devDeps)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }

    // Scripts
    if (composer.scripts && Object.keys(composer.scripts).length > 0) {
      chunks.push({
        source: `${sourceName} — composer.json`,
        section: "## Composer Scripts",
        content: Object.entries(composer.scripts)
          .map(([k, v]) => {
            const val = Array.isArray(v) ? v.join(", ") : String(v);
            return `${k}: ${val}`;
          })
          .join("\n"),
        lineStart: 1,
        lineEnd: 1,
      });
    }

    return chunks;
  } catch (err) {
    onFail?.("composer.json", `${sourceName}: ${errText(err)}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 4. .env Collector (sanitized — passwords redacted)
// ---------------------------------------------------------------------------

/**
 * Collect environment configuration. Passwords/secrets are REDACTED.
 * Gives AI context about database hosts, mail config, app URLs, etc.
 */
export function collectEnvFile(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const envPath = join(projectDir, ".env");
  if (!existsSync(envPath)) return [];

  try {
    const raw = readFileSync(envPath, "utf-8");
    const redacted = redactSensitive(raw);

    // Remove empty lines and comments for cleaner chunks
    const meaningful = redacted
      .split("\n")
      .filter((line) => line.trim() && !line.trim().startsWith("#"))
      .join("\n");

    if (!meaningful) return [];

    return [
      {
        source: `${sourceName} — .env`,
        section: "## Environment Configuration",
        content: meaningful,
        lineStart: 1,
        lineEnd: meaningful.split("\n").length,
      },
    ];
  } catch (err) {
    onFail?.(".env", `${sourceName}: ${errText(err)}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 5. Shell History Collector (recent commands)
// ---------------------------------------------------------------------------

/**
 * Collect recent shell history entries.
 * Useful for understanding what the developer has been doing recently.
 * Passwords in history are redacted.
 */
export function collectShellHistory(sourceName: string, onFail?: CollectorFailure): Chunk[] {
  const histFile = resolve(homedir(), ".zsh_history");
  if (!existsSync(histFile)) return [];

  try {
    // Read last 200 lines (most recent commands). Read directly: the path comes from HOME, and a
    // home folder with a space or a `$(` broke, or ran, the old `tail -200 ${histFile}` (E2E A1-1).
    const raw = readLastLines(histFile, 200);
    if (!raw) return [];

    // Parse zsh extended history format: : timestamp:0;command
    const commands = raw
      .split("\n")
      .map((line) => {
        const match = line.match(/^:\s*(\d+):\d+;(.+)/);
        if (match) return match[2].trim();
        // Plain format
        return line.trim();
      })
      .filter(Boolean)
      // Remove duplicates while preserving order
      .filter((cmd, i, arr) => arr.indexOf(cmd) === i);

    if (commands.length === 0) return [];

    const redacted = redactSensitive(commands.join("\n"));

    return [
      {
        source: `${sourceName} — shell history`,
        section: "## Recent Shell Commands",
        content: redacted,
        lineStart: 1,
        lineEnd: commands.length,
      },
    ];
  } catch (err) {
    onFail?.("shell history", errText(err));
    return [];
  }
}

// ---------------------------------------------------------------------------
// 6. Docker Collector (running containers + compose config)
// ---------------------------------------------------------------------------

/**
 * Collect Docker container info — what's running, ports, images.
 */
export function collectDocker(sourceName: string, onFail?: CollectorFailure): Chunk[] {
  if (!commandExists("docker")) {
    onFail?.("docker", "not found");
    return [];
  }

  const chunks: Chunk[] = [];

  // Running containers
  const ps = run(
    'docker ps --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"'
  );
  if (!ps.ok) {
    onFail?.("docker", ps.error);
    return [];
  }
  if (ps.out) {
    const formatted = ps.out
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, image, status, ports] = line.split("|");
        return `${name}: ${image} (${status}) ${ports || ""}`.trim();
      })
      .join("\n");

    chunks.push({
      source: `${sourceName} — docker`,
      section: "## Running Containers",
      content: formatted,
      lineStart: 1,
      lineEnd: 1,
    });
  }

  // Docker images (a decoration next to the container list, so exec() is fine here)
  const images = exec(
    'docker images --format "{{.Repository}}:{{.Tag}} ({{.Size}})" | head -20'
  );
  if (images) {
    chunks.push({
      source: `${sourceName} — docker`,
      section: "## Docker Images",
      content: images,
      lineStart: 1,
      lineEnd: 1,
    });
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// 7. PM2 Collector (running processes)
// ---------------------------------------------------------------------------

/**
 * Collect PM2 process list — what apps are running, ports, status.
 */
export function collectPM2(sourceName: string, onFail?: CollectorFailure): Chunk[] {
  if (!commandExists("pm2")) {
    onFail?.("pm2", "not found");
    return [];
  }

  // Use jlist for structured data
  const raw = run("pm2 jlist");
  if (!raw.ok) {
    onFail?.("pm2", raw.error);
    return [];
  }
  if (!raw.out) return [];

  let processes: unknown;
  try {
    processes = JSON.parse(raw.out);
  } catch {
    onFail?.("pm2", "pm2 jlist printed something that is not JSON");
    return [];
  }
  if (!Array.isArray(processes) || processes.length === 0) return [];

  {
    const formatted = processes
      .map((p: any) => {
        const env = p.pm2_env || {};
        return [
          `${p.name}: ${env.status || "unknown"}`,
          `  pid: ${p.pid || "N/A"}`,
          `  port: ${env.PORT || env.port || "N/A"}`,
          `  cwd: ${env.pm_cwd || "N/A"}`,
          `  uptime: ${env.pm_uptime ? new Date(env.pm_uptime).toISOString() : "N/A"}`,
          `  restarts: ${env.restart_time || 0}`,
        ].join("\n");
      })
      .join("\n\n");

    return [
      {
        source: `${sourceName} — pm2`,
        section: "## PM2 Processes",
        content: formatted,
        lineStart: 1,
        lineEnd: processes.length,
      },
    ];
  }
}

// ---------------------------------------------------------------------------
// 8. Nginx Collector (site configurations)
// ---------------------------------------------------------------------------

/**
 * Collect Nginx site configurations — domains, roots, proxy settings.
 * Reads from common config locations.
 */
export function collectNginx(sourceName: string, onFail?: CollectorFailure): Chunk[] {
  const configDirs = [
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/usr/local/etc/nginx/servers", // macOS Homebrew
  ];

  const chunks: Chunk[] = [];

  for (const dir of configDirs) {
    if (!existsSync(dir)) continue;

    try {
      const files = readdirSync(dir);
      for (const file of files) {
        if (file.startsWith(".")) continue;
        const filePath = join(dir, file);

        try {
          if (!statSync(filePath).isFile()) continue;
        } catch {
          continue;
        }

        try {
          const content = readFileSync(filePath, "utf-8");

          // Extract key directives for a summary
          const serverNames = [
            ...content.matchAll(/server_name\s+([^;]+);/g),
          ].map((m) => m[1].trim());
          const roots = [...content.matchAll(/root\s+([^;]+);/g)].map((m) =>
            m[1].trim()
          );
          const listens = [...content.matchAll(/listen\s+([^;]+);/g)].map(
            (m) => m[1].trim()
          );
          const proxyPasses = [
            ...content.matchAll(/proxy_pass\s+([^;]+);/g),
          ].map((m) => m[1].trim());

          const summary = [
            serverNames.length
              ? `Domains: ${serverNames.join(", ")}`
              : "",
            listens.length ? `Listen: ${listens.join(", ")}` : "",
            roots.length ? `Root: ${roots.join(", ")}` : "",
            proxyPasses.length
              ? `Proxy: ${proxyPasses.join(", ")}`
              : "",
          ]
            .filter(Boolean)
            .join("\n");

          if (summary) {
            chunks.push({
              source: `${sourceName} — nginx`,
              section: `## Nginx: ${file}`,
              content: summary,
              lineStart: 1,
              lineEnd: 1,
            });
          }
        } catch (err) {
          onFail?.("nginx", `${filePath}: ${errText(err)}`);
        }
      }
    } catch (err) {
      onFail?.("nginx", `${dir}: ${errText(err)}`);
    }
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// 9. Crontab Collector
// ---------------------------------------------------------------------------

/**
 * Collect crontab entries — scheduled tasks and maintenance jobs.
 */
export function collectCrontab(sourceName: string, onFail?: CollectorFailure): Chunk[] {
  if (!commandExists("crontab")) {
    onFail?.("crontab", "not found");
    return [];
  }
  const cron = run("crontab -l");
  if (!cron.ok) {
    // "no crontab for <user>" is a real empty; a refusal or any other failure is reported
    if (!/no crontab for/i.test(cron.error)) onFail?.("crontab", cron.error);
    return [];
  }
  if (!cron.out) return [];

  // Filter out comments and empty lines for summary
  const entries = cron.out
    .split("\n")
    .filter((line) => line.trim() && !line.trim().startsWith("#"));

  if (entries.length === 0) return [];

  return [
    {
      source: `${sourceName} — crontab`,
      section: "## Scheduled Tasks (crontab)",
      content: entries.join("\n"),
      lineStart: 1,
      lineEnd: entries.length,
    },
  ];
}

// ---------------------------------------------------------------------------
// 10. Ecosystem.config.js Collector (PM2 config files)
// ---------------------------------------------------------------------------

/**
 * Collect PM2 ecosystem config from project directory.
 */
export function collectEcosystemConfig(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const configNames = ["ecosystem.config.js", "ecosystem.config.cjs"];

  for (const name of configNames) {
    const configPath = join(projectDir, name);
    if (!existsSync(configPath)) continue;

    try {
      const content = readFileSync(configPath, "utf-8");
      return [
        {
          source: `${sourceName} — ecosystem.config`,
          section: "## PM2 Ecosystem Config",
          content,
          lineStart: 1,
          lineEnd: content.split("\n").length,
        },
      ];
    } catch (err) {
      onFail?.("ecosystem.config", `${sourceName}: ${errText(err)}`);
      continue;
    }
  }

  return [];
}

// ---------------------------------------------------------------------------
// 11. Docker Compose Collector (project-level)
// ---------------------------------------------------------------------------

/**
 * Collect docker-compose.yml for a project — services, ports, volumes.
 */
export function collectDockerCompose(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const composeNames = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.prod.yml",
    "compose.yml",
    "compose.yaml",
  ];

  const chunks: Chunk[] = [];

  for (const name of composeNames) {
    const composePath = join(projectDir, name);
    if (!existsSync(composePath)) continue;

    try {
      const content = readFileSync(composePath, "utf-8");
      const redacted = redactSensitive(content);

      chunks.push({
        source: `${sourceName} — ${name}`,
        section: `## Docker Compose: ${name}`,
        content: redacted,
        lineStart: 1,
        lineEnd: redacted.split("\n").length,
      });
    } catch (err) {
      onFail?.(name, `${sourceName}: ${errText(err)}`);
    }
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// Master collector: gather all operational data for a project
// ---------------------------------------------------------------------------

/**
 * Collect all operational data for a single project directory.
 * Returns chunks from all available collectors.
 */
export function collectProjectOps(
  projectDir: string,
  sourceName: string,
  onFail?: CollectorFailure
): Chunk[] {
  const allChunks: Chunk[] = [];

  allChunks.push(...collectGitLog(projectDir, sourceName, onFail));
  allChunks.push(...collectPackageJson(projectDir, sourceName, onFail));
  allChunks.push(...collectComposerJson(projectDir, sourceName, onFail));
  allChunks.push(...collectEnvFile(projectDir, sourceName, onFail));
  allChunks.push(...collectEcosystemConfig(projectDir, sourceName, onFail));
  allChunks.push(...collectDockerCompose(projectDir, sourceName, onFail));

  return allChunks;
}

/**
 * Collect system-wide operational data (not project-specific).
 * These run once, not per-project.
 */
export function collectSystemOps(onFail?: CollectorFailure): Chunk[] {
  const allChunks: Chunk[] = [];
  const sourceName = "System";

  allChunks.push(...collectShellHistory(sourceName, onFail));
  allChunks.push(...collectDocker(sourceName, onFail));
  allChunks.push(...collectPM2(sourceName, onFail));
  allChunks.push(...collectNginx(sourceName, onFail));
  allChunks.push(...collectCrontab(sourceName, onFail));

  return allChunks;
}
