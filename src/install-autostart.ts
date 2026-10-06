// [LOCKED] [AUTOSTART-INSTALL], 2026-06-23
// [NEVER] bootstrap into a `system/` domain (would need root + run as root).
//    Use `gui/$UID` — per-user agent, started at user login, runs as the user.
// [NEVER] write the plist before checking if a server is already listening on
//    the port. A pre-existing process means we'd race with the launchd-managed
//    one for port 7842.
// [NEVER] ship a plist that calls `npx -y @latest`, every restart would
//    fetch the registry, eating ~3s and breaking offline. Pin a specific
//    node path + a specific dist path.
// WHY: This is the "set it and forget it" entrypoint for non-technical users.
//    If it fails silently or starts duplicating processes, the entire
//    auto-capture story collapses and the user has to type `nohup npx ...`
//    forever — defeating the whole point.
// FIX: To add platform support beyond macOS, branch on process.platform and
//    add equivalent systemd / NSSM logic. Keep `gui/$UID` and KeepAlive
//    discipline in any new platform.

import { existsSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { homedir, platform } from "os";
import { execFileSync } from "child_process";
import { createRequire } from "module";
import { fileURLToPath } from "url";

// [LOCKED] [M2-ESM-FILENAME-FIX], 2026-06-24
// [NEVER] reference bare `__filename` in this file, the package is
//    `"type": "module"` so __filename is `undefined` at runtime and
//    `dirname(__filename || "")` was returning dirname("") = "." which
//    silently broke the dev-tree fallback. Audit FRESH_USER_AUDIT_
//    2026-06-23.md finding M2.
// FIX: Resolve module path via fileURLToPath(import.meta.url). For
//    cross-package resolution (e.g. when running via npx and the
//    @compr/opscontext-mcp tarball is in npx's transient cache), also
//    try createRequire(import.meta.url).resolve("@compr/opscontext-mcp/
//    dist/index.js") which works inside npx.
const __filename_esm = fileURLToPath(import.meta.url);
const __dirname_esm = dirname(__filename_esm);
const requireFromHere = createRequire(import.meta.url);

export const LABEL = "com.opscontext.mcp";
export const PLIST_FILE = join(homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);
const LOG_DIR = join(homedir(), ".contextengine", "logs");
const PORT = 7842;

/** Resolve an absolute node binary path that launchd can find without PATH. */
function detectNodePath(): string {
  // process.execPath is the node that's running THIS script — absolute path.
  // launchd runs without the user's interactive shell, so we MUST pass an
  // absolute path (no PATH lookup of "node" works under launchd).
  return process.execPath;
}

/** Find a stable path to the opscontext entrypoint that survives version
 *  upgrades. Order: (1) globally installed bin → resolve symlink to real path;
 *  (2) ./dist/index.js next to this module (dev tree). Falls through with
 *  null if neither is found. */
function detectOpscontextEntry(): { kind: "global" | "devtree" | "npx"; path: string } | null {
  // (1) Try global install via `npm root -g`
  try {
    const globalRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    const candidate = join(globalRoot, "@compr", "opscontext-mcp", "dist", "index.js");
    if (existsSync(candidate)) return { kind: "global", path: candidate };
  } catch {
    /* no npm root available; fall through */
  }
  // (2) Try dev tree relative to this module's location (dist/install-autostart.js)
  // → __dirname_esm IS dist/, so dist/index.js is a sibling. ESM-safe (uses
  // fileURLToPath(import.meta.url), not the broken `__filename` reference
  // that the M2 audit caught).
  try {
    const candidate = join(__dirname_esm, "index.js");
    if (existsSync(candidate)) return { kind: "devtree", path: candidate };
  } catch {
    /* ignore */
  }
  // (3) NEW: Try resolve via createRequire (works inside npx's transient
  // install — when the user runs `npx -y @compr/opscontext-mcp
  // install-autostart` the package is in npx's cache, not npm's global root,
  // so step (1) misses. createRequire walks Node's resolution algorithm and
  // finds the cache copy. Audit M2 fix.
  try {
    const resolved = requireFromHere.resolve("@compr/opscontext-mcp/dist/index.js");
    if (existsSync(resolved)) return { kind: "npx", path: resolved };
  } catch {
    /* not resolvable — caller will print the install-globally hint */
  }
  return null;
}

// [LOCKED] [AUTOSTART-IS-THE-STANDING-INDEXER] 2026-09-06
// [NEVER] run the agent as ProcessType Background, drop CONTEXTENGINE_SHARED_INDEX from its
//         environment, or give it a corpus the chats do not have.
// WHY: measured 2026-09-05 (SESSION_26): as Background the agent got 2.5 s of CPU in 15 minutes
//      under load, took 4.5 min from exec to main(), served no MCP client (stdin is /dev/null),
//      lost the browser-event port to whichever chat started first, and, with the memory skip and
//      no config, indexed a corpus no chat used. It burned CPU keeping a cache warm that never
//      hit. As the standing indexer it is the oldest server at every login, so it wins the
//      election, every chat opens onto a ready index, and it owns the port from boot.
// FIX: Standard priority; the shared-index flag; CONTEXTENGINE_CONFIG passed through from the
//      installing shell so its corpus id equals the chats'; the memory skip only if the installer
//      was itself run with it (an explicit choice, not a default).
// [LOCKED] [AUTOSTART-ARGV-AND-XML-ESCAPED] - 2026-09-25
// [NEVER] paste a path into a launchctl/lsof/curl command string, or into the plist unescaped.
// WHY: with a home folder named "John Smith", `launchctl bootstrap gui/501 ${PLIST_FILE}` handed
//      launchctl the path in two pieces and failed, after `bootout` had already stopped the running
//      agent; a home named "R&D home" produced a plist launchd refuses ("unknown ampersand-escape
//      sequence"); only the passthrough env values were escaped (E2E_REVIEW_2026-09 A3-2, A3-3).
// FIX: execFileSync with an argument list for every command; xml() on every value in the plist;
//      `plutil -lint` on the written file before anything running is stopped.
function xml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;");
}

export function buildPlist(nodePath: string, entryPath: string, nodeBinDir: string, env: NodeJS.ProcessEnv = process.env): string {
  // OPSCONTEXT_DAEMON tells the server it has no MCP client on stdin and must stay alive on its
  // own: as a reader it holds no file watchers, and every poller is unref'd, so without this the
  // event loop drained and launchd restarted it every 10 s (found 2026-09-06, first real run).
  const passthrough: Array<[string, string]> = [["CONTEXTENGINE_SHARED_INDEX", "1"], ["OPSCONTEXT_DAEMON", "1"]];
  if (env.CONTEXTENGINE_CONFIG) passthrough.push(["CONTEXTENGINE_CONFIG", env.CONTEXTENGINE_CONFIG]);
  if (env.CONTEXTENGINE_WORKSPACES) passthrough.push(["CONTEXTENGINE_WORKSPACES", env.CONTEXTENGINE_WORKSPACES]);
  if (env.OPSCONTEXT_SKIP_CLAUDE_MEMORY === "1") passthrough.push(["OPSCONTEXT_SKIP_CLAUDE_MEMORY", "1"]);
  // [LOCK] [AUTOSTART-ARGV-AND-XML-ESCAPED]: every value, not only the passthrough ones.
  const extraEnv = passthrough.map(([k, v]) => `        <key>${k}</key>\n        <string>${xml(v)}</string>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${xml(nodePath)}</string>
        <string>${xml(entryPath)}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${xml(nodeBinDir)}:/usr/local/bin:/usr/bin:/bin</string>
        <key>HOME</key>
        <string>${xml(homedir())}</string>
${extraEnv}
    </dict>

    <key>WorkingDirectory</key>
    <string>${xml(homedir())}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>${xml(join(LOG_DIR, "mcp-stdout.log"))}</string>

    <key>StandardErrorPath</key>
    <string>${xml(join(LOG_DIR, "mcp-stderr.log"))}</string>

    <key>ProcessType</key>
    <string>Standard</string>
</dict>
</plist>
`;
}

function isMacOS(): boolean {
  return platform() === "darwin";
}

function userId(): number {
  return process.getuid?.() ?? 501;
}

// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: "lsof found nothing" and "lsof could not run" are different
// answers; the second used to read as "not listening", and the installer then waited 30 s to report a
// server that "didn't bind" without ever having been able to look (2026-09-29, C6-5).
/** true: something listens on PORT; false: nothing does; null: lsof could not tell (missing, or failed). */
function portIsOurs(): boolean | null {
  try {
    execFileSync("lsof", ["-nP", `-iTCP:${PORT}`, "-sTCP:LISTEN"], { stdio: ["ignore", "ignore", "pipe"] });
    return true;
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { status?: number | null; stderr?: string | Buffer };
    if (e.code === "ENOENT") return null; // lsof is not installed
    const said = e.stderr ? String(e.stderr).trim() : "";
    return e.status === 1 && !said ? false : null; // exit 1 with nothing said: no such listener
  }
}

function waitForPort(timeoutSec: number = 30): boolean | null {
  const start = Date.now();
  while (Date.now() - start < timeoutSec * 1000) {
    const up = portIsOurs();
    if (up !== false) return up; // true, or null when lsof cannot tell
    execFileSync("sleep", ["1"]);
  }
  return false;
}

// [LOCKED] [AUTOSTART-WAITS-FOR-LAUNCHD] 2026-10-02
// [NEVER] bootstrap right after bootout, or call the install a success because something listens
//         on the port.
// WHY: 2026-10-02, moving the agent to Node 24 with `install-autostart --force`, the use its own
//      help names: `launchctl bootout` returned while launchd was still removing the old agent, the
//      bootstrap right after it failed ("Bootstrap failed: 5: Input/output error"), and the Mac was
//      left with no agent. A chat server took over the index and the port, so nothing looked wrong,
//      and the old success test, "something listens on 7842", passes with that chat server too: an
//      agent that crashes at start was reported as running.
// FIX: after bootout, wait until launchd no longer knows the label, and start nothing if it still
//      does; success means launchd reports the job running and never exited, and its pid is the
//      one listening on 7842. A chat server hands the port over within seconds once it sees the
//      agent, so a slow handover is a warning; an agent that exited is a failure.
// OPSCONTEXT_AUTOSTART_WAIT_SECONDS shortens the waits, for the tests only.
// launchd sends SIGKILL 20 s after SIGTERM by default (ExitTimeOut), so 30 s covers a slow exit.
const WAIT_SECONDS = Number(process.env.OPSCONTEXT_AUTOSTART_WAIT_SECONDS) || 30;

interface JobState {
  running: boolean;
  pid: number | null;
  /** "(never exited)" for a job that has not stopped since it was loaded. */
  lastExit: string | null;
}

/** What launchd says about the agent: its state, or "gone" once launchd no longer knows the label,
 *  or null when launchctl could not answer at all. [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] */
function jobState(uid: number): JobState | "gone" | null {
  try {
    const out = execFileSync("launchctl", ["print", `gui/${uid}/${LABEL}`], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
    // An answer without a state line is one this code cannot read: say so, never guess.
    if (!/^\s*state = /m.test(out)) return null;
    // The job's own lines come first; nested sections indent theirs further and are not read.
    const pid = /^\s*pid = (\d+)/m.exec(out)?.[1];
    return {
      running: /^\s*state = running\b/m.test(out),
      pid: pid ? Number(pid) : null,
      lastExit: /^\s*last exit code = (.+)$/m.exec(out)?.[1].trim() ?? null,
    };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { status?: number | null };
    if (e.code === "ENOENT") return null; // no launchctl
    return e.status === 113 ? "gone" : null; // 113: "Could not find service"
  }
}

/** The pids listening on PORT: [] for none, null when lsof could not tell. */
function portHolders(): number[] | null {
  try {
    const out = execFileSync("lsof", ["-nP", "-t", `-iTCP:${PORT}`, "-sTCP:LISTEN"], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
    return out.split("\n").map((s) => Number(s.trim())).filter((n) => n > 0);
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { status?: number | null; stderr?: string | Buffer };
    if (e.code === "ENOENT") return null;
    const said = e.stderr ? String(e.stderr).trim() : "";
    return e.status === 1 && !said ? [] : null;
  }
}

/** Polls every quarter second until check() says done, or the time is up (then the last value). */
function pollFor<T>(seconds: number, check: () => { done: boolean; value: T }): T {
  const end = Date.now() + seconds * 1000;
  for (;;) {
    const r = check();
    if (r.done || Date.now() >= end) return r.value;
    execFileSync("sleep", ["0.25"]);
  }
}

/* eslint-disable no-console -- the three commands below print their report on stdout, CLI only.
   The helpers above stay under the rule, in case the MCP server ever imports one: its stdout is
   the protocol (CLAUDE.md rule 5). */
export async function cliInstallAutostart(args: string[]): Promise<void> {
  const help = args.includes("-h") || args.includes("--help");
  if (help) {
    console.log(`Usage: opscontext install-autostart [--force]

Installs OpsContext as a macOS LaunchAgent so the MCP server starts
automatically at every login and restarts if it crashes.

After running this once, you never need to start the server manually again.
Browser extension events + Claude Code hook events + VS Code emitter events
all flow through the auto-started server.

  --force   Re-create the plist even if one already exists (use after a
            node version upgrade or after moving the install location).

To stop / uninstall:        opscontext uninstall-autostart
To check status:            opscontext autostart-status
To view server logs:        tail -f ~/.contextengine/logs/mcp-stderr.log
`);
    return;
  }

  if (!isMacOS()) {
    console.error(`❌ install-autostart currently supports macOS only (this is ${platform()}).`);
    console.error(`   For Linux: write a systemd --user unit. For Windows: NSSM or Task Scheduler.`);
    process.exit(1);
  }

  const force = args.includes("--force") || args.includes("-f");
  if (existsSync(PLIST_FILE) && !force) {
    console.error(`❌ ${PLIST_FILE} already exists.`);
    console.error(`   Pass --force to overwrite, or run: opscontext autostart-status`);
    process.exit(1);
  }

  // Allow operator to pin the entry path explicitly — escape hatch when
  // detection fails (e.g. monorepo / private registry / unconventional layout).
  // Audit M2 follow-up: was originally a CLI flag suggestion.
  const entryFlagIdx = args.findIndex((a) => a === "--entry" || a.startsWith("--entry="));
  let entry: { kind: "global" | "devtree" | "npx" | "manual"; path: string } | null = null;
  if (entryFlagIdx >= 0) {
    const raw = args[entryFlagIdx].includes("=")
      ? args[entryFlagIdx].split("=")[1]
      : args[entryFlagIdx + 1];
    if (!raw) {
      console.error(`❌ --entry requires a path. Usage: --entry=/path/to/dist/index.js`);
      process.exit(1);
    }
    if (!existsSync(raw)) {
      console.error(`❌ --entry path does not exist: ${raw}`);
      process.exit(1);
    }
    entry = { kind: "manual", path: raw };
  }

  const nodePath = detectNodePath();
  if (!entry) entry = detectOpscontextEntry();
  if (!entry) {
    console.error(`❌ Could not locate opscontext entrypoint. Tried 3 paths:`);
    console.error(`     (1) npm global root → @compr/opscontext-mcp/dist/index.js`);
    console.error(`     (2) dev tree sibling (this script's dist/ dir)`);
    console.error(`     (3) Node resolution of "@compr/opscontext-mcp/dist/index.js" via createRequire (npx cache)`);
    console.error(``);
    console.error(`   If you installed with npx, install globally first:`);
    console.error(`     npm install -g @compr/opscontext-mcp`);
    console.error(``);
    console.error(`   Or run from a clone:      cd .../ContextEngine && npm run build`);
    console.error(``);
    console.error(`   Or pin a path explicitly: opscontext install-autostart --entry=/full/path/to/dist/index.js`);
    process.exit(1);
  }

  // Ensure log dir
  mkdirSync(LOG_DIR, { recursive: true });
  mkdirSync(dirname(PLIST_FILE), { recursive: true });

  const nodeBinDir = dirname(nodePath);
  const plist = buildPlist(nodePath, entry.path, nodeBinDir);
  writeFileSync(PLIST_FILE, plist);
  console.log(`✅ Wrote ${PLIST_FILE}`);
  console.log(`   node:  ${nodePath}`);
  console.log(`   entry: ${entry.path}  (${entry.kind})`);

  // Stop any currently-running unmanaged opscontext server on the port —
  // it would race with launchd for port 7842.
  if (portIsOurs() === true) {
    console.log(`   detected existing process on :${PORT} — relying on launchctl bootout to clean it.`);
  }

  // [LOCK] [AUTOSTART-ARGV-AND-XML-ESCAPED]: a file launchd would refuse must never cost the user
  // the agent that is running now, so check it before the bootout.
  try {
    execFileSync("plutil", ["-lint", PLIST_FILE], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    console.error(`❌ The new plist is not valid, nothing was stopped or loaded: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  // Idempotent bootstrap: bootout (ignore failure), wait until launchd has let go, then bootstrap.
  // [LOCK] [AUTOSTART-WAITS-FOR-LAUNCHD]
  const uid = userId();
  try {
    execFileSync("launchctl", ["bootout", `gui/${uid}/${LABEL}`], { stdio: "ignore" });
  } catch {
    /* not loaded — fine */
  }
  const released = pollFor(WAIT_SECONDS, () => {
    const s = jobState(uid);
    return { done: s === "gone" || s === null, value: s };
  });
  if (released !== "gone" && released !== null) {
    console.error(`❌ launchd was still removing the previous agent after ${WAIT_SECONDS} s, so the new one was not started.`);
    console.error(`   The new plist is written. In a few seconds, start it by hand:`);
    console.error(`     launchctl bootstrap gui/${uid} "${PLIST_FILE}"`);
    process.exit(1);
  }
  try {
    execFileSync("launchctl", ["bootstrap", `gui/${uid}`, PLIST_FILE], { stdio: "inherit" });
  } catch (err) {
    console.error(`❌ launchctl bootstrap failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  console.log(`   waiting for launchd to start it and for it to take port ${PORT}...`);
  type Started =
    | { kind: "no-launchctl" }
    | { kind: "not-started" }
    | { kind: "exited"; lastExit: string }
    | { kind: "running"; pid: number; holders: number[] | null };
  const started = pollFor<Started>(WAIT_SECONDS, () => {
    const s = jobState(uid);
    if (s === null) return { done: true, value: { kind: "no-launchctl" } };
    if (s !== "gone" && s.lastExit && s.lastExit !== "(never exited)") return { done: true, value: { kind: "exited", lastExit: s.lastExit } };
    if (s === "gone" || !s.running || !s.pid) return { done: false, value: { kind: "not-started" } };
    const holders = portHolders();
    return { done: holders === null || holders.includes(s.pid), value: { kind: "running", pid: s.pid, holders } };
  });
  if (started.kind === "exited") {
    console.error(`❌ launchd started the agent and it exited (last exit code ${started.lastExit}).`);
    console.error(`   Check the logs: tail -50 ~/.contextengine/logs/mcp-stderr.log`);
    process.exit(1);
  }
  if (started.kind === "not-started") {
    console.error(`❌ launchd did not report the agent running within ${WAIT_SECONDS} s.`);
    console.error(`   Check: launchctl print gui/${uid}/${LABEL}, and tail -50 ~/.contextengine/logs/mcp-stderr.log`);
    process.exit(1);
  }
  if (started.kind === "running") {
    if (started.holders !== null && started.holders.includes(started.pid)) {
      console.log(`✅ OpsContext is now running as a LaunchAgent (pid ${started.pid}, holds port ${PORT}; started at every login).`);
      console.log(``);
      console.log(`Verify:      curl -s http://127.0.0.1:${PORT}/health | jq .`);
      console.log(`Logs:        tail -f ~/.contextengine/logs/mcp-stderr.log`);
      console.log(`Stop:        opscontext uninstall-autostart`);
    } else {
      const who = started.holders === null ? "could not be checked (no working lsof here)" : started.holders.length ? `is still held by pid ${started.holders.join(", pid ")}` : "is not bound yet";
      console.log(`⚠️ launchd runs the agent (pid ${started.pid}), but port ${PORT} ${who}.`);
      console.log(`   A chat's server hands the port over once it sees the agent. Check in a minute: opscontext autostart-status`);
    }
    return;
  }
  // launchctl could not answer: fall back to the port alone.
  const bound = waitForPort(30);
  if (bound === null) {
    console.error(`⚠️ Loaded, but this machine has no working lsof, so whether the server bound port ${PORT} could not be checked.`);
    console.error(`   Check by hand: curl -s http://127.0.0.1:${PORT}/health | jq .`);
  } else if (bound) {
    console.log(`✅ OpsContext is now running as a LaunchAgent (started at every login).`);
    console.log(``);
    console.log(`Verify:      curl -s http://127.0.0.1:${PORT}/health | jq .`);
    console.log(`Logs:        tail -f ~/.contextengine/logs/mcp-stderr.log`);
    console.log(`Stop:        opscontext uninstall-autostart`);
  } else {
    console.error(`⚠️ Server didn't bind port ${PORT} within 30s.`);
    console.error(`   Check the logs: tail -50 ~/.contextengine/logs/mcp-stderr.log`);
    process.exit(1);
  }
}

export async function cliUninstallAutostart(args: string[]): Promise<void> {
  const help = args.includes("-h") || args.includes("--help");
  if (help) {
    console.log(`Usage: opscontext uninstall-autostart

Removes the LaunchAgent and stops the OpsContext MCP server. The audit log
and extension secret are NOT touched — only the auto-start wiring goes away.
You can re-install with: opscontext install-autostart`);
    return;
  }

  if (!isMacOS()) {
    console.error(`❌ Only macOS LaunchAgents supported here.`);
    process.exit(1);
  }

  const uid = userId();
  let removed = false;
  try {
    execFileSync("launchctl", ["bootout", `gui/${uid}/${LABEL}`], { stdio: "ignore" });
    removed = true;
  } catch {
    /* not loaded */
  }

  if (existsSync(PLIST_FILE)) {
    const { unlinkSync } = await import("fs");
    unlinkSync(PLIST_FILE);
    console.log(`✅ Removed ${PLIST_FILE}`);
  } else {
    console.log(`   (no plist at ${PLIST_FILE})`);
  }

  if (removed) {
    console.log(`✅ Stopped the running ${LABEL} agent.`);
  } else {
    console.log(`   (no running ${LABEL} agent found)`);
  }
  console.log(``);
  console.log(`Audit log and extension secret kept at ~/.contextengine/ — re-install any time.`);
}

export async function cliAutostartStatus(args: string[]): Promise<void> {
  if (args.includes("-h") || args.includes("--help")) {
    console.log(`Usage: opscontext autostart-status

Shows whether OpsContext is configured to auto-start (LaunchAgent present),
whether it's currently running (port 7842 listening), and the path to the
running entrypoint.`);
    return;
  }

  if (!isMacOS()) {
    console.log(`platform:  ${platform()} (LaunchAgent applies to macOS only)`);
    return;
  }

  const plistExists = existsSync(PLIST_FILE);
  const portUp = portIsOurs();
  const uid = userId();

  let launchctlState = "not loaded";
  try {
    const out = execFileSync("launchctl", ["print", `gui/${uid}/${LABEL}`], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });
    const match = out.match(/state\s*=\s*(\S+)/);
    if (match) launchctlState = match[1];
  } catch {
    /* ignore */
  }

  console.log(`OpsContext auto-start status`);
  console.log(`─────────────────────────────`);
  console.log(`  plist:       ${plistExists ? "✅ " + PLIST_FILE : "❌ not installed (run: opscontext install-autostart)"}`);
  console.log(`  launchctl:   ${launchctlState}`);
  console.log(`  port ${PORT}:   ${portUp === true ? "✅ listening" : portUp === false ? "❌ not listening" : "❔ unknown (lsof is not available here)"}`);

  if (portUp === true) {
    try {
      const health = execFileSync("curl", ["-sf", `http://127.0.0.1:${PORT}/health`], { encoding: "utf-8", timeout: 2000 });
      console.log(`  health:      ${health.trim()}`);
    } catch {
      console.log(`  health:      ⚠ port open but /health didn't respond`);
    }
  }
  console.log(``);
  console.log(`Logs: ~/.contextengine/logs/mcp-stderr.log`);
}
/* eslint-enable no-console */
