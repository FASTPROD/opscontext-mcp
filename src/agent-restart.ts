// [LOCKED] [THE-AGENT-FOLLOWS-THE-BUILD] - 2026-09-30
// [NEVER] let a chat server exit on a rebuild (its client would lose the connection), let the launchd
//         agent exit while its build folder is still changing, exit twice for the same build, or exit
//         when launchd would not start it again.
// WHY: after every build the agent kept running its old code until someone ran `launchctl kickstart`
//      by hand; until then every server was stale, and before 2.18.0 the oldest chat window took the
//      index over and ran its old importer (E2E_REVIEW_2026-09 C0 and point 20: on 30 September from
//      08:51 to 09:02 and from 15:51 to 16:00). A build is not one moment: tsc writes file by file, the
//      prune follows, a publish encodes the rubric and the next build rewrites it.
// FIX: at every role poll (15 s) the agent compares the build it loaded with the one on disk. It exits
//      only when they differ, no compiled file next to its entry changed for QUIET_MS, it has run for
//      MIN_UP_MS, the marker file does not name that very build (one restart per build, never a loop),
//      and it is the macOS launchd agent (OPSCONTEXT_DAEMON=1, parent pid 1) whose installed plist has
//      KeepAlive true; and only once the new build has proven it loads: its entry started with
//      CONTEXTENGINE_PREFLIGHT=1 in a scratch CE home evaluates every static import and exits 0 (tsc
//      emits even when it reports errors, and a build that cannot start would have launchd restart
//      it every 10 s). It writes the marker and a `server.self_restart` record, then ends like any
//      server; launchd starts it again on the new build. Anything that stops it is said once in its
//      log, with the command to restart it by hand. While it is away no old build takes the index
//      over. [LOCK] [ONE-INDEXER-MANY-READERS] [LOCK] [AUTOSTART-IS-THE-STANDING-INDEXER]
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { tmpdir } from "os";
import { execFile } from "child_process";
import { ceHome } from "./ce-home.js";
import { buildHashOrError } from "./server-registry.js";
import { LABEL as AGENT_LABEL, PLIST_FILE as AGENT_PLIST_FILE } from "./install-autostart.js";

/** No compiled file may have changed for this long before the agent leaves for a new build. */
export const QUIET_MS = 30_000;
/** A fresh agent finishes its start (index, model) before it may leave again. */
export const MIN_UP_MS = 120_000;
/** The new build must load within this long. */
export const PREFLIGHT_TIMEOUT_MS = 20_000;

export interface RestartInputs {
  /** OPSCONTEXT_DAEMON=1 */
  daemon: boolean;
  platform: string;
  ppid: number;
  /** The build this process registered with ("unknown" when it could not be hashed). */
  loadedBuild: string;
  /** The build on disk now, or null when it cannot be computed. */
  diskBuild: string | null;
  now: number;
  startedAt: number;
  /** The installed launchd plist, null when it cannot be read. */
  plistText: () => string | null;
  /** The newest mtime of a compiled file next to the entry, null when it cannot be read. */
  newestCompiledMs: () => number | null;
  /** The build the previous self-restart was for, null when none is recorded. */
  lastRestartTo: () => string | null;
}

export type RestartDecision =
  | { restart: true; from: string; to: string }
  | { restart: false; state: "not-the-agent" | "current" | "unknown-build" | "not-under-launchd" | "no-keepalive" | "changing" | "too-soon" | "already-restarted"; note: string | null };

const KICKSTART = `launchctl kickstart -k gui/$(id -u)/${AGENT_LABEL}`;

export function keepAliveIsTrue(plist: string): boolean {
  return /<key>\s*KeepAlive\s*<\/key>\s*<true\s*\/>/.test(plist);
}

/** Pure: whether the agent leaves now for the build on disk, and what it says when it does not. */
export function decideAgentRestart(i: RestartInputs): RestartDecision {
  if (!i.daemon) return { restart: false, state: "not-the-agent", note: null };
  if (i.loadedBuild === "unknown" || i.diskBuild === null) {
    return { restart: false, state: "unknown-build", note: "the build on disk cannot be compared with the one this agent loaded; it does not restart itself (after a build: " + KICKSTART + ")" };
  }
  if (i.loadedBuild === i.diskBuild) return { restart: false, state: "current", note: null };
  const newer = `build ${i.diskBuild} is on disk, this agent runs ${i.loadedBuild}`;
  if (i.platform !== "darwin" || i.ppid !== 1) {
    return { restart: false, state: "not-under-launchd", note: `${newer}; it was not started by launchd (parent pid ${i.ppid}), so it stays: restart it by hand` };
  }
  const plist = i.plistText();
  if (plist === null || !keepAliveIsTrue(plist)) {
    return { restart: false, state: "no-keepalive", note: `${newer}; the installed launchd job would not start it again (${plist === null ? `${AGENT_PLIST_FILE} unreadable` : "KeepAlive is not true"}), so it stays: ${KICKSTART}` };
  }
  const newest = i.newestCompiledMs();
  if (newest === null || i.now - newest < QUIET_MS) {
    return { restart: false, state: "changing", note: `${newer}; waiting until its folder has been quiet for ${QUIET_MS / 1000} s` };
  }
  if (i.now - i.startedAt < MIN_UP_MS) {
    return { restart: false, state: "too-soon", note: `${newer}; this agent started less than ${MIN_UP_MS / 60_000} minutes ago and waits` };
  }
  if (i.lastRestartTo() === i.diskBuild) {
    return { restart: false, state: "already-restarted", note: `${newer}, and it already restarted once for that build: it stays until restarted by hand (${KICKSTART})` };
  }
  return { restart: true, from: i.loadedBuild, to: i.diskBuild };
}

function markerPath(): string {
  return join(ceHome(), "agent-restart.json");
}

function newestCompiledMs(script: string): number | null {
  try {
    const dir = dirname(script);
    let newest = 0;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".js")) continue; // the files the build fingerprint covers
      newest = Math.max(newest, statSync(join(dir, f)).mtimeMs);
    }
    return newest || null;
  } catch {
    return null;
  }
}

/** The build the last self-restart was for, from the marker file; null when there is none. */
export function lastRestartTo(): string | null {
  try {
    const m = JSON.parse(readFileSync(markerPath(), "utf8")) as { to?: unknown };
    return typeof m.to === "string" ? m.to : null;
  } catch {
    return null;
  }
}

/** The decision for this process, reading the disk only as far as the decision needs. */
export function checkAgentRestart(opts: { script: string; loadedBuild: string; startedAt: number; now?: number }): RestartDecision {
  const daemon = process.env.OPSCONTEXT_DAEMON === "1";
  const disk = daemon ? buildHashOrError(opts.script) : { hash: null };
  return decideAgentRestart({
    daemon,
    platform: process.platform,
    ppid: process.ppid,
    loadedBuild: opts.loadedBuild,
    diskBuild: disk.hash,
    now: opts.now ?? Date.now(),
    startedAt: opts.startedAt,
    plistText: () => { try { return readFileSync(AGENT_PLIST_FILE, "utf8"); } catch { return null; } },
    newestCompiledMs: () => newestCompiledMs(opts.script),
    lastRestartTo,
  });
}

/** Written before the agent leaves, so a fresh agent never leaves twice for the same build. */
export function recordAgentRestart(r: { pid: number; from: string; to: string }): void {
  const path = markerPath();
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${r.pid}`;
  writeFileSync(tmp, JSON.stringify({ at: new Date().toISOString(), ...r }, null, 2));
  renameSync(tmp, path);
}

export type PreflightResult = { ok: true } | { ok: false; error: string; timedOut?: boolean };
/** A build that failed to start is not tried again; one that only ran out of time is, after this long. */
export const PREFLIGHT_RETRY_AFTER_TIMEOUT_MS = 10 * 60_000;
const preflights = new Map<string, { at: number; result: Promise<PreflightResult> }>();

/**
 * Whether the build on disk starts: its entry run with CONTEXTENGINE_PREFLIGHT=1 (the server exits 0
 * once every static import is evaluated) in a scratch CE home, never the launchd agent's. Asked once
 * per build: a build that does not start is not tried again every poll.
 */
export function preflightBuild(script: string, build: string, opts: { now?: number; timeoutMs?: number } = {}): Promise<PreflightResult> {
  const now = opts.now ?? Date.now();
  const timeoutMs = opts.timeoutMs ?? PREFLIGHT_TIMEOUT_MS;
  const known = preflights.get(build);
  if (known) {
    return known.result.then((r) => {
      if (r.ok || !r.timedOut || now - known.at < PREFLIGHT_RETRY_AFTER_TIMEOUT_MS) return r;
      if (preflights.get(build) === known) preflights.delete(build); // a loaded Mac, not a broken build: ask again
      return preflightBuild(script, build, opts);
    });
  }
  const p = new Promise<PreflightResult>((resolve) => {
    let home: string;
    try {
      home = mkdtempSync(join(tmpdir(), "ce-preflight-"));
    } catch (err) {
      resolve({ ok: false, error: `no scratch folder for the check: ${(err as Error).message}` });
      return;
    }
    const env: NodeJS.ProcessEnv = { ...process.env, CONTEXTENGINE_PREFLIGHT: "1", CONTEXTENGINE_HOME: home };
    delete env.OPSCONTEXT_DAEMON;
    execFile(process.execPath, [script], { env, timeout: timeoutMs, maxBuffer: 1 << 20 }, (err, _stdout, stderr) => {
      try { rmSync(home, { recursive: true, force: true }); } catch { /* a scratch folder */ }
      if (!err) { resolve({ ok: true }); return; }
      // Node ends a crash with "Node.js vX.Y.Z"; the line that names the error comes before it.
      const lines = String(stderr ?? "").split("\n").map((l) => l.trim()).filter(Boolean);
      const named = lines.find((l) => /^[A-Za-z]*Error\b.*:/.test(l)) ?? lines.filter((l) => !/^Node\.js v/.test(l)).slice(-1)[0];
      if (err.killed) { resolve({ ok: false, error: `no answer within ${timeoutMs / 1000} s`, timedOut: true }); return; }
      resolve({ ok: false, error: named || err.message });
    });
  });
  preflights.set(build, { at: now, result: p });
  return p;
}
