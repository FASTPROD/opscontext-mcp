// [LOCKED] [HEALTH-IS-MEASURED-NEVER-ESTIMATED] 2026-09-06
// [NEVER] put a number in this file that comes from a timer, a multiplier or a guess; every
//         field is counted from the audit log, the server registry, git, or a file on disk.
// WHY: the VS Code status bar showed "CE SAVE SESSION" in yellow on a wall-clock timer and
//      "~N min saved" from a multiplier nobody could check (Session 25 item 4). Meanwhile the
//      real problems of 2026-09-05 (eleven servers re-embedding, load average 230; two servers
//      on a stale build re-importing 1,766 records; a store growth of 1,766 in one minute) had no
//      surface at all. A nag without evidence trains the user to ignore the bar; a fact does not.
// FIX: one function computes the fleet's health from evidence, one writer (the indexer) drops
//      it into ~/.contextengine/fleet-health.json every minute, and every surface (servers CLI,
//      end-session, the status bar) reads the same file. Warnings list measured problems only.
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, readdirSync, renameSync, writeFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { listServers, type ServerReport } from "./server-registry.js";
import { readVerifyState, pendingRefusals } from "./audit.js";
import { claudeHookRegistrations } from "./install-claude-hook.js";
import { secretsLockHealth, type SecretsLockHealth } from "./secrets-lock.js";

export interface FleetHealth {
  generatedAt: string;
  version: string;
  writerPid: number;
  servers: {
    total: number;
    indexers: number;
    readers: number;
    /** Servers whose loaded build differs from the file on disk. */
    stale: Array<{ pid: number; version: string; build: string; cwd: string }>;
    diskBuild: string | null;
  };
  reindex: {
    /** Shared-index writes in the last hour, all corpora. */
    lastHourWrites: number;
    perCorpus: Record<string, number>;
    /** Above this many writes per hour a warning is raised. */
    threshold: number;
  };
  /** Claude Code hook registrations per event, read from ~/.claude/settings.json the way the
   *  installer counts them (paths expanded). null: no readable settings.json. A correct install
   *  has 1 for every event; the 2026-09-06 doubling would have shown 2 here within a minute. */
  claudeHooks: Record<string, number> | null;
  /** Whether Claude Code's user (or managed) settings deny the agent the secrets files, read the
   *  way `contextengine secrets-lock` reads them. null: no settings file on this machine. */
  secretsLock: SecretsLockHealth | null;
  today: {
    /** Claude Code hook events (vscode.*) since local midnight. */
    hookEvents: number;
    /** Of those, records identical in event and payload to the previous hook event within
     *  DOUBLED_WINDOW_MS: what a hook registered twice produces.
     *  [LOCKED] [DOUBLED-IS-THE-SAME-INPUT-TWICE] 2026-09-29
     *  [NEVER] call two records doubled on the tool name and the file path alone.
     *  WHY: on 2026-09-29 this counted 28 of 569 events and health said "a hook is registered twice
     *       somewhere". Measured against the transcripts: 6 Edits on one file, 6 records, one per call.
     *       Claude Code runs the hooks of parallel calls one after the other, about 1 s apart, and the
     *       record kept only the file path, so distinct edits looked identical (E2E_REVIEW C6-6).
     *  FIX: the hook records `input_chars`, the size of the whole tool input (no content), inside the
     *       payload this comparison uses: two edits of one file differ, the same call recorded twice
     *       does not. */
    doubledHookEvents: number;
    /** Pre-commit blocks (hook.block) since local midnight. */
    blocks: number;
    /** Store refusals (unreadable, shrink refused, growth refused) since local midnight. */
    refusals: number;
    learningsSaved: number;
    /** learning.backup_failed records since local midnight: the daily copy of the store could not be written. */
    backupFailures: number;
    /** Newest last: time, kind, one-line detail. */
    lastBlocks: Array<{ ts: string; kind: string; detail: string }>;
  };
  /** The last full check of the audit chain (`audit-verify`, run by hand or daily by the indexing
   *  server), or null when it never ran here. [LOCK] [HEALTH-SEES-THE-CHAIN] */
  chain: {
    checkedAt: string;
    ageHours: number;
    ok: boolean;
    unique: number;
    altered: number;
    orphans: number;
    unreadable: number;
    duplicates: number;
    reason: string | null;
  } | null;
  /** Entries the audit log refused today (chained as audit.append_failed, or still pending), and
   *  records cut short today (audit.torn_tail). */
  auditLog: {
    refusedToday: number; lastRefusal: string | null; tornToday: number; lastTornKept: string | null;
    /** Set when the live log is there but could not be read: every count above is then unknown, not zero. */
    readError: string | null;
  };
  /** The newest release for which verify-release passed on this machine, or null. */
  lastVerifiedRelease: string | null;
  /** Measured problems only. Empty means green. */
  warnings: string[];
}

export const REINDEX_PER_HOUR_WARN = 30;
/** Doubled hook events above this share of the day's hook events raise a warning, once the day
 *  has at least DOUBLED_MIN_EVENTS of them (a single repeated call is not a doubled hook). */
export const DOUBLED_HOOK_EVENTS_WARN_PCT = 5;
export const DOUBLED_MIN_EVENTS = 10;
export const DOUBLED_WINDOW_MS = 2000;
/** A full check older than this is reported: the indexing server runs one a day. */
export const CHAIN_CHECK_STALE_HOURS = 48;
const TAIL_BYTES = 8 * 1024 * 1024;

function ceHome(): string {
  return process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine");
}

export function fleetHealthPath(): string {
  return join(ceHome(), "fleet-health.json");
}

/** The last `bytes` of a file as complete lines (the first partial line is dropped); `error` when the
 *  file is there but could not be read. [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: an unreadable log used to
 *  count as zero events, blocks and refusals, and health stayed green (2026-09-29, C6-5). */
function tailLines(path: string, bytes: number): { lines: string[]; error: string | null } {
  if (!existsSync(path)) return { lines: [], error: null };
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    const size = fstatSync(fd).size;
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    let text = buf.toString("utf8");
    if (start > 0) {
      const nl = text.indexOf("\n");
      text = nl === -1 ? "" : text.slice(nl + 1);
    }
    return { lines: text.split("\n").filter(Boolean), error: null };
  } catch (err) {
    return { lines: [], error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

interface Rec { ts: string; event: string; payload?: Record<string, unknown> }

function parseRecords(lines: string[]): Rec[] {
  const out: Rec[] = [];
  for (const l of lines) {
    try {
      const r = JSON.parse(l);
      if (r && typeof r.ts === "string" && typeof r.event === "string") out.push(r);
    } catch {
      /* a torn line, ignored */
    }
  }
  return out;
}

function localMidnight(now: Date): Date {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d;
}

function blockDetail(p: Record<string, unknown> = {}): string {
  const check = String(p.check ?? "block");
  if (p.file) return `${check}: ${String(p.file)}${p.line ? `:${String(p.line)}` : ""}${p.pattern_id ? ` (${String(p.pattern_id)})` : ""}`;
  if (p.requires_section) return `${check}: ${String(p.requires_section)}`;
  if (p.reason) return `${check}: ${String(p.reason)}`;
  return check;
}

/** The highest version with a verify-release marker; version order, not file time (ties). */
export function lastVerifiedRelease(dir: string = ceHome()): string | null {
  let files: string[] = [];
  try { files = readdirSync(dir); } catch { return null; }
  const versions = files.map((f) => /^verified-(\d+\.\d+\.\d+)$/.exec(f)?.[1]).filter((v): v is string => !!v);
  if (versions.length === 0) return null;
  const key = (v: string) => v.split(".").map(Number);
  versions.sort((a, b) => { const x = key(a), y = key(b); return (x[0] - y[0]) || (x[1] - y[1]) || (x[2] - y[2]); });
  return versions[versions.length - 1];
}

export function computeFleetHealth(opts: { now?: Date; version?: string; auditPath?: string; report?: ServerReport; settingsPath?: string } = {}): FleetHealth {
  const now = opts.now ?? new Date();
  const report = opts.report ?? listServers();
  const audit = opts.auditPath ?? join(ceHome(), "audit.log");
  const tail = tailLines(audit, TAIL_BYTES);
  const records = parseRecords(tail.lines);
  const midnight = localMidnight(now).getTime();
  const hourAgo = now.getTime() - 3_600_000;

  const perCorpus: Record<string, number> = {};
  let lastHourWrites = 0, blocks = 0, refusals = 0, learningsSaved = 0, hookEvents = 0, doubledHookEvents = 0;
  const lastBlocks: FleetHealth["today"]["lastBlocks"] = [];
  let prevHook: { t: number; event: string; payload: string } | null = null;
  let refusedToday = 0, tornToday = 0, backupFailures = 0;
  let lastBackupError: string | null = null;
  let lastRefusal: string | null = null, lastTornKept: string | null = null;
  for (const r of records) {
    const t = Date.parse(r.ts);
    if (Number.isNaN(t)) continue;
    if (r.event.startsWith("vscode.") && t >= midnight) {
      hookEvents++;
      const payload = JSON.stringify(r.payload ?? {});
      if (prevHook && prevHook.event === r.event && prevHook.payload === payload && t - prevHook.t <= DOUBLED_WINDOW_MS) doubledHookEvents++;
      prevHook = { t, event: r.event, payload };
    }
    if (r.event === "index.write" && t >= hourAgo) {
      lastHourWrites++;
      const c = String(r.payload?.corpus ?? "?");
      perCorpus[c] = (perCorpus[c] ?? 0) + 1;
    }
    if (t < midnight) continue;
    if (r.event === "audit.append_failed") {
      refusedToday += Number(r.payload?.count ?? 0) || 0;
      const errs = r.payload?.errors as Record<string, number> | undefined;
      if (errs && Object.keys(errs).length > 0) lastRefusal = Object.keys(errs)[0];
    }
    if (r.event === "audit.torn_tail") { tornToday++; lastTornKept = String(r.payload?.kept ?? ""); }
    if (r.event === "learning.backup_failed") { backupFailures++; lastBackupError = String(r.payload?.error ?? ""); }
    if (r.event === "hook.block") { blocks++; lastBlocks.push({ ts: r.ts, kind: "pre-commit", detail: blockDetail(r.payload) }); }
    else if (r.event === "learning.store_unreadable" || r.event === "learning.store_shrink_refused" || r.event === "learning.store_growth_refused") {
      refusals++;
      lastBlocks.push({ ts: r.ts, kind: "store", detail: r.event.replace("learning.store_", "").replace(/_/g, " ") });
    } else if (r.event === "learning.save" && r.payload?.mode !== "update") learningsSaved++; // a sweep's updates are not saves
  }

  const stale = report.servers.filter((s) => s.staleBuild).map((s) => ({ pid: s.pid, version: s.version, build: s.build, cwd: s.cwd }));
  const diskBuild = report.servers.find((s) => s.currentBuild)?.currentBuild ?? null;
  const indexers = report.servers.filter((s) => s.role !== "reader").length;

  const claudeHooks = claudeHookRegistrations(opts.settingsPath);
  const secretsLock = secretsLockHealth({ userSettingsPath: opts.settingsPath });

  const warnings: string[] = [];
  if (stale.length > 0) warnings.push(`${stale.length} server(s) on an old build (pid ${stale.map((s) => s.pid).join(", ")}): reload their windows`);
  if (claudeHooks) {
    const doubled = Object.entries(claudeHooks).filter(([, n]) => n > 1);
    if (doubled.length > 0) warnings.push(`Claude Code runs an OpsContext hook more than once (${doubled.map(([ev, n]) => `${ev}=${n}`).join(", ")}): every event reaches the audit log that many times, run install-claude-hook`);
    const core = ["UserPromptSubmit", "PostToolUse", "SessionStart", "Stop"];
    const present = core.filter((ev) => (claudeHooks[ev] ?? 0) >= 1);
    if (present.length > 0 && present.length < core.length) warnings.push(`OpsContext hooks installed for ${present.join(", ")} but not ${core.filter((ev) => !present.includes(ev)).join(", ")}: run install-claude-hook`);
  }
  // [LOCK] [SECRETS-LOCK-NEVER-READS-A-SECRET]: read from the settings file only; red until every rule is there.
  if (secretsLock && !secretsLock.inPlace) {
    warnings.push(`agent lock on secrets files: MISSING (${secretsLock.missing} of ${secretsLock.total} deny rules absent from Claude Code's user settings): the agent can read the credentials and env files; run contextengine secrets-lock --apply in your own terminal`);
  }
  if (hookEvents >= DOUBLED_MIN_EVENTS && doubledHookEvents * 100 > hookEvents * DOUBLED_HOOK_EVENTS_WARN_PCT) {
    warnings.push(`${doubledHookEvents} of ${hookEvents} Claude Code hook events today arrived twice within ${DOUBLED_WINDOW_MS / 1000} s with the same input: a hook is registered twice somewhere, or the installed hook predates 2.15.0 (no input_chars); run install-claude-hook`);
  }
  if (tail.error) warnings.push(`the live audit log could not be read (${tail.error}): today's counts are unknown, not zero`);
  if (backupFailures > 0) warnings.push(`the daily learnings backup failed ${backupFailures} time(s) today${lastBackupError ? ` (${lastBackupError})` : ""}: the store has no fresh restore copy`);
  if (lastHourWrites > REINDEX_PER_HOUR_WARN) warnings.push(`${lastHourWrites} shared-index writes in the last hour (ceiling ${REINDEX_PER_HOUR_WARN}): something saves in a loop`);
  if (refusals > 0) warnings.push(`${refusals} learnings-store refusal(s) today: a write looked like a wipe or a runaway import`);

  // [LOCKED] [HEALTH-SEES-THE-CHAIN] - 2026-09-27
  // [NEVER] report green while the audit chain failed its last check, or while the log refuses entries.
  // WHY: fleet health read the audit log for counts only. On three broken logs (a stuck log whose
  //      appends were all refused, missing history, 100 altered records) the verifier said FAILED
  //      and health said 0 warnings (E2E_REVIEW_2026-09 B6-1). The chain is the product's claim.
  // FIX: health never runs the check (26 s and 3.5 GB on 4.9M records, measured): it reads the
  //      result every `audit-verify` leaves, which the indexing server refreshes daily in a separate
  //      low-priority process. A failed check, a check older than CHAIN_CHECK_STALE_HOURS, refused
  //      entries (chained as audit.append_failed or still pending) and records cut short today are
  //      each a warning. [LOCK] [A-REFUSED-APPEND-IS-COUNTED-AND-CHAINED] [LOCK] [TORN-TAIL-IS-KEPT-AND-CHAINED]
  const vs = readVerifyState();
  const chain = vs
    ? {
        checkedAt: vs.checkedAt,
        ageHours: Math.max(0, Math.round((now.getTime() - Date.parse(vs.checkedAt)) / 3_600_000)),
        ok: vs.ok,
        unique: vs.unique,
        altered: vs.altered,
        orphans: vs.orphans,
        unreadable: vs.unreadable,
        duplicates: vs.duplicates,
        reason: vs.reason,
      }
    : null;
  if (chain && !chain.ok) warnings.push(`the audit chain did not verify at its last check (${chain.checkedAt.slice(0, 16).replace("T", " ")}Z): ${chain.reason ?? "see contextengine audit-verify"}`);
  else if (chain && chain.ageHours > CHAIN_CHECK_STALE_HOURS) warnings.push(`the audit chain was last checked ${chain.ageHours} h ago: run contextengine audit-verify`);
  const pending = pendingRefusals();
  if (pending.count > 0 && pending.error) lastRefusal = pending.error; // the newest refusal wins
  const refusedTotal = refusedToday + pending.count;
  if (refusedTotal > 0) warnings.push(`the audit log refused ${refusedTotal} entr${refusedTotal === 1 ? "y" : "ies"} today${lastRefusal ? ` (${lastRefusal})` : ""}: they are not in the log, and the gap is noted on the chain`);
  if (tornToday > 0) warnings.push(`${tornToday} audit record(s) were cut short today (a full disk?); the bytes are kept in ${lastTornKept}`);
  for (const w of report.warnings) if (/index on their own/.test(w)) warnings.push(w);

  return {
    generatedAt: now.toISOString(),
    version: opts.version ?? "unknown",
    writerPid: process.pid,
    servers: { total: report.servers.length, indexers, readers: report.servers.length - indexers, stale, diskBuild },
    reindex: { lastHourWrites, perCorpus, threshold: REINDEX_PER_HOUR_WARN },
    claudeHooks,
    secretsLock,
    today: { hookEvents, doubledHookEvents, blocks, refusals, learningsSaved, backupFailures, lastBlocks: lastBlocks.slice(-3) },
    chain,
    auditLog: { refusedToday: refusedTotal, lastRefusal, tornToday, lastTornKept, readError: tail.error },
    lastVerifiedRelease: lastVerifiedRelease(),
    warnings,
  };
}

/** Temp file + rename: a reader never sees half a file. */
export function writeFleetHealth(h: FleetHealth): string {
  const path = fleetHealthPath();
  mkdirSync(join(path, ".."), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(h, null, 2) + "\n");
  renameSync(tmp, path);
  return path;
}

export function formatFleetHealth(h: FleetHealth): string {
  const lines: string[] = [];
  lines.push(`health: ${h.warnings.length === 0 ? "green" : `${h.warnings.length} measured problem(s)`}  (v${h.version}, last verified release ${h.lastVerifiedRelease ?? "none"}, ${h.generatedAt.slice(11, 19)}Z)`);
  lines.push(`  servers ${h.servers.total}: ${h.servers.indexers} indexing, ${h.servers.readers} reading, ${h.servers.stale.length} on an old build`);
  lines.push(`  shared-index writes last hour: ${h.reindex.lastHourWrites} (ceiling ${h.reindex.threshold})`);
  lines.push(`  today: ${h.today.blocks} block(s) prevented, ${h.today.refusals} store refusal(s), ${h.today.learningsSaved} learning(s) saved${h.today.backupFailures ? `, ${h.today.backupFailures} backup failure(s)` : ""}`);
  lines.push(h.chain
    ? `  audit chain: ${h.chain.ok ? "verified" : "FAILED"} ${h.chain.ageHours} h ago, ${h.chain.unique} record(s)${h.chain.duplicates ? `, ${h.chain.duplicates} copies counted once` : ""}; ${h.auditLog?.refusedToday ?? 0} entr(ies) refused today`
    : `  audit chain: not checked on this machine yet (the indexing server runs a full check daily; or run contextengine audit-verify)`);
  lines.push(`  claude code: ${h.today.hookEvents} hook event(s) today, ${h.today.doubledHookEvents} doubled; registrations ${h.claudeHooks ? Object.entries(h.claudeHooks).map(([ev, n]) => `${ev}=${n}`).join(" ") : "no settings.json"}`);
  lines.push(`  agent lock on secrets files: ${h.secretsLock ? (h.secretsLock.inPlace ? "in place" : `MISSING (${h.secretsLock.missing} of ${h.secretsLock.total} rules)`) : "no Claude Code settings on this machine"}`);
  for (const b of h.today.lastBlocks) lines.push(`    ${b.ts.slice(11, 19)}Z ${b.kind}: ${b.detail}`);
  for (const w of h.warnings) lines.push(`  ⚠ ${w}`);
  return lines.join("\n");
}
