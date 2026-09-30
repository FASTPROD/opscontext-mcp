// The SealHour client, step 1 (COMPR-TSA docs/SEALHOUR_PROTOCOL.md; plan docs/SEALHOUR_INTEGRATION_PLAN.md
// section 6): once an hour, when the audit log grew, a checkpoint of the chain (and of the workspaces'
// code when the owner said yes), kept in ~/.contextengine/anchors/, stamped by the interim backend
// (src/anchor-tsa.ts) until the SealHour service exists.
//
// [LOCKED] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] - 2026-09-30
// [NEVER] stamp, or open any connection, unless anchors/config.json says enabled AND records the owner's
//         yes to this backend and these providers, given on the enable screen; never set that yes from
//         a default, a flag the owner did not type, an environment variable or a policy file.
// WHY: OpsContext's promise is local-only: no network call without an explicit opt-in (workplan 2,
//      global criteria). A fingerprint leaving the machine tells the receiver the hours the owner was
//      active; the owner decides that, on a screen that says so (contract section 10, correction 7).
// FIX: `contextengine anchor enable` shows the screen, asks the code question (default yes) and the
//      start question (default no), and writes nothing before the second answer. anchorTick() returns
//      "off" before touching anything else unless that consent is on disk, and stamps only with the
//      providers it names.
//
// [LOCKED] [ONE-EMITTER-PER-MACHINE] - 2026-09-30
// [NEVER] make a checkpoint outside the anchor lock, or without re-reading the chain's head under it.
// WHY: 31 OpsContext servers ran at once on the author's Mac (workplan 2, correction 5). Two emitters
//      would each chain a checkpoint on the same previous one: a forked chain that verify reports.
// FIX: only the elected indexer schedules the hourly job (src/index.ts), and the job itself takes an
//      O_EXCL lock (a dead holder loses it at once, a live one keeps it up to 6 hours), then reads the
//      chain's head and "one checkpoint per clock hour" from disk under it.
//
// [LOCKED] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD] - 2026-09-30
// [NEVER] make a checkpoint whose window is empty, and never append an audit record from the hourly job.
// WHY: the contract allows a checkpoint only when the log grew (section 2.5), so the receiver learns the
//      hours the owner was active, not the hours the machine was on. A job that wrote its own record
//      each hour would make the log grow every hour and stamp forever.
// FIX: the job compares the live log's head with the last checkpoint's before anything else and writes
//      its results to anchors/, never to the audit log. Only the owner's own changes (enable, disable,
//      code on or off, the copy folder) are chained, as consent evidence.
//
// [LOCKED] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED] - 2026-09-30
// [NEVER] count a checkpoint as stamped without a stored stamp that answered it, or report an hour as
//         sealed: in interim mode nothing is sealed by SealHour.
// WHY: an hour that could not be stamped must be said (plan section 8, [EXEC-FAILURE-IS-NOT-EMPTY]); a
//      status line that rounds "queued" up to "stamped" is the silent failure the product exists to catch.
// FIX: a checkpoint is stamped when at least one provider's reply was granted for its digest and stored;
//      otherwise it is queued and retried, and every surface says "not stamped since" with the reason.
//      Once a later checkpoint is stamped, an earlier one still queued is dated through the chain by that
//      stamp (its digest is inside it) and said so, with that later date; it is not retried, since a
//      stamp of its own would now come later still.
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync, constants, copyFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomBytes, randomInt } from "crypto";
import { liveHeadHash } from "./audit.js";
import { readWindow, type Position } from "./anchor-window.js";
import { canonBytes, checkpointProblems, codeRoot as codeRootOf, digestOf, isoSecond, makeCheckpoint, ZERO, type Checkpoint } from "./anchor-protocol.js";
import { activeProviders, stampDigest, type Provider, type StampResult } from "./anchor-tsa.js";
import { codeLeaves } from "./anchor-code.js";
import { findRepoPolicy } from "./policy.js";

export const ANCHOR_SCREEN_VERSION = 1;
/** The slot is drawn once per machine, between these minutes of each hour (never :00 to :04, where
 *  every scheduler on earth fires, nor the hour's last minutes). */
const SLOT_MIN_S = 5 * 60;
const SLOT_MAX_S = 55 * 60;
/** Queued stamps are retried after 1, 2, 4, 8, 15, 30, then every 60 minutes. */
const RETRY_MIN = [1, 2, 4, 8, 15, 30, 60];
const MAX_RETRIES_PER_TICK = 12;
/** A live holder keeps the lock this long (a first code scan can take many minutes); a dead one loses
 *  it at once. Past this age the pid may belong to another process. [LOCK] [ONE-EMITTER-PER-MACHINE] */
const LOCK_STALE_MS = 6 * 3_600_000;
/** After a failed run, the job waits this long before the server starts it again. */
const ERROR_BACKOFF_MS = 15 * 60_000;
/** A job that has not run for this long while there is something to stamp is a problem. */
export const JOB_STALE_MS = 75 * 60_000;

function ceHome(): string {
  return process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine");
}
export const anchorsDir = (): string => join(ceHome(), "anchors");
const configPath = () => join(anchorsDir(), "config.json");
const statePath = () => join(anchorsDir(), "state.json");
export const checkpointsDir = (): string => join(anchorsDir(), "checkpoints");
export const certsDir = (): string => join(anchorsDir(), "certs");
const manifestsDir = () => join(anchorsDir(), "manifests");
const lockPath = () => join(anchorsDir(), "anchor.lock");

export interface AnchorConfig {
  version: 1;
  enabled: boolean;
  code: boolean;
  backend: "rfc3161";
  /** Seconds past each hour at which this machine's checkpoint is due. */
  slot_seconds: number;
  /** Random, names this machine's folder in the copy off the machine. */
  machine: string;
  /** The owner's yes, as given on the enable screen. [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] */
  consent: { at: string; screen: number; backend: "rfc3161"; providers: string[] } | null;
  copy_dir: string | null;
  enabled_at: string | null;
  disabled_at: string | null;
}

export interface ChainHead {
  seq: number;
  digest: string;
  head_hash: string;
  created_at: string;
  /** Where the next window starts; null when unknown (the reader then searches for head_hash). */
  at: Position | null;
}

export interface AnchorState {
  chain: ChainHead | null;
  /** Set when the previous checkpoint's last record is gone from the log. */
  lost: string | null;
  last_tick: { at: string; action: string; detail: string } | null;
  next_due: string | null;
  /** The newest stamped checkpoint, for status lines that must not list the folder every minute. */
  last_stamped: { seq: number; created_at: string; ok: number; total: number; failed: string[] } | null;
  queued: Array<{ seq: number; created_at: string; error: string | null }>;
  code: { repos: number; skipped: number } | null;
  copy: { at: string | null; error: string | null } | null;
}

export interface CheckpointMeta {
  seq: number;
  digest: string;
  created_at: string;
  first_ts: string;
  last_ts: string;
  end: Position;
  code: { repos: number; skipped: Array<{ repo: string; why: string }> } | null;
  attempts: number;
  next_try_at: string | null;
  /** Set when a later checkpoint was stamped first: its chain names this one's digest, so this one is
   *  dated by that stamp (a later date) and is no longer retried: any stamp of its own now would be later
   *  still. */
  covered_by?: { seq: number; name: string; time: string | null } | null;
}

export type StampEntry = StampResult & { first_try: boolean };

function writeJson(path: string, obj: unknown): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  renameSync(tmp, path);
}

function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

export function readConfig(): AnchorConfig | null {
  const c = readJson<AnchorConfig>(configPath());
  return c && c.version === 1 ? c : null;
}

export function writeConfig(c: AnchorConfig): void {
  mkdirSync(anchorsDir(), { recursive: true, mode: 0o700 });
  writeJson(configPath(), c);
}

const emptyState = (): AnchorState => ({ chain: null, lost: null, last_tick: null, next_due: null, last_stamped: null, queued: [], code: null, copy: null });

export function readState(): AnchorState {
  return { ...emptyState(), ...(readJson<AnchorState>(statePath()) ?? {}) };
}

export function writeState(s: AnchorState): void {
  mkdirSync(anchorsDir(), { recursive: true, mode: 0o700 });
  writeJson(statePath(), s);
}

/** A new configuration for the enable screen's yes: a random slot and machine id. */
export function newConfig(o: { code: boolean; providers: string[]; now: Date; rand?: (min: number, max: number) => number }): AnchorConfig {
  const rand = o.rand ?? ((min: number, max: number) => randomInt(min, max));
  const at = o.now.toISOString();
  return {
    version: 1,
    enabled: true,
    code: o.code,
    backend: "rfc3161",
    slot_seconds: rand(SLOT_MIN_S, SLOT_MAX_S),
    machine: randomBytes(4).toString("hex"),
    consent: { at, screen: ANCHOR_SCREEN_VERSION, backend: "rfc3161", providers: o.providers },
    copy_dir: null,
    enabled_at: at,
    disabled_at: null,
  };
}

// ---------- the checkpoints on disk ----------

const FOLDER = /^(\d{6})-([0-9a-f]{12})$/;

export interface StoredCheckpoint {
  dir: string;
  name: string;
  seq: number;
  checkpoint: Checkpoint;
  meta: CheckpointMeta;
  stamps: Record<string, StampEntry>;
}

export function listCheckpoints(): StoredCheckpoint[] {
  let names: string[];
  try {
    names = readdirSync(checkpointsDir()).filter((n) => FOLDER.test(n)).sort();
  } catch {
    return [];
  }
  const out: StoredCheckpoint[] = [];
  for (const name of names) {
    const dir = join(checkpointsDir(), name);
    const checkpoint = readJson<Checkpoint>(join(dir, "checkpoint.json"));
    const meta = readJson<CheckpointMeta>(join(dir, "meta.json"));
    if (!checkpoint || !meta) continue;
    out.push({ dir, name, seq: Number(FOLDER.exec(name)![1]), checkpoint, meta, stamps: readJson<Record<string, StampEntry>>(join(dir, "stamps.json")) ?? {} });
  }
  return out;
}

export const isStamped = (c: { stamps: Record<string, StampEntry> }): boolean => Object.values(c.stamps).some((s) => s.ok);

/** The earliest time among a checkpoint's granted stamps. */
export const firstStampTime = (c: { stamps: Record<string, StampEntry> }): string | null =>
  Object.values(c.stamps).filter((s) => s.ok && s.time).map((s) => s.time!).sort()[0] ?? null;

/**
 * Mark every checkpoint still queued that a later stamped checkpoint covers: the earliest later stamped
 * one whose chain reaches back to it unbroken. Written to its meta.json. [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED]
 */
function markCovered(all: StoredCheckpoint[]): void {
  for (let i = 0; i < all.length; i++) {
    const c = all[i];
    if (isStamped(c) || c.meta.covered_by) continue;
    for (let j = i + 1; j < all.length; j++) {
      if (all[j].checkpoint.prev_checkpoint_digest !== digestOf(all[j - 1].checkpoint)) break; // the chain breaks: nothing later covers it
      if (isStamped(all[j])) {
        c.meta.covered_by = { seq: all[j].seq, name: all[j].name, time: firstStampTime(all[j]) };
        c.meta.next_try_at = null;
        writeJson(join(c.dir, "meta.json"), c.meta);
        break;
      }
    }
  }
}

const isQueued = (c: StoredCheckpoint): boolean => !isStamped(c) && !c.meta.covered_by;

// ---------- the lock ----------

function holderGone(path: string): boolean {
  let pid: number;
  try {
    pid = parseInt(readFileSync(path, "utf8").split("\n")[0], 10);
  } catch {
    return false;
  }
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return false;
  try {
    process.kill(pid, 0);
    return false;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ESRCH";
  }
}

/** The anchor lock, or null while another live job holds it. [LOCK] [ONE-EMITTER-PER-MACHINE] */
export function acquireAnchorLock(): (() => void) | null {
  mkdirSync(anchorsDir(), { recursive: true, mode: 0o700 });
  const path = lockPath();
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      try { writeSync(fd, `${process.pid}\n${new Date().toISOString()}\n`); } catch { /* a courtesy */ }
      closeSync(fd);
      return () => { try { unlinkSync(path); } catch { /* already gone */ } };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      let age = 0;
      try { age = Date.now() - statSync(path).mtimeMs; } catch { continue; }
      if (age < LOCK_STALE_MS && !holderGone(path)) return null;
      try { unlinkSync(path); } catch { /* another job broke it first */ }
    }
  }
  return null;
}

// ---------- the hourly job ----------

const hourKey = (d: Date) => d.toISOString().slice(0, 13);
const hourStart = (d: Date) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours()));

/** This hour's slot, as a time. */
export function slotOf(d: Date, slotSeconds: number): Date {
  return new Date(hourStart(d).getTime() + slotSeconds * 1000);
}

/** When the next checkpoint is due: this hour's slot if it is still ahead and this hour has none yet,
 *  else next hour's. */
function nextSlot(now: Date, cfg: AnchorConfig, chain: ChainHead | null): Date {
  const slot = slotOf(now, cfg.slot_seconds);
  const doneThisHour = !!chain && hourKey(new Date(chain.created_at)) === hourKey(now);
  if (now < slot && !doneThisHour) return slot;
  return slotOf(new Date(hourStart(now).getTime() + 3_600_000), cfg.slot_seconds);
}

export interface TickReport {
  action: "off" | "busy" | "checkpoint" | "quiet" | "not-due" | "lost" | "error";
  detail: string;
  checkpoint?: string;
  stamped?: string[];
  retried?: number;
}

function readPackageVersion(): string {
  try {
    const v = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: string }).version;
    return typeof v === "string" && /^[ -~]{1,32}$/.test(v) ? v : "unknown";
  } catch {
    return "unknown";
  }
}

/** The providers this owner said yes to, among those in use. */
export function consentedProviders(cfg: AnchorConfig): Provider[] {
  const yes = new Set(cfg.consent?.providers ?? []);
  return activeProviders().filter((p) => yes.has(p.id));
}

async function stampAll(c: { dir: string; checkpoint: Checkpoint; stamps: Record<string, StampEntry> }, providers: Provider[], firstTry: boolean, o: { now: () => Date; timeoutMs?: number }): Promise<Record<string, StampEntry>> {
  const digest = digestOf(c.checkpoint);
  const results = await Promise.all(providers.map((p) => stampDigest(digest, p, c.dir, { certsDir: certsDir(), timeoutMs: o.timeoutMs, now: o.now })));
  const stamps = { ...c.stamps };
  for (const r of results) if (!stamps[r.provider]?.ok) stamps[r.provider] = { ...r, first_try: firstTry };
  writeJson(join(c.dir, "stamps.json"), stamps);
  return stamps;
}

const lastError = (stamps: Record<string, StampEntry>): string | null => {
  const failed = Object.values(stamps).filter((s) => !s.ok && s.error);
  return failed.length > 0 ? `${failed.map((s) => `${s.name}: ${s.error}`).join("; ")}` : null;
};

function summarize(state: AnchorState, all: StoredCheckpoint[]): void {
  const stamped = [...all].reverse().find(isStamped);
  state.last_stamped = stamped
    ? {
        seq: stamped.seq,
        created_at: stamped.checkpoint.created_at,
        ok: Object.values(stamped.stamps).filter((s) => s.ok).length,
        total: Object.keys(stamped.stamps).length,
        failed: Object.values(stamped.stamps).filter((s) => !s.ok).map((s) => s.name),
      }
    : null;
  state.queued = all.filter(isQueued).map((c) => ({ seq: c.seq, created_at: c.checkpoint.created_at, error: lastError(c.stamps) }));
}

/** Copy the checkpoints and stamps (never the code leaves or meta.json: they can name repositories) to the owner's
 *  folder off this machine, file by file, only what is new or changed. Correction 1 of workplan 2. */
export function copyOffMachine(cfg: AnchorConfig, now: Date): { at: string | null; error: string | null } {
  if (!cfg.copy_dir) return { at: null, error: null };
  if (!existsSync(cfg.copy_dir)) return { at: null, error: `the folder ${cfg.copy_dir} is not there (not mounted?)` };
  const dest = join(cfg.copy_dir, `opscontext-anchors-${cfg.machine}`);
  try {
    for (const c of listCheckpoints()) {
      const to = join(dest, "checkpoints", c.name);
      mkdirSync(to, { recursive: true });
      for (const f of readdirSync(c.dir)) {
        if (!/^(checkpoint\.json|stamps\.json|checkpoint\.[a-z0-9-]+\.ts[qr])$/.test(f)) continue;
        const src = join(c.dir, f);
        const dst = join(to, f);
        const a = statSync(src);
        let same = false;
        try { const b = statSync(dst); same = b.size === a.size && b.mtimeMs >= a.mtimeMs; } catch { same = false; }
        if (!same) copyFileSync(src, dst);
      }
    }
    if (existsSync(certsDir())) {
      mkdirSync(join(dest, "certs"), { recursive: true });
      for (const f of readdirSync(certsDir())) if (f.endsWith(".pem")) copyFileSync(join(certsDir(), f), join(dest, "certs", f));
    }
    return { at: now.toISOString(), error: null };
  } catch (e) {
    return { at: null, error: (e as Error).message.slice(0, 200) };
  }
}

/**
 * The hourly job: retry queued stamps that are due, then, when this hour's slot has passed, this hour
 * has no checkpoint yet and the log grew, make one and stamp it; then copy off the machine.
 * Runs in its own process (`contextengine anchor tick`), started by the indexing server.
 */
export async function anchorTick(o: { now?: () => Date; force?: boolean; timeoutMs?: number; clientVersion?: string } = {}): Promise<TickReport> {
  const now = o.now ?? (() => new Date());
  const cfg = readConfig();
  // [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE]: nothing is read, written or sent without the owner's yes.
  if (!cfg || !cfg.enabled || !cfg.consent || cfg.consent.backend !== "rfc3161") return { action: "off", detail: "SealHour is off on this machine" };
  const providers = consentedProviders(cfg);
  if (providers.length === 0) return { action: "off", detail: "no time stamp service this machine said yes to is in use: run contextengine anchor enable" };

  const release = acquireAnchorLock();
  if (!release) return { action: "busy", detail: "another anchor job is running" };
  const state = readState();
  let report: TickReport = { action: "not-due", detail: "" };
  try {
    let all = listCheckpoints();
    // A checkpoint written just before a crash, whose state was not: it is the chain's head.
    const last = all[all.length - 1];
    if (last && state.chain?.digest !== digestOf(last.checkpoint) && (!state.chain || last.seq > state.chain.seq)) {
      state.chain = { seq: last.seq, digest: digestOf(last.checkpoint), head_hash: last.checkpoint.records.head_hash, created_at: last.checkpoint.created_at, at: last.meta.end ?? null };
    }

    // 1. Queued stamps, oldest first, each on its own backoff; one covered by a later stamp is done.
    markCovered(all);
    let retried = 0;
    for (const c of all) {
      if (retried >= MAX_RETRIES_PER_TICK) break;
      if (!isQueued(c)) continue;
      if (!o.force && c.meta.next_try_at && Date.parse(c.meta.next_try_at) > now().getTime()) continue;
      c.stamps = await stampAll(c, providers, false, { now, timeoutMs: o.timeoutMs });
      retried++;
      c.meta.attempts += 1;
      c.meta.next_try_at = isStamped(c) ? null : new Date(now().getTime() + RETRY_MIN[Math.min(c.meta.attempts - 1, RETRY_MIN.length - 1)] * 60_000).toISOString();
      writeJson(join(c.dir, "meta.json"), c.meta);
    }

    // 2. This hour's checkpoint.
    const t = now();
    const doneThisHour = !!state.chain && hourKey(new Date(state.chain.created_at)) === hourKey(t);
    const due = o.force || (t >= slotOf(t, cfg.slot_seconds) && !doneThisHour);
    if (!due) {
      report = { action: "not-due", detail: `next checkpoint after ${nextSlot(t, cfg, state.chain).toISOString().slice(11, 16)}Z` };
    } else {
      // [LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD]: the cheap test first, before code or window.
      const head = liveHeadHash();
      const grew = head === null || (head !== ZERO && head !== state.chain?.head_hash);
      if (!grew) {
        report = { action: "quiet", detail: "no new record since the last checkpoint: nothing to stamp" };
      } else {
        const code = cfg.code ? await codeLeaves({ cacheDir: manifestsDir() }) : null;
        const w = readWindow({ hash: state.chain?.head_hash ?? ZERO, at: state.chain?.at ?? undefined });
        if (w.kind === "busy") {
          report = { action: "busy", detail: "a rotation of the audit log is running; the checkpoint waits a minute" };
          state.next_due = new Date(t.getTime() + 60_000).toISOString();
        } else if (w.kind === "lost") {
          state.lost = w.detail;
          report = { action: "lost", detail: w.detail };
        } else if (w.kind === "empty") {
          state.lost = null;
          report = { action: "quiet", detail: "no new record since the last checkpoint: nothing to stamp" };
        } else {
          state.lost = null;
          const createdAt = isoSecond(now());
          const repos = code && code.leaves.length > 0 ? code.leaves.length : 0;
          const cp = makeCheckpoint(w.window, {
            created_at: createdAt,
            prev: state.chain?.digest ?? ZERO,
            clientVersion: o.clientVersion ?? readPackageVersion(),
            code: repos > 0 ? { repos, code_root: codeRootOf(code!.leaves) } : undefined,
          });
          const problems = checkpointProblems(cp, canonBytes(cp).length);
          if (problems.length > 0) throw new Error(`the checkpoint would be refused (${problems.join("; ")}); nothing was kept`);
          const digest = digestOf(cp);
          const seq = Math.max(state.chain?.seq ?? 0, last?.seq ?? 0) + 1;
          const name = `${String(seq).padStart(6, "0")}-${digest.slice(0, 12)}`;
          const tmp = join(checkpointsDir(), `.tmp-${name}`);
          mkdirSync(tmp, { recursive: true });
          writeJson(join(tmp, "checkpoint.json"), cp);
          if (code) writeJson(join(tmp, "code-leaves.json"), code.leaves);
          const meta: CheckpointMeta = {
            seq, digest, created_at: createdAt, first_ts: w.window.firstTs, last_ts: w.window.lastTs, end: w.window.end,
            code: code ? { repos, skipped: code.skipped } : null, attempts: 1, next_try_at: null,
          };
          writeJson(join(tmp, "meta.json"), meta);
          writeJson(join(tmp, "stamps.json"), {});
          const dir = join(checkpointsDir(), name);
          renameSync(tmp, dir);
          state.chain = { seq, digest, head_hash: cp.records.head_hash, created_at: createdAt, at: w.window.end };
          state.code = code ? { repos, skipped: code.skipped.length } : null;
          writeState(state); // the chain moved: saved before any network call
          const stamps = await stampAll({ dir, checkpoint: cp, stamps: {} }, providers, true, { now, timeoutMs: o.timeoutMs });
          if (!Object.values(stamps).some((s) => s.ok)) {
            meta.next_try_at = new Date(now().getTime() + RETRY_MIN[0] * 60_000).toISOString();
            writeJson(join(dir, "meta.json"), meta);
          }
          const ok = Object.values(stamps).filter((s) => s.ok).map((s) => s.name);
          report = {
            action: "checkpoint",
            checkpoint: name,
            stamped: ok,
            detail: ok.length > 0
              ? `checkpoint ${seq} (${cp.records.count} record(s)${repos ? `, ${repos} repositor${repos === 1 ? "y" : "ies"}` : ""}) stamped by ${ok.join(" and ")}`
              : `checkpoint ${seq} made, not stamped yet: ${lastError(stamps) ?? "no service answered"} (queued)`,
          };
        }
      }
    }
    if (retried > 0) report.retried = retried;

    all = listCheckpoints();
    markCovered(all);
    summarize(state, all);
    if (cfg.copy_dir) state.copy = copyOffMachine(cfg, now());
    const t2 = now();
    const retries = all.filter((c) => isQueued(c) && c.meta.next_try_at).map((c) => Date.parse(c.meta.next_try_at!));
    const slot = nextSlot(t2, cfg, state.chain).getTime();
    if (report.action !== "busy") state.next_due = new Date(Math.min(slot, ...retries)).toISOString();
    state.last_tick = { at: t2.toISOString(), action: report.action, detail: report.detail };
    writeState(state);
    return report;
  } catch (e) {
    state.last_tick = { at: now().toISOString(), action: "error", detail: (e as Error).message.slice(0, 300) };
    state.next_due = new Date(now().getTime() + ERROR_BACKOFF_MS).toISOString(); // not a restart every 5 minutes
    try { writeState(state); } catch { /* the report says it */ }
    return { action: "error", detail: (e as Error).message };
  } finally {
    release();
  }
}


// ---------- what every surface says ----------

export interface AnchorHealth {
  enabled: boolean;
  code: boolean;
  repos: number | null;
  lastStampAt: string | null;
  queued: number;
  lost: string | null;
  /** The live log holds records no checkpoint covers yet (normal until the next slot). */
  pending: boolean | null;
  lastTickAt: string | null;
  nextDue: string | null;
  copy: { dir: string; at: string | null; error: string | null } | null;
  /** Why the chain is not stamped as it should be; null when it is (or when SealHour is off). */
  problem: string | null;
  /** One line, in the words of contract section 10. */
  line: string;
}

const hhmm = (iso: string) => `${iso.slice(11, 16)}Z`;
function ago(iso: string, now: Date): string {
  const m = Math.max(0, Math.round((now.getTime() - Date.parse(iso)) / 60_000));
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`;
}

/** The SealHour line for status, fleet health and end_session. Reads two small files and the log's
 *  last line; never the checkpoints folder. [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED] */
export function anchorHealth(now = new Date()): AnchorHealth {
  const cfg = readConfig();
  const off: AnchorHealth = { enabled: false, code: false, repos: null, lastStampAt: null, queued: 0, lost: null, pending: null, lastTickAt: null, nextDue: null, copy: null, problem: null, line: "SealHour: off (contextengine anchor enable)" };
  if (!cfg || !cfg.enabled) return off;
  const s = readState();
  const head = liveHeadHash();
  const pending = head === null ? null : head !== ZERO && head !== s.chain?.head_hash;
  const repos = cfg.code ? (s.code?.repos ?? null) : null;
  const what = cfg.code ? (repos ? `chain + ${repos} repo${repos === 1 ? "" : "s"}` : "chain + code") : "chain only";
  const since = s.last_stamped ? `not stamped since ${hhmm(s.last_stamped.created_at)}` : "not stamped yet";
  let problem: string | null = null;
  if (s.lost) problem = `${since}: the last stamped record is gone from the audit log (run contextengine audit-verify)`;
  else if (s.queued.length > 0) {
    // Everything older than a stamped checkpoint is covered by it (markCovered), so the queue always
    // holds the newest checkpoint: "not stamped since" the last stamp is exact.
    const n = s.queued.length;
    problem = `${since}: ${s.queued[n - 1].error ?? "no time stamp service answered"} (${n} checkpoint${n === 1 ? "" : "s"} queued)`;
  }
  else if (pending && now.getTime() - Date.parse(s.last_tick?.at ?? cfg.enabled_at ?? now.toISOString()) > JOB_STALE_MS) {
    problem = `${since}: the hourly job has not run ${s.last_tick ? `since ${hhmm(s.last_tick.at)}` : "yet"} (it runs in the OpsContext server; contextengine anchor tick runs it by hand)`;
  } else if (s.last_tick?.action === "error") problem = `${since}: the hourly job failed: ${s.last_tick.detail}`;
  const copy = cfg.copy_dir ? { dir: cfg.copy_dir, at: s.copy?.at ?? null, error: s.copy?.error ?? null } : null;
  let line: string;
  if (problem) line = `SealHour interim: on, ${problem}`;
  else {
    const stamp = s.last_stamped
      ? `last stamp ${ago(s.last_stamped.created_at, now)} by ${s.last_stamped.ok} of ${s.last_stamped.total} free services${s.last_stamped.failed.length ? ` (${s.last_stamped.failed.join(", ")} did not answer)` : ""}`
      : "no stamp yet";
    const next = s.next_due ? `, next after ${hhmm(s.next_due)}` : "";
    const quiet = s.last_stamped && pending === false ? ", nothing new since" : "";
    line = `SealHour interim: on (${what}), ${stamp}${quiet}${next}`;
  }
  line += copy
    ? copy.error ? `; copy off this machine FAILED (${copy.error})` : copy.at ? `; copied off this machine ${ago(copy.at, now)}` : "; not copied off this machine yet"
    : "; no copy off this machine (contextengine anchor copy <folder>)";
  return { enabled: true, code: cfg.code, repos, lastStampAt: s.last_stamped?.created_at ?? null, queued: s.queued.length, lost: s.lost, pending, lastTickAt: s.last_tick?.at ?? null, nextDue: s.next_due, copy, problem, line };
}

/** Should the indexing server start the hourly job now? Cheap: two small files. */
export function anchorTickDue(now = new Date()): boolean {
  const cfg = readConfig();
  if (!cfg || !cfg.enabled || !cfg.consent) return false;
  const s = readState();
  return !s.next_due || Date.parse(s.next_due) <= now.getTime();
}

/** Whether the repository holding `dir` requires the chain to be stamped (policy.json `anchoring`). */
export function anchoringPolicy(dir = process.cwd()): { required: boolean; where: string | null; error: string | null } {
  const found = findRepoPolicy(dir);
  if (!found) return { required: false, where: null, error: null };
  const where = join(found.root, ".contextengine", "policy.json");
  if (!found.result.ok) return { required: false, where, error: "the policy file does not validate (contextengine policy validate)" };
  return { required: !!found.result.policy.anchoring?.required, where, error: null };
}
