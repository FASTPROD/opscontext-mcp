// The SealHour client (COMPR-TSA docs/SEALHOUR_PROTOCOL.md; plan docs/SEALHOUR_INTEGRATION_PLAN.md
// section 6, steps 1 and 3): once an hour, when the audit log grew, a checkpoint of the chain (and of the
// workspaces' code when the owner said yes), kept in ~/.contextengine/anchors/, then dated by the backend
// the owner said yes to: the SealHour service (src/anchor-seal.ts, src/anchor-service.ts: a signed
// receipt, the hour sealed with an official European stamp, Bitcoin), or the interim backend
// (src/anchor-tsa.ts: a direct stamp from free public services, contract section 7.3).
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
//      "off" before touching anything else unless that consent is on disk AND names the backend in
//      use; it stamps only with the providers the consent names, and sends to the SealHour service
//      only the credential kind it names (2026-10-05: a yes to the interim screen is not a yes to the
//      service, which receives the checkpoint and the licence key; moving asks again).
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
import { activeService, serviceName, type Service } from "./anchor-service.js";
import { cutoffOf, fetchDueProofs, newSealMeta, sealCredential, sendQueued, type Hold, type SealCheckpoint, type SealCredential, type SealMeta } from "./anchor-seal.js";
import { BUNDLE_NAME } from "./anchor-bundle.js";

/** 1: the interim screen of step 1. 2: the SealHour service's screen, and the interim one that names it (2026-10-05). */
export const ANCHOR_SCREEN_VERSION = 2;
/** Who dates the checkpoints: the SealHour service, or free public time stamp services asked directly. */
export type Backend = "rfc3161" | "sealhour";
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
  backend: Backend;
  /** Seconds past each hour at which this machine's checkpoint is due. */
  slot_seconds: number;
  /** Random, names this machine's folder in the copy off the machine. */
  machine: string;
  /** The owner's yes, as given on the enable screen. [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] */
  consent: { at: string; screen: number; backend: Backend; providers: string[]; /** SealHour only: what the screen said is sent. */ credential?: "licence" | "pilot" } | null;
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
  /** SealHour: the newest sealed checkpoint. `at` is its hour's stamp time, or the hour's cut-off without one. */
  last_sealed?: { seq: number; created_at: string; hour: string | null; at: string; stamp_checked: boolean | null; bitcoin: string | null } | null;
  /** SealHour: received (receipt stored), their hour not sealed yet. */
  waiting?: Array<{ seq: number; hour: string | null; note: string | null }>;
  /** SealHour: refused for themselves or their hour missed, and no later seal covers them yet. */
  undated?: Array<{ seq: number; created_at: string; error: string | null }>;
  /** SealHour: the queue waits until then (the service was away, said to wait, or refused the credential). */
  hold?: Hold | null;
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
  /** The backend that was on when it was made (absent: the interim one, the only one before 2026-10-05). */
  backend?: Backend;
  /** SealHour: where it stands at the service. [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts) */
  seal?: SealMeta | null;
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

const emptyState = (): AnchorState => ({ chain: null, lost: null, last_tick: null, next_due: null, last_stamped: null, queued: [], code: null, copy: null, last_sealed: null, waiting: [], undated: [], hold: null });

export function readState(): AnchorState {
  return { ...emptyState(), ...(readJson<AnchorState>(statePath()) ?? {}) };
}

export function writeState(s: AnchorState): void {
  mkdirSync(anchorsDir(), { recursive: true, mode: 0o700 });
  writeJson(statePath(), s);
}

/** A new configuration for the enable screen's yes: a random slot and machine id. The backend is the
 *  one the screen named; `credential` (SealHour only) is what that screen said is sent. */
export function newConfig(o: { code: boolean; providers: string[]; now: Date; rand?: (min: number, max: number) => number; backend?: Backend; credential?: "licence" | "pilot" }): AnchorConfig {
  const rand = o.rand ?? ((min: number, max: number) => randomInt(min, max));
  const at = o.now.toISOString();
  const backend = o.backend ?? "rfc3161";
  return {
    version: 1,
    enabled: true,
    code: o.code,
    backend,
    slot_seconds: rand(SLOT_MIN_S, SLOT_MAX_S),
    machine: randomBytes(4).toString("hex"),
    consent: { at, screen: ANCHOR_SCREEN_VERSION, backend, providers: o.providers, ...(backend === "sealhour" ? { credential: o.credential ?? "licence" } : {}) },
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

export const backendOf = (c: { meta: CheckpointMeta }): Backend => c.meta.backend ?? "rfc3161";
/** Its hour's proof is stored here and holds. [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts) */
export const isSealed = (c: { meta: CheckpointMeta }): boolean => backendOf(c) === "sealhour" && c.meta.seal?.state === "sealed";
/** Dated by an outside witness of its own: a direct stamp, or a sealed hour. */
export const isDated = (c: { meta: CheckpointMeta; stamps: Record<string, StampEntry> }): boolean => isStamped(c) || isSealed(c);
/** When a sealed checkpoint's hour was sealed: its stamp's time, or the hour's cut-off without one. */
export const sealTime = (c: { meta: CheckpointMeta }): string | null =>
  c.meta.seal?.stamp?.time ?? (c.meta.seal?.hour ? cutoffOf(c.meta.seal.hour).toISOString() : null);
const dateOf = (c: StoredCheckpoint): string | null => (isSealed(c) ? sealTime(c) : firstStampTime(c));
/** Sent or about to be, with the backend in use: it will get, or be refused, a seal of its own. */
const onItsWay = (c: StoredCheckpoint, current: Backend): boolean =>
  current === "sealhour" && backendOf(c) === "sealhour" && (c.meta.seal?.state === "queued" || c.meta.seal?.state === "received");

/**
 * Mark every checkpoint without a date of its own that a later dated checkpoint covers: the earliest
 * later stamped or sealed one whose chain reaches back to it unbroken. Written to its meta.json. A
 * checkpoint still on its way to SealHour is left alone: it is sent in its turn, so the service keeps
 * every checkpoint of the log (workplan 2, correction 1), and its hour dates it.
 * [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED]
 */
function markCovered(all: StoredCheckpoint[], current: Backend): void {
  for (let i = 0; i < all.length; i++) {
    const c = all[i];
    if (isDated(c) || c.meta.covered_by || onItsWay(c, current)) continue;
    for (let j = i + 1; j < all.length; j++) {
      if (all[j].checkpoint.prev_checkpoint_digest !== digestOf(all[j - 1].checkpoint)) break; // the chain breaks: nothing later covers it
      if (isDated(all[j])) {
        c.meta.covered_by = { seq: all[j].seq, name: all[j].name, time: dateOf(all[j]) };
        c.meta.next_try_at = null;
        writeJson(join(c.dir, "meta.json"), c.meta);
        break;
      }
    }
  }
}

/** Not dated, and nothing later dates it: retried by its own backend while that backend is in use. */
const isQueued = (c: StoredCheckpoint): boolean =>
  backendOf(c) === "sealhour" ? c.meta.seal?.state === "queued" && !c.meta.covered_by : !isStamped(c) && !c.meta.covered_by;

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
  /** SealHour: the checkpoints the service gave a receipt for in this run, and those newly sealed. */
  received?: number[];
  sealed?: number[];
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
  const sealed = [...all].reverse().find(isSealed);
  state.last_sealed = sealed
    ? { seq: sealed.seq, created_at: sealed.checkpoint.created_at, hour: sealed.meta.seal!.hour, at: sealTime(sealed) ?? sealed.checkpoint.created_at, stamp_checked: sealed.meta.seal!.stamp ? sealed.meta.seal!.stamp.checked : null, bitcoin: sealed.meta.seal!.bitcoin }
    : null;
  state.waiting = all.filter((c) => backendOf(c) === "sealhour" && c.meta.seal?.state === "received").map((c) => ({ seq: c.seq, hour: c.meta.seal!.hour, note: c.meta.seal!.error ?? c.meta.seal!.waiting }));
  state.undated = all
    .filter((c) => backendOf(c) === "sealhour" && (c.meta.seal?.state === "refused" || c.meta.seal?.state === "missed") && !c.meta.covered_by)
    .map((c) => ({ seq: c.seq, created_at: c.checkpoint.created_at, error: c.meta.seal!.error }));
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
  state.queued = all.filter(isQueued).map((c) => ({ seq: c.seq, created_at: c.checkpoint.created_at, error: backendOf(c) === "sealhour" ? (c.meta.seal?.error ?? null) : lastError(c.stamps) }));
}

// [LOCKED] [SEALHOUR-COPY-WRITES-ONLY-WHAT-CHANGED] - 2026-10-02
// [NEVER] write a file into the copy folder again when the copy there is already current, and
//         [NEVER] read the copy's content to decide it: compare the two files' sizes and times only.
// WHY: 2026-10-02, once the launchd agent ran Node 24, macOS refused that new program access to the
//      files Google Drive manages (privacy database: kTCCServiceFileProviderDomain, the Node 24 path
//      denied at 14:24:38 UTC, the Node 20 path allowed since 2026-10-01). New files could still be
//      created there, so every new checkpoint reached the folder, but the two certificates were
//      written again every hour and the first rewrite failed ("EPERM ... copyfile"): the status said
//      the copy FAILED at 14:24 and 15:24 while nothing was missing, and before that every hour
//      uploaded two unchanged files. Reading the copy to compare would make the provider fetch it,
//      the very access that was refused.
// FIX: one rule for every file, checkpoints and certificates alike: copy when the copy is missing,
//      has another size, or is older than the source; otherwise leave it alone. A file that really
//      changed and cannot be written is still reported as a failed copy.
function copyIfChanged(src: string, dst: string): void {
  const a = statSync(src);
  let same = false;
  try { const b = statSync(dst); same = b.size === a.size && b.mtimeMs >= a.mtimeMs; } catch { same = false; }
  if (!same) copyFileSync(src, dst);
}

/** Copy the checkpoints, their stamps, their SealHour receipts and proofs (never the code leaves or meta.json:
 *  they can name repositories; never the pilot code) to the owner's folder off this machine, file by
 *  file, only what is new or changed. Correction 1 of workplan 2.
 *  [LOCK] [SEALHOUR-COPY-WRITES-ONLY-WHAT-CHANGED] */
export function copyOffMachine(cfg: AnchorConfig, now: Date): { at: string | null; error: string | null } {
  if (!cfg.copy_dir) return { at: null, error: null };
  if (!existsSync(cfg.copy_dir)) return { at: null, error: `the folder ${cfg.copy_dir} is not there (not mounted?)` };
  const dest = join(cfg.copy_dir, `opscontext-anchors-${cfg.machine}`);
  try {
    for (const c of listCheckpoints()) {
      const to = join(dest, "checkpoints", c.name);
      mkdirSync(to, { recursive: true });
      for (const f of readdirSync(c.dir)) {
        if (!/^(checkpoint\.json|stamps\.json|receipt\.json|checkpoint\.[a-z0-9-]+\.ts[qr])$/.test(f)) continue;
        copyIfChanged(join(c.dir, f), join(to, f));
      }
      // The proof as SealHour served it, under the contract's names only.
      const proof = join(c.dir, "proof");
      if (existsSync(proof)) {
        for (const e of readdirSync(proof, { withFileTypes: true })) {
          const names = e.isDirectory() ? readdirSync(join(proof, e.name)).map((f) => `${e.name}/${f}`) : [e.name];
          for (const n of names) {
            if (!BUNDLE_NAME.test(n)) continue;
            mkdirSync(join(to, "proof", e.isDirectory() ? e.name : ""), { recursive: true });
            copyIfChanged(join(proof, n), join(to, "proof", n));
          }
        }
      }
    }
    if (existsSync(certsDir())) {
      mkdirSync(join(dest, "certs"), { recursive: true });
      for (const f of readdirSync(certsDir())) if (f.endsWith(".pem")) copyIfChanged(join(certsDir(), f), join(dest, "certs", f));
    }
    return { at: now.toISOString(), error: null };
  } catch (e) {
    return { at: null, error: (e as Error).message.slice(0, 200) };
  }
}

/**
 * The hourly job: when this hour's slot has passed, this hour has no checkpoint yet and the log grew,
 * make a checkpoint; have it dated by the backend the owner said yes to (queued stamps retried and the
 * new one stamped by the free services, or the queue sent to SealHour and the proofs of sealed hours
 * fetched); then copy off the machine. Runs in its own process (`contextengine anchor tick`), started
 * by the indexing server.
 */
export async function anchorTick(o: { now?: () => Date; force?: boolean; timeoutMs?: number; clientVersion?: string; sleep?: (ms: number) => Promise<void> } = {}): Promise<TickReport> {
  const now = o.now ?? (() => new Date());
  const cfg = readConfig();
  // [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE]: nothing is read, written or sent without the owner's yes
  // to the backend in use.
  if (!cfg || !cfg.enabled || !cfg.consent || cfg.consent.backend !== cfg.backend || (cfg.backend !== "rfc3161" && cfg.backend !== "sealhour")) {
    return { action: "off", detail: "SealHour is off on this machine" };
  }
  const interim = cfg.backend === "rfc3161";
  const providers = interim ? consentedProviders(cfg) : [];
  if (interim && providers.length === 0) return { action: "off", detail: "no time stamp service this machine said yes to is in use: run contextengine anchor enable" };
  const service: Service | null = interim ? null : activeService();
  const who = service ? serviceName(service) : "";

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

    // 1. Interim: queued stamps, oldest first, each on its own backoff; one covered by a later stamp is done.
    markCovered(all, cfg.backend);
    let retried = 0;
    if (interim) {
      for (const c of all) {
        if (retried >= MAX_RETRIES_PER_TICK) break;
        if (backendOf(c) !== "rfc3161" || !isQueued(c)) continue;
        if (!o.force && c.meta.next_try_at && Date.parse(c.meta.next_try_at) > now().getTime()) continue;
        c.stamps = await stampAll(c, providers, false, { now, timeoutMs: o.timeoutMs });
        retried++;
        c.meta.attempts += 1;
        c.meta.next_try_at = isStamped(c) ? null : new Date(now().getTime() + RETRY_MIN[Math.min(c.meta.attempts - 1, RETRY_MIN.length - 1)] * 60_000).toISOString();
        writeJson(join(c.dir, "meta.json"), c.meta);
      }
    }

    // 2. This hour's checkpoint.
    const t = now();
    const doneThisHour = !!state.chain && hourKey(new Date(state.chain.created_at)) === hourKey(t);
    const due = o.force || (t >= slotOf(t, cfg.slot_seconds) && !doneThisHour);
    let made: { seq: number; count: number; repos: number } | null = null;
    if (!due) {
      report = { action: "not-due", detail: `next checkpoint after ${nextSlot(t, cfg, state.chain).toISOString().slice(11, 16)}Z` };
    } else {
      // [LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD]: the cheap test first, before code or window.
      const head = liveHeadHash();
      const grew = head === null || (head !== ZERO && head !== state.chain?.head_hash);
      const nothing = interim ? "no new record since the last checkpoint: nothing to stamp" : "no new record since the last checkpoint: nothing to seal";
      if (!grew) {
        report = { action: "quiet", detail: nothing };
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
          report = { action: "quiet", detail: nothing };
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
            code: code ? { repos, skipped: code.skipped } : null, attempts: interim ? 1 : 0, next_try_at: null,
            backend: cfg.backend, ...(interim ? {} : { seal: newSealMeta() }),
          };
          writeJson(join(tmp, "meta.json"), meta);
          writeJson(join(tmp, "stamps.json"), {});
          const dir = join(checkpointsDir(), name);
          renameSync(tmp, dir);
          state.chain = { seq, digest, head_hash: cp.records.head_hash, created_at: createdAt, at: w.window.end };
          state.code = code ? { repos, skipped: code.skipped.length } : null;
          writeState(state); // the chain moved: saved before any network call
          made = { seq, count: cp.records.count, repos };
          if (interim) {
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
          } else {
            report = { action: "checkpoint", checkpoint: name, detail: "" };
          }
        }
      }
    }
    if (retried > 0) report.retried = retried;

    // 3. SealHour: the queue, oldest first, then the proofs of the hours sealed since.
    // [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts)
    if (service) {
      all = listCheckpoints();
      const mine = all.filter((c) => backendOf(c) === "sealhour") as Array<StoredCheckpoint & SealCheckpoint>;
      const cred: SealCredential = sealCredential(cfg.consent.credential);
      let trouble: string | null = null;
      if ("problem" in cred) {
        trouble = cred.problem;
      } else {
        const sent = await sendQueued(mine, service, cred.credential, { now, hold: state.hold ?? null, force: o.force, timeoutMs: o.timeoutMs, sleep: o.sleep });
        state.hold = sent.hold;
        if (sent.received.length > 0) report.received = sent.received;
        trouble = sent.hold?.line ?? null;
      }
      const sealedNow = await fetchDueProofs(mine, service, { now, force: o.force, timeoutMs: o.timeoutMs });
      if (sealedNow.length > 0) report.sealed = sealedNow;
      const notes: string[] = [];
      if (made) {
        const m = mine.find((c) => c.seq === made!.seq);
        const what = `checkpoint ${made.seq} (${made.count} record(s)${made.repos ? `, ${made.repos} repositor${made.repos === 1 ? "y" : "ies"}` : ""})`;
        const st = m?.meta.seal;
        if (st?.state === "received" || st?.state === "sealed") notes.push(`${what} received by ${who}, receipt ok; its hour ${st.hour} is sealed at ${cutoffOf(st.hour ?? "").toISOString().slice(11, 16)}Z`);
        else if (st?.state === "refused") notes.push(`${what} made; ${st.error}`);
        else notes.push(`${what} made, not sent yet: ${trouble ?? st?.error ?? `${who} did not answer`} (queued)`);
      } else if (trouble && mine.some((c) => c.meta.seal?.state === "queued")) {
        notes.push(`${mine.filter((c) => c.meta.seal?.state === "queued").length} checkpoint(s) queued: ${trouble}`);
      }
      const others = (report.received ?? []).filter((n) => n !== made?.seq);
      if (others.length > 0) notes.push(`${others.length} queued checkpoint(s) received by ${who}`);
      if (sealedNow.length > 0) notes.push(`checkpoint(s) #${sealedNow.join(", #")} sealed: proof kept and checked`);
      if (notes.length > 0) report.detail = [report.detail, ...notes].filter(Boolean).join("; ");
    }

    all = listCheckpoints();
    markCovered(all, cfg.backend);
    summarize(state, all);
    if (cfg.copy_dir) state.copy = copyOffMachine(cfg, now());
    const t2 = now();
    const times = all.filter((c) => backendOf(c) === "rfc3161" && interim && isQueued(c) && c.meta.next_try_at).map((c) => Date.parse(c.meta.next_try_at!));
    if (service) {
      // The queue when its hold ends; each received checkpoint when its hour's proof can be asked.
      if (state.hold && all.some((c) => backendOf(c) === "sealhour" && isQueued(c))) times.push(Date.parse(state.hold.until));
      for (const c of all) if (backendOf(c) === "sealhour" && c.meta.seal?.state === "received" && c.meta.seal.proof_next_at) times.push(Date.parse(c.meta.seal.proof_next_at));
    }
    const slot = nextSlot(t2, cfg, state.chain).getTime();
    if (report.action !== "busy") state.next_due = new Date(Math.min(slot, ...times.filter((x) => Number.isFinite(x)))).toISOString();
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
  /** Who dates the checkpoints on this machine; null when SealHour is off. */
  backend: Backend | null;
  code: boolean;
  repos: number | null;
  /** Interim: the newest stamped checkpoint's time. SealHour: when the newest sealed checkpoint's hour was sealed. */
  lastStampAt: string | null;
  queued: number;
  lost: string | null;
  /** The live log holds records no checkpoint covers yet (normal until the next slot). */
  pending: boolean | null;
  lastTickAt: string | null;
  nextDue: string | null;
  copy: { dir: string; at: string | null; error: string | null } | null;
  /** Why the chain is not stamped or sealed as it should be; null when it is (or when SealHour is off). */
  problem: string | null;
  /** One line, in the words of contract section 10. */
  line: string;
}

const hhmm = (iso: string) => `${iso.slice(11, 16)}Z`;
/** A time of today as 14:02Z, an older one with its day. */
const when = (iso: string, now: Date) => (now.getTime() - Date.parse(iso) < 20 * 3_600_000 ? hhmm(iso) : `${iso.slice(0, 10)} ${hhmm(iso)}`);
function ago(iso: string, now: Date): string {
  const m = Math.max(0, Math.round((now.getTime() - Date.parse(iso)) / 60_000));
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`;
}
/** A received checkpoint whose hour is still not sealed this long after its cut-off is a problem. */
const SEAL_LATE_MS = 75 * 60_000;

/** The SealHour line for status, fleet health, audit-verify and end_session. Reads two small files, the
 *  log's last line and, for the SealHour backend, the credential; never the checkpoints folder.
 *  [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED] [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts) */
export function anchorHealth(now = new Date()): AnchorHealth {
  const cfg = readConfig();
  const off: AnchorHealth = { enabled: false, backend: null, code: false, repos: null, lastStampAt: null, queued: 0, lost: null, pending: null, lastTickAt: null, nextDue: null, copy: null, problem: null, line: "SealHour: off (contextengine anchor enable)" };
  if (!cfg || !cfg.enabled) return off;
  const s = readState();
  const head = liveHeadHash();
  const pending = head === null ? null : head !== ZERO && head !== s.chain?.head_hash;
  const repos = cfg.code ? (s.code?.repos ?? null) : null;
  const what = cfg.code ? (repos ? `chain + ${repos} repo${repos === 1 ? "" : "s"}` : "chain + code") : "chain only";
  const copy = cfg.copy_dir ? { dir: cfg.copy_dir, at: s.copy?.at ?? null, error: s.copy?.error ?? null } : null;
  const sealing = cfg.backend === "sealhour";
  const jobLate = pending && now.getTime() - Date.parse(s.last_tick?.at ?? cfg.enabled_at ?? now.toISOString()) > JOB_STALE_MS;
  const jobLine = `the hourly job has not run ${s.last_tick ? `since ${hhmm(s.last_tick.at)}` : "yet"} (it runs in the OpsContext server; contextengine anchor tick runs it by hand)`;
  let problem: string | null = null;
  let line: string;
  let lastAt: string | null;
  if (!sealing) {
    lastAt = s.last_stamped?.created_at ?? null;
    const since = s.last_stamped ? `not stamped since ${hhmm(s.last_stamped.created_at)}` : "not stamped yet";
    if (s.lost) problem = `${since}: the last stamped record is gone from the audit log (run contextengine audit-verify)`;
    else if (s.queued.length > 0) {
      // Everything older than a stamped checkpoint is covered by it (markCovered), so the queue always
      // holds the newest checkpoint: "not stamped since" the last stamp is exact.
      const n = s.queued.length;
      problem = `${since}: ${s.queued[n - 1].error ?? "no time stamp service answered"} (${n} checkpoint${n === 1 ? "" : "s"} queued)`;
    }
    else if (jobLate) problem = `${since}: ${jobLine}`;
    else if (s.last_tick?.action === "error") problem = `${since}: the hourly job failed: ${s.last_tick.detail}`;
    if (problem) line = `SealHour interim: on, ${problem}`;
    else {
      const stamp = s.last_stamped
        ? `last stamp ${ago(s.last_stamped.created_at, now)} by ${s.last_stamped.ok} of ${s.last_stamped.total} free services${s.last_stamped.failed.length ? ` (${s.last_stamped.failed.join(", ")} did not answer)` : ""}`
        : "no stamp yet";
      const next = s.next_due ? `, next after ${hhmm(s.next_due)}` : "";
      const quiet = s.last_stamped && pending === false ? ", nothing new since" : "";
      line = `SealHour interim: on (${what}), ${stamp}${quiet}${next}`;
    }
  } else {
    // The SealHour service. "Sealed" is said of a checkpoint whose hour's proof is kept here and holds,
    // and of nothing else. [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts)
    let who = "SealHour";
    try { who = serviceName(activeService()); } catch { who = "SealHour TEST stand-in (its settings cannot be read)"; }
    const last = s.last_sealed ?? null;
    lastAt = last?.at ?? null;
    const since = last ? `not sealed since ${when(last.at, now)}` : "not sealed yet";
    const queued = s.queued.length;
    const waiting = s.waiting ?? [];
    const undated = s.undated ?? [];
    const cred = cfg.consent?.backend === "sealhour" ? sealCredential(cfg.consent.credential) : { problem: "the owner's yes to the SealHour service is not recorded (contextengine anchor enable)" };
    const late = waiting.find((w) => w.hour && now.getTime() - cutoffOf(w.hour).getTime() > SEAL_LATE_MS);
    const n = `(${queued} checkpoint${queued === 1 ? "" : "s"} queued)`;
    if (s.lost) problem = `${since}: the last sealed record is gone from the audit log (run contextengine audit-verify)`;
    else if ("problem" in cred) problem = `${since}: ${cred.problem}${queued ? ` ${n}` : ""}`;
    else if (queued > 0) problem = `${since}: ${s.hold?.line ?? s.queued[queued - 1].error ?? `${who} did not answer`} ${n}`;
    else if (undated.length > 0) problem = `${since}: checkpoint #${undated[undated.length - 1].seq} has no seal of its own (${undated[undated.length - 1].error ?? "refused"}); the next sealed checkpoint dates it`;
    else if (late) problem = `${since}: the hour ${late.hour} is still not sealed at ${who}${late.note ? ` (${late.note})` : ""}`;
    else if (jobLate) problem = `${since}: ${jobLine}`;
    else if (s.last_tick?.action === "error") problem = `${since}: the hourly job failed: ${s.last_tick.detail}`;
    if (problem) line = `${who}: on, ${problem}`;
    else {
      const note = !last ? "" : last.stamp_checked === true ? "" : last.stamp_checked === false ? " (its official stamp could not be checked on this machine)" : " (that hour has no official stamp yet)";
      const seal = last ? `last seal ${ago(last.at, now)}${note}, receipt ok` : "no seal yet";
      const next = waiting.length > 0 && waiting[0].hour
        ? `, ${waiting.length} checkpoint${waiting.length === 1 ? "" : "s"} received (receipt ok), next seal at ${hhmm(cutoffOf(waiting[waiting.length - 1].hour ?? waiting[0].hour).toISOString())}`
        : `${last && pending === false ? ", nothing new since" : ""}${s.next_due ? `, next checkpoint after ${hhmm(s.next_due)}` : ""}`;
      line = `${who}: on (${what}), ${seal}${next}`;
    }
  }
  line += copy
    ? copy.error ? `; copy off this machine FAILED (${copy.error})` : copy.at ? `; copied off this machine ${ago(copy.at, now)}` : "; not copied off this machine yet"
    : "; no copy off this machine (contextengine anchor copy <folder>)";
  return { enabled: true, backend: cfg.backend, code: cfg.code, repos, lastStampAt: lastAt, queued: s.queued.length, lost: s.lost, pending, lastTickAt: s.last_tick?.at ?? null, nextDue: s.next_due, copy, problem, line };
}

/** Should the indexing server start the hourly job now? Cheap: two small files. */
export function anchorTickDue(now = new Date()): boolean {
  const cfg = readConfig();
  if (!cfg || !cfg.enabled || !cfg.consent || cfg.consent.backend !== cfg.backend) return false;
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
