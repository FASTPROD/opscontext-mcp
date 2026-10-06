// The SealHour backend's half of the hourly job (COMPR-TSA docs/SEALHOUR_PROTOCOL.md sections 5 to 7;
// plan docs/SEALHOUR_INTEGRATION_PLAN.md section 6, step 3): the queue of checkpoints to send, the receipt
// checked before it is stored, the proof fetched once the hour is sealed and checked before the
// checkpoint is ever called sealed. Called by anchorTick() (src/anchor.ts) under the anchor lock.
//
// [LOCKED] [NOT-SEALED-IS-NEVER-CALLED-SEALED] - 2026-10-05
// [NEVER] move a checkpoint to "received" without a stored receipt that passed section 6 under a pinned
//         key, or to "sealed" without a stored proof that checkBundle() found included; never replace a
//         stored proof by one that checks less well; never retry a checkpoint the service refused for
//         itself (400, 409) or whose hour it missed (410).
// WHY: the status line is what the owner, fleet health, end-session and a policy gate read. "Sent" is
//      not "received", "received" is not "sealed", and a proof that came is not a proof that holds: each
//      rounding up is the silent failure the product exists to catch (plan section 8,
//      [EXEC-FAILURE-IS-NOT-EMPTY]; the interim rule is [NOT-STAMPED-IS-NEVER-CALLED-STAMPED]). The
//      contract says what never to retry (section 5.1) and that a missed hour is dated by the next
//      checkpoint of the log, at a later date (sections 2.4 and 5.3), in those words on both sides.
// FIX: five states, each entered by one check: queued (made, not received), received (receipt stored),
//      sealed (proof stored and included), missed (410), refused (400 or 409). A trouble of the service
//      or of the credential (no answer, 5xx, 429, 401, 403, an answer that is not a receipt) stops the
//      queue and holds it, for as long as the service says or with a backoff, once a day for a refused
//      credential; the service's line is kept word for word and shown.
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { digestOf, type Checkpoint } from "./anchor-protocol.js";
import { getProof, postCheckpoint, readPilotToken, serviceName, LICENCE_KEY, type Service } from "./anchor-service.js";
import { bundleFiles, checkBundle, writeBundle, type BundleCheck } from "./anchor-bundle.js";
import { quietLicence } from "./activation.js";

/** Trouble with the service is retried after 1, 2, 4, 8, 15, 30, then every 60 minutes. */
const RETRY_MIN = [1, 2, 4, 8, 15, 30, 60];
const DAY_MS = 86_400_000;
/** A run sends this many checkpoints at most (the service takes 60 a minute per credential). */
const MAX_POSTS_PER_TICK = 30;
const MAX_PROOFS_PER_TICK = 12;
/** A proof whose Bitcoin attestation is pending is fetched again this long after the last fetch... */
const REFRESH_AFTER_MS = 3 * 3_600_000;
/** ...two at most per run, and no longer by the hourly job once it is this old (export-evidence --refresh still does). */
const MAX_REFRESH_PER_TICK = 2;
const REFRESH_FOR_MS = 7 * DAY_MS;
/** The seal of an hour takes a few seconds after its minute 2: the proof is first asked this long after. */
const AFTER_CUTOFF_MS = 45_000;

export type SealState = "queued" | "received" | "sealed" | "missed" | "refused";

/** What the SealHour backend knows of one checkpoint; kept in its meta.json. */
export interface SealMeta {
  state: SealState;
  /** Received on the first try after it was made: its received_at then reads this machine's clock. */
  first_try: boolean;
  /** The pseudonym of the credential it was received under (SHA-256 of it; never the credential). */
  customer: string | null;
  hour: string | null;
  received_at: string | null;
  /** The last thing that went wrong, the service's own line word for word when it gave one. */
  error: string | null;
  /** Why the proof was not ready the last time it was asked ("hour not sealed yet", ...). */
  waiting: string | null;
  proof_tries: number;
  proof_next_at: string | null;
  /** The hour's stamp as the stored proof carries it; checked: OpenSSL verified it under a pinned certificate. */
  stamp: { name: string; time: string | null; checked: boolean } | null;
  bitcoin: "complete" | "pending" | "none" | null;
  proof_at: string | null;
}

export const newSealMeta = (): SealMeta => ({
  state: "queued", first_try: false, customer: null, hour: null, received_at: null, error: null, waiting: null,
  proof_tries: 0, proof_next_at: null, stamp: null, bitcoin: null, proof_at: null,
});

/** The queue is held until then: the service was away, said to wait, or refused the credential. */
export interface Hold {
  until: string;
  line: string;
  fails: number;
}

/** One checkpoint as the job holds it (a StoredCheckpoint of src/anchor.ts whose meta carries `seal`). */
export interface SealCheckpoint {
  dir: string;
  seq: number;
  checkpoint: Checkpoint;
  meta: { digest: string; attempts: number; seal?: SealMeta | null };
}

/** The moment an hour is sealed: minute 2 of the hour it is named after (contract section 3.1). */
export function cutoffOf(hour: string): Date {
  return new Date(`${hour.slice(0, 13)}:02:00Z`);
}

function writeJson(path: string, obj: unknown): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  renameSync(tmp, path);
}

const saveMeta = (c: SealCheckpoint): void => writeJson(join(c.dir, "meta.json"), c.meta);
const backoffMs = (fails: number): number => RETRY_MIN[Math.min(Math.max(fails, 1) - 1, RETRY_MIN.length - 1)] * 60_000;
const plus = (now: Date, ms: number): string => new Date(now.getTime() + ms).toISOString();

// ---------- the credential (contract section 4) ----------

export type SealCredential = { credential: string; kind: "licence" | "pilot" } | { problem: string };

/**
 * The credential the owner said yes to on the enable screen: the licence key of this machine, or the
 * pilot code made at enable. Never the other one: a licence activated after a yes given to a pilot code
 * does not start leaving on its own ([LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] in src/anchor-cli.ts).
 * Reads without a word and without a record ([LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD]).
 */
export function sealCredential(kind: "licence" | "pilot" | undefined): SealCredential {
  if (kind === "pilot") {
    const t = readPilotToken();
    return t ? { credential: t, kind: "pilot" } : { problem: "this machine's pilot code is gone from the anchors folder (contextengine anchor enable makes a new one)" };
  }
  const lic = quietLicence();
  if ("problem" in lic) return { problem: `${lic.problem} (contextengine anchor enable asks again)` };
  if (!LICENCE_KEY.test(lic.key)) return { problem: "this machine's licence key is not of the shape SealHour takes (CE- and four groups of four)" };
  return { credential: lic.key, kind: "licence" };
}

// ---------- sending ----------

/**
 * Send the queued checkpoints, oldest first, until one meets a trouble that is not its own.
 * Returns the hold to keep (null when the service took everything it was sent).
 * [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED]
 */
export async function sendQueued(
  queue: SealCheckpoint[],
  service: Service,
  credential: string,
  o: { now: () => Date; hold: Hold | null; force?: boolean; timeoutMs?: number; sleep?: (ms: number) => Promise<void> },
): Promise<{ received: number[]; refused: number[]; hold: Hold | null }> {
  const who = serviceName(service);
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const received: number[] = [];
  const refused: number[] = [];
  let hold = o.hold;
  if (hold && !o.force && Date.parse(hold.until) > o.now().getTime()) return { received, refused, hold };
  let fails = hold?.fails ?? 0;
  let posts = 0;
  for (const c of queue) {
    const seal = c.meta.seal;
    if (!seal || seal.state !== "queued") continue;
    if (posts >= MAX_POSTS_PER_TICK) break;
    posts++;
    const first = c.meta.attempts === 0;
    let r = await postCheckpoint(service, c.checkpoint, credential, { timeoutMs: o.timeoutMs });
    // "The hour is being sealed; try again in a second" (section 3.1): once more, in this run.
    if (r.kind === "later" && r.waitS !== null && r.waitS <= 5) {
      await sleep((r.waitS + 1) * 1000);
      r = await postCheckpoint(service, c.checkpoint, credential, { timeoutMs: o.timeoutMs });
    }
    c.meta.attempts += 1;
    const t = o.now();
    if (r.kind === "receipt") {
      // Stored only now: it passed section 6 under a pinned key. [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY]
      writeJson(join(c.dir, "receipt.json"), r.receipt);
      const due = cutoffOf(r.receipt.hour).getTime() + AFTER_CUTOFF_MS;
      c.meta.seal = { ...seal, state: "received", first_try: first, customer: r.receipt.customer, hour: r.receipt.hour, received_at: r.receipt.received_at, error: null, proof_next_at: new Date(Math.max(due, t.getTime())).toISOString() };
      saveMeta(c);
      received.push(c.seq);
      hold = null;
      fails = 0;
      continue;
    }
    if (r.kind === "refused" && r.retry === "never") {
      c.meta.seal = { ...seal, state: "refused", error: `${who} refused this checkpoint (${r.status}): ${r.line}` };
      saveMeta(c);
      refused.push(c.seq);
      continue;
    }
    fails += 1;
    let line: string;
    let wait: number;
    if (r.kind === "refused") {
      line = `${who} answered: ${r.line}`;
      wait = DAY_MS; // 401 and 403: once a day (section 5.1)
    } else if (r.kind === "bad-receipt") {
      line = `${who} answered with something that is not a receipt this version of OpsContext may keep (${r.problems.join("; ")})`;
      wait = 6 * 3_600_000;
    } else {
      line = r.status === null ? r.line : `${who} answered: ${r.line}`;
      wait = r.waitS !== null ? Math.max(r.waitS, 30) * 1000 : backoffMs(fails);
    }
    c.meta.seal = { ...seal, error: line };
    saveMeta(c);
    hold = { until: plus(t, wait), line, fails };
    break;
  }
  return { received, refused, hold };
}

// ---------- the proof ----------

function firstNo(chk: BundleCheck): string {
  const lines = [chk.checkpoint, chk.path, chk.receipt, ...chk.stamps.map((s) => ({ mark: s.mark, detail: `${s.name}: ${s.detail}` }))];
  return lines.find((l) => l.mark === "NO")?.detail ?? lines.find((l) => l.mark !== "OK")?.detail ?? "it could not be checked";
}

function stampOf(chk: BundleCheck): SealMeta["stamp"] {
  const ok = chk.stamps.filter((s) => s.mark === "OK").sort((a, b) => String(a.time).localeCompare(String(b.time)))[0];
  if (ok) return { name: ok.name, time: ok.time, checked: true };
  const some = chk.stamps.find((s) => s.time !== null);
  return some ? { name: some.name, time: some.time, checked: false } : null;
}

export const proofDir = (c: { dir: string }): string => join(c.dir, "proof");

/**
 * Ask for one checkpoint's proof and keep it when it holds. For a received checkpoint this is what
 * makes it sealed; for a sealed one it refreshes the proof (the Bitcoin attestation comes hours later).
 * [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] [LOCK] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES]
 */
export async function fetchProof(c: SealCheckpoint, service: Service, o: { now: () => Date; timeoutMs?: number }): Promise<SealState> {
  const seal = c.meta.seal;
  if (!seal || (seal.state !== "received" && seal.state !== "sealed")) return seal?.state ?? "queued";
  const who = serviceName(service);
  const had = seal.state === "sealed";
  const r = await getProof(service, c.meta.digest, { timeoutMs: o.timeoutMs });
  const t = o.now();
  const tries = seal.proof_tries + 1;
  const again = (ms: number, patch: Partial<SealMeta>): SealState => {
    c.meta.seal = { ...seal, proof_tries: tries, proof_next_at: plus(t, had ? Math.max(ms, REFRESH_AFTER_MS) : ms), ...patch };
    saveMeta(c);
    return seal.state;
  };
  if (r.kind === "pending") return again(backoffMs(tries), { waiting: r.why, error: null });
  if (r.kind === "missed") {
    if (had) return again(DAY_MS, {}); // a stored proof that holds is not undone by a later answer
    c.meta.seal = { ...seal, state: "missed", proof_tries: tries, proof_next_at: null, waiting: null, error: `${who} missed the hour ${seal.hour ?? "of this checkpoint"}: ${r.line}` };
    saveMeta(c);
    return "missed";
  }
  if (r.kind === "unknown") return again(60 * 60_000, had ? {} : { error: `${who} does not know this checkpoint any more (${r.line})` });
  if (r.kind === "later") return again(r.waitS !== null ? Math.max(r.waitS, 30) * 1000 : backoffMs(tries), had ? {} : { error: r.status === null ? r.line : `${who} answered: ${r.line}` });

  // A bundle: read under the contract's names, written to a folder of its own, checked there, and
  // only then put in place.
  const tmp = join(c.dir, `.proof-check-${process.pid}`);
  try {
    const files = bundleFiles(r.bundle);
    if ((r.bundle as { checkpoint_digest?: unknown }).checkpoint_digest !== c.meta.digest || digestOf(c.checkpoint) !== c.meta.digest) throw new Error("it is about another checkpoint");
    writeBundle(files, tmp);
    const chk = checkBundle(tmp, service, { digest: c.meta.digest, customer: seal.customer ?? undefined });
    if (!chk.included || !chk.holds) throw new Error(firstNo(chk));
    const stamp = stampOf(chk);
    if (had && seal.stamp?.checked && !stamp?.checked) throw new Error("it carries no checked stamp, and the proof kept here does");
    writeBundle(files, proofDir(c));
    const pending = chk.bitcoin.state === "pending";
    c.meta.seal = {
      ...seal, state: "sealed", hour: chk.hour ?? seal.hour, error: null, waiting: null, proof_tries: tries, stamp, bitcoin: chk.bitcoin.state,
      proof_at: t.toISOString(), proof_next_at: pending ? plus(t, REFRESH_AFTER_MS) : null,
    };
    saveMeta(c);
    return "sealed";
  } catch (e) {
    return again(backoffMs(tries), had ? {} : { error: `the proof ${who} served was not kept: ${(e as Error).message.slice(0, 200)}` });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * The proofs that are due: received checkpoints whose hour has been sealed by now, then a few sealed
 * ones whose Bitcoin attestation was still pending. Returns the sequence numbers newly sealed.
 */
export async function fetchDueProofs(all: SealCheckpoint[], service: Service, o: { now: () => Date; force?: boolean; timeoutMs?: number }): Promise<number[]> {
  const sealed: number[] = [];
  const due = (c: SealCheckpoint): boolean => !!c.meta.seal?.proof_next_at && Date.parse(c.meta.seal.proof_next_at) <= o.now().getTime();
  let asked = 0;
  for (const c of all) {
    const s = c.meta.seal;
    if (!s || s.state !== "received" || asked >= MAX_PROOFS_PER_TICK) continue;
    // Before its hour's cut-off there is nothing to ask, by hand or not.
    if (s.hour && cutoffOf(s.hour).getTime() > o.now().getTime()) continue;
    if (!o.force && !due(c)) continue;
    asked++;
    if ((await fetchProof(c, service, o)) === "sealed") sealed.push(c.seq);
  }
  let refreshed = 0;
  for (const c of [...all].reverse()) {
    const s = c.meta.seal;
    if (!s || s.state !== "sealed" || s.bitcoin !== "pending" || refreshed >= MAX_REFRESH_PER_TICK) continue;
    if (!due(c) || o.now().getTime() - Date.parse(s.received_at ?? s.proof_at ?? "") > REFRESH_FOR_MS) continue;
    refreshed++;
    await fetchProof(c, service, o);
  }
  return sealed;
}

/** The stored receipt of a checkpoint, or null. */
export function readReceipt(c: { dir: string }): unknown {
  try {
    return existsSync(join(c.dir, "receipt.json")) ? JSON.parse(readFileSync(join(c.dir, "receipt.json"), "utf8")) : null;
  } catch {
    return null;
  }
}
