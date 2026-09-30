// The window of a SealHour checkpoint (COMPR-TSA docs/SEALHOUR_PROTOCOL.md section 2.2), read from
// OpsContext's own history: the records appended since the previous checkpoint, in the verifier's file
// order (archived segments, then the live log), complete records only.
//
// [LOCKED] [CHECKPOINT-COMMITS-TO-EVERY-RECORD] - 2026-09-30
// [NEVER] compute records_root over the head's ancestors only, over parsed records that have no 64-hex
//         hash, or over a reading that differs from verifyChain()'s file order and seam rule.
// WHY: the chain has side branches (two writers read the same head: 67 on the author's log in 2026-09).
//      A record on a dead branch is not an ancestor of the head, so a checkpoint over the head alone
//      does not cover it, and it could be rewritten by recomputing its own hash (workplan 2, Chantier 1,
//      correction 2). And a window read in another order than the verifier's gives another root: every
//      proof would fail on the first rotation.
// FIX: every record of the window counts, whatever branch it sits on, one leaf per record over its hash
//      field only (a redaction changes content, never the hash). The files are read in verifyChain()'s
//      order, split on "\n" only, with its seam rule (the leading live records already in the last
//      segment are the same records, read once). The emitter reads holding the rotate lock, so no move
//      happens mid-read.
//
// [LOCKED] [VERIFY-READS-THE-LOG-AS-IT-STOOD] - 2026-09-30
// [NEVER] verify a checkpoint only against the history as it stands today, and never trust a record's
//         index: a restore inserts records and shifts every index after them.
// WHY: a segment put back by audit-restore after a checkpoint was there when the checkpoint was made if
//      the checkpoint came before the loss, and missing if it came during the hole (correction 3). One
//      reading proves one case and calls the other tampered.
// FIX: checkWindows() reads with every segment, then, for a checkpoint that does not match, without the
//      segments whose audit.restore record is later than its created_at (one set at a time; a restored
//      segment with no record counts as restored later), keeps the reading where from_hash, count,
//      head_hash and the root all agree, and says which one it kept.
import { closeSync, openSync, readSync } from "fs";
import { historyFiles, withRotateLock, listSegments } from "./audit.js";
import { MerkleStream, ZERO, recordLeaf } from "./anchor-protocol.js";

const HEX64 = /^[0-9a-f]{64}$/;
const RESTORED_SEGMENT = /^audit-\d{4,}-r[1-9]\d*\.jsonl$/;
const CHUNK = 4 << 20;

type HistoryFile = ReturnType<typeof historyFiles>[number];

interface Line {
  text: string;
  start: number;
  end: number;
}

/** Every line of a file from byte `from`, split on "\n" only (never readline: U+2028 sits raw in real
 *  records). The last line is yielded even without its newline. [LOCK] [VERIFY-STREAMS-THE-HISTORY] */
function* linesOf(path: string, from = 0): Generator<Line> {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.allocUnsafe(CHUNK);
    let pos = from;
    let carry = Buffer.alloc(0);
    let carryStart = from;
    for (;;) {
      const got = readSync(fd, buf, 0, buf.length, pos);
      if (got === 0) break;
      pos += got;
      const chunk = carry.length > 0 ? Buffer.concat([carry, buf.subarray(0, got)]) : buf.subarray(0, got);
      let i = 0;
      for (;;) {
        const nl = chunk.indexOf(10, i);
        if (nl === -1) break;
        yield { text: chunk.toString("utf8", i, nl), start: carryStart + i, end: carryStart + nl + 1 };
        i = nl + 1;
      }
      carry = Buffer.from(chunk.subarray(i));
      carryStart += i;
    }
    if (carry.length > 0) yield { text: carry.toString("utf8"), start: carryStart, end: carryStart + carry.length };
  } finally {
    closeSync(fd);
  }
}

interface Parsed {
  hash: string;
  ts: string;
  /** Set on an audit.restore record: the segment it put back. */
  restored?: string;
}

/** undefined: not JSON (skipped, as the verifier skips it); null: JSON without a 64-hex hash (not a
 *  complete record, contract section 2.2); otherwise the record's hash and time. */
function parseLine(text: string): Parsed | null | undefined {
  if (!text) return undefined;
  let r: { hash?: unknown; ts?: unknown; event?: unknown; payload?: { segment?: unknown } };
  try {
    r = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!r || typeof r !== "object" || typeof r.hash !== "string" || !HEX64.test(r.hash)) return null;
  const out: Parsed = { hash: r.hash, ts: typeof r.ts === "string" ? r.ts : "" };
  if (r.event === "audit.restore" && typeof r.payload?.segment === "string") out.restored = r.payload.segment;
  return out;
}

/** The byte offset in the live log after which the verifier's reading starts: past the leading records
 *  that are copies of the last segment's (an interrupted rotation), else 0. As readHistory() and
 *  verifyChain() decide it. [LOCK] [ROTATE-ARCHIVE-BEFORE-TRUNCATE] */
function liveSeamOffset(files: HistoryFile[]): number {
  const live = files.find((f) => f.live);
  const segs = files.filter((f) => !f.live);
  if (!live || segs.length === 0) return 0;
  const last = segs[segs.length - 1].path;
  let first: string | null = null;
  for (const l of linesOf(live.path)) {
    const r = parseLine(l.text);
    if (r === undefined) continue;
    first = r?.hash ?? null;
    break;
  }
  if (!first) return 0;
  let inLast = false;
  for (const l of linesOf(last)) {
    if (l.text.includes(first) && parseLine(l.text)?.hash === first) {
      inLast = true;
      break;
    }
  }
  if (!inLast) return 0; // the only cost on a healthy log: one scan of the last segment
  const set = new Set<string>();
  for (const l of linesOf(last)) {
    const r = parseLine(l.text);
    if (r) set.add(r.hash);
  }
  let offset = 0;
  for (const l of linesOf(live.path)) {
    const r = parseLine(l.text);
    if (r === undefined) continue;
    if (!r || !set.has(r.hash)) break;
    offset = l.end;
  }
  return offset;
}

export interface Position {
  /** "audit.log" or a segment's file name. */
  label: string;
  /** Byte offset just after the record's line. */
  offset: number;
}

export interface HistoryRecord extends Parsed {
  file: string;
  end: number;
}

/** The reading of contract section 2.2 from `from` (exclusive), or from the first record. */
function* reading(files: HistoryFile[], seam: number, from: Position | null): Generator<HistoryRecord> {
  let started = from === null;
  for (const f of files) {
    let offset = 0;
    if (!started) {
      if (f.label !== from!.label) continue;
      started = true;
      offset = from!.offset;
    }
    if (f.live && offset < seam) offset = seam;
    for (const l of linesOf(f.path, offset)) {
      const r = parseLine(l.text);
      if (r) yield { ...r, file: f.label, end: l.end };
    }
  }
}

/** The record whose line ends at `offset` in `path`, or null. */
function recordEndingAt(path: string, offset: number): Parsed | null {
  if (offset <= 0) return null;
  const want = Math.min(offset, 1 << 20);
  const buf = Buffer.alloc(want);
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return null;
  }
  try {
    const got = readSync(fd, buf, 0, want, offset - want);
    if (got !== want) return null;
  } finally {
    closeSync(fd);
  }
  let end = buf.length;
  if (buf[end - 1] === 10) end--;
  const nl = buf.lastIndexOf(10, end - 1);
  if (nl === -1 && want < offset) return null; // the line is longer than the window: search instead
  return parseLine(buf.toString("utf8", nl + 1, end)) ?? null;
}

/**
 * Where the record `hash` sits in the reading: the cached position when it still holds that record,
 * else its last occurrence in the newest file that holds it (the previous checkpoint's head is recent;
 * a rotation moves it from the live log into a new segment). null when the history no longer holds it.
 */
function locate(files: HistoryFile[], seam: number, hash: string, cached?: Position): Position | null {
  if (cached) {
    const f = files.find((x) => x.label === cached.label);
    if (f && !(f.live && cached.offset <= seam) && recordEndingAt(f.path, cached.offset)?.hash === hash) return cached;
  }
  for (const f of [...files].reverse()) {
    let found: Position | null = null;
    for (const l of linesOf(f.path, f.live ? seam : 0)) {
      if (l.text.includes(hash) && parseLine(l.text)?.hash === hash) found = { label: f.label, offset: l.end };
    }
    if (found) return found;
  }
  return null;
}

export interface Window {
  from_hash: string;
  count: number;
  head_hash: string;
  records_root: string;
  /** Where the next window starts. */
  end: Position;
  /** Time of the window's first record, and the latest time in it. */
  firstTs: string;
  lastTs: string;
}

export type WindowOutcome =
  | { kind: "window"; window: Window }
  | { kind: "empty" }
  | { kind: "lost"; detail: string }
  | { kind: "busy"; heldMs: number };

/**
 * The window after the record `from` (ZERO: from the first record), read now, holding the rotate lock.
 * [LOCK] [CHECKPOINT-COMMITS-TO-EVERY-RECORD]
 */
export function readWindow(from: { hash: string; at?: Position }): WindowOutcome {
  const r = withRotateLock((): WindowOutcome => {
    const files = historyFiles();
    const seam = liveSeamOffset(files);
    let start: Position | null = null;
    if (from.hash !== ZERO) {
      start = locate(files, seam, from.hash, from.at);
      if (!start) {
        return { kind: "lost", detail: `the last record of the previous checkpoint (${from.hash.slice(0, 12)}) is no longer in the audit log: history was cut or replaced after it was sealed; run contextengine audit-verify` };
      }
    }
    const tree = new MerkleStream();
    let last: HistoryRecord | null = null;
    let firstTs = "";
    let lastTs = "";
    for (const rec of reading(files, seam, start)) {
      tree.push(recordLeaf(rec.hash));
      if (!last) firstTs = rec.ts;
      if (rec.ts > lastTs) lastTs = rec.ts;
      last = rec;
    }
    if (!last) return { kind: "empty" };
    return {
      kind: "window",
      window: {
        from_hash: from.hash,
        count: tree.size,
        head_hash: last.hash,
        records_root: tree.root().toString("hex"),
        end: { label: last.file, offset: last.end },
        firstTs,
        lastTs,
      },
    };
  });
  return r.ran ? r.value : { kind: "busy", heldMs: r.heldMs };
}

export interface WindowClaim {
  id: string;
  created_at: string;
  from_hash: string;
  count: number;
  head_hash: string;
  records_root: string;
}

export interface WindowCheck {
  ok: boolean;
  /** "with every segment", or "without <segments> (restored after this checkpoint)". */
  reading: string;
  /** What the log gave when nothing matched. */
  got?: { count: number; head_hash: string | null; records_root: string | null; found: boolean };
}

interface Builder {
  claim: WindowClaim;
  tree: MerkleStream;
  last: string | null;
}

/** One pass over one reading, for every claim at once: a window starts after each occurrence of its
 *  from_hash (usually one) and is compared when it holds `count` records. */
function pass(files: HistoryFile[], claims: WindowClaim[], restores: Map<string, string> | null): Map<string, WindowCheck["got"] & { ok: boolean }> {
  const seam = liveSeamOffset(files);
  const out = new Map<string, WindowCheck["got"] & { ok: boolean }>();
  const byFrom = new Map<string, WindowClaim[]>();
  const active: Builder[] = [];
  for (const c of claims) {
    if (c.from_hash === ZERO) active.push({ claim: c, tree: new MerkleStream(), last: null });
    else byFrom.set(c.from_hash, [...(byFrom.get(c.from_hash) ?? []), c]);
  }
  const settle = (id: string, v: WindowCheck["got"] & { ok: boolean }) => {
    const had = out.get(id);
    if (!had || (!had.ok && v.ok)) out.set(id, v);
  };
  for (const rec of reading(files, seam, null)) {
    if (restores && rec.restored) restores.set(rec.restored, rec.ts);
    if (active.length > 0) {
      const leaf = recordLeaf(rec.hash);
      for (let i = active.length - 1; i >= 0; i--) {
        const b = active[i];
        b.tree.push(leaf);
        b.last = rec.hash;
        if (b.tree.size === b.claim.count) {
          const root = b.tree.root().toString("hex");
          settle(b.claim.id, { ok: b.last === b.claim.head_hash && root === b.claim.records_root, count: b.tree.size, head_hash: b.last, records_root: root, found: true });
          active.splice(i, 1);
        }
      }
    }
    const starters = byFrom.get(rec.hash);
    if (starters) for (const c of starters) active.push({ claim: c, tree: new MerkleStream(), last: null });
    if (!restores && active.length === 0 && claims.every((c) => out.get(c.id)?.ok)) break;
  }
  for (const b of active) settle(b.claim.id, { ok: false, count: b.tree.size, head_hash: b.last, records_root: null, found: true });
  for (const c of claims) if (!out.has(c.id)) out.set(c.id, { ok: false, count: 0, head_hash: null, records_root: null, found: false });
  return out;
}

/** Every non-empty subset of `s`, the whole set first, then by decreasing size (at most 4 members
 *  are combined; beyond that, the whole set and each one alone). */
function exclusionSets(s: string[]): string[][] {
  if (s.length > 4) return [s, ...s.map((x) => [x])];
  const sets: string[][] = [];
  for (let mask = (1 << s.length) - 1; mask > 0; mask--) sets.push(s.filter((_, i) => mask & (1 << i)));
  return sets.sort((a, b) => b.length - a.length);
}

/**
 * Recompute every claimed window from this machine's history, restore-aware. [LOCK] [VERIFY-READS-THE-LOG-AS-IT-STOOD]
 * Reads holding the rotate lock when it can get it within `waitMs`; otherwise reads anyway and says so.
 */
export function checkWindows(claims: WindowClaim[], opts: { waitMs?: number } = {}): { results: Map<string, WindowCheck>; restored: Array<{ segment: string; at: string | null }>; unlocked: boolean } {
  const run = () => {
    const files = historyFiles();
    const restoreTimes = new Map<string, string>();
    const first = pass(files, claims, restoreTimes);
    const present = new Set(listSegments());
    const restored = [...present].filter((f) => RESTORED_SEGMENT.test(f) || restoreTimes.has(f)).map((segment) => ({ segment, at: restoreTimes.get(segment) ?? null }));
    const results = new Map<string, WindowCheck>();
    const retry = new Map<string, WindowClaim[]>();
    const plans = new Map<string, string[][]>();
    for (const c of claims) {
      const got = first.get(c.id)!;
      if (got.ok) {
        results.set(c.id, { ok: true, reading: "with every segment" });
        continue;
      }
      results.set(c.id, { ok: false, reading: "with every segment", got: { count: got.count, head_hash: got.head_hash, records_root: got.records_root, found: got.found } });
      const later = restored.filter((r) => r.at === null || Date.parse(r.at) > Date.parse(c.created_at)).map((r) => r.segment);
      if (later.length > 0) plans.set(c.id, exclusionSets(later));
    }
    // One reading per exclusion set, for every claim that still needs it, one set at a time.
    for (let round = 0; plans.size > 0 && round < 16; round++) {
      retry.clear();
      for (const [id, sets] of plans) {
        const next = sets.shift();
        if (!next) { plans.delete(id); continue; }
        const key = next.join("\n");
        retry.set(key, [...(retry.get(key) ?? []), claims.find((c) => c.id === id)!]);
      }
      for (const [key, group] of retry) {
        const without = new Set(key.split("\n"));
        const got = pass(files.filter((f) => !without.has(f.label)), group, null);
        for (const c of group) {
          if (got.get(c.id)?.ok) {
            results.set(c.id, { ok: true, reading: `without ${[...without].join(", ")} (restored after this checkpoint)` });
            plans.delete(c.id);
          }
        }
      }
      for (const [id, sets] of plans) if (sets.length === 0) plans.delete(id);
    }
    return { results, restored };
  };
  const deadline = Date.now() + (opts.waitMs ?? 20_000);
  for (;;) {
    const r = withRotateLock(run);
    if (r.ran) return { ...r.value, unlocked: false };
    if (Date.now() >= deadline) return { ...run(), unlocked: true };
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
}
