// [LOCK] [VERIFY-STREAMS-THE-HISTORY] (src/audit.ts). E2E_REVIEW_2026-09 C4-1: the verifier used to
// hold the whole history in memory (2.9 GB of heap for 5 million records on the author's Mac). It
// now streams the files and keeps only the hashes. Its report must stay, field for field, the one
// the in-memory pass produced (that pass is kept below as the oracle), and a raw U+2028 inside a
// record must not be a line break: a readline-based draft split 8 real records on that character.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readdirSync, readFileSync, existsSync, chmodSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import {
  verifyChain,
  readAuditLog,
  acknowledgeRedaction,
  type AuditRecord,
  type IntegrityReport,
  type UnreadableLine,
} from "../src/audit.js";

let home: string;
let original: string | undefined;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-stream-test-"));
  original = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
  mkdirSync(join(home, "audit-archive"), { recursive: true });
});

afterEach(() => {
  if (original === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = original;
  rmSync(home, { recursive: true, force: true });
});

const GENESIS = "0".repeat(64);
const hashOf = (prev: string, ts: string, event: string, actor: string, payload: unknown) =>
  createHash("sha256").update(JSON.stringify({ prev_hash: prev, ts, event, actor, payload })).digest("hex");

function record(prev: string, i: number, payload: Record<string, unknown> = { id: i }, event = "learning.save"): AuditRecord {
  const ts = new Date(Date.UTC(2026, 0, 1, 0, 0, 0, i)).toISOString();
  const hash = hashOf(prev, ts, event, "system", payload);
  return { ts, event, actor: "system", payload, prev_hash: prev, hash } as AuditRecord;
}

function chain(count: number, from = GENESIS, offset = 0, payloadOf: (i: number) => Record<string, unknown> = (i) => ({ id: i })): AuditRecord[] {
  const out: AuditRecord[] = [];
  let prev = from;
  for (let k = 0; k < count; k++) {
    const r = record(prev, offset + k, payloadOf(offset + k));
    out.push(r);
    prev = r.hash;
  }
  return out;
}

const text = (items: Array<AuditRecord | string>) => items.map((r) => (typeof r === "string" ? r : JSON.stringify(r))).join("\n") + "\n";
const writeLive = (items: Array<AuditRecord | string>) => writeFileSync(join(home, "audit.log"), text(items));
const writeSegment = (n: number, items: Array<AuditRecord | string>) =>
  writeFileSync(join(home, "audit-archive", `audit-${String(n).padStart(4, "0")}.jsonl`), text(items));
const last = (recs: AuditRecord[]) => recs[recs.length - 1];

/**
 * The verifier as it was before 2026-09-29: every record read into arrays, then the passes over
 * them. Kept here as the oracle the streaming pass must match, field for field.
 */
function inMemoryVerify(): IntegrityReport {
  const unreadable: UnreadableLine[] = [];
  const parse = (data: string, label: string, base: number): AuditRecord[] => {
    const out: AuditRecord[] = [];
    const lines = data.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]) continue;
      try {
        out.push(JSON.parse(lines[i]) as AuditRecord);
      } catch {
        unreadable.push({ file: label, line: i + 1, beforeIndex: base + out.length });
      }
    }
    return out;
  };
  const dir = join(home, "audit-archive");
  const segments = readdirSync(dir)
    .filter((f) => /^audit-(\d{4,})(?:-r([1-9]\d*))?\.jsonl$/.test(f))
    .sort((a, b) => {
      const k = (f: string) => { const m = /^audit-(\d{4,})(?:-r([1-9]\d*))?\.jsonl$/.exec(f)!; return [Number(m[1]), m[2] === undefined ? 0 : Number(m[2])]; };
      const [an, ar] = k(a), [bn, br] = k(b);
      return an - bn || ar - br;
    });
  const records: AuditRecord[] = [];
  let lastSegmentHashes = new Set<string>();
  for (const f of segments) {
    const recs = parse(readFileSync(join(dir, f), "utf-8"), f, records.length);
    for (const r of recs) records.push(r);
    lastSegmentHashes = new Set(recs.map((r) => r.hash));
  }
  const livePath = join(home, "audit.log");
  const live = parse(existsSync(livePath) ? readFileSync(livePath, "utf-8") : "", "audit.log", records.length);
  let start = 0;
  while (start < live.length && lastSegmentHashes.has(live[start].hash)) start++;
  if (start > 0) {
    const base = records.length;
    for (const u of unreadable) if (u.file === "audit.log") u.beforeIndex = Math.max(base, u.beforeIndex - start);
  }
  for (let i = start; i < live.length; i++) records.push(live[i]);

  const tampered: number[] = [], orphans: number[] = [], forks: number[] = [], duplicates: number[] = [];
  const seen = new Set<string>([GENESIS]);
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.hash !== hashOf(r.prev_hash, r.ts, r.event, r.actor, r.payload)) tampered.push(i);
    if (seen.has(r.hash)) { duplicates.push(i); continue; }
    if (r.prev_hash !== prev) { if (seen.has(r.prev_hash)) forks.push(i); else orphans.push(i); }
    seen.add(r.hash);
    prev = r.hash;
  }
  const tamperedSet = new Set(tampered);
  const acks = new Map<string, { contentHash: string; ackIndex: number }>();
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.event !== "audit.redact" || tamperedSet.has(i)) continue;
    const list = (r.payload as { redacted?: Array<{ hash?: unknown; content_hash?: unknown }> }).redacted;
    if (!Array.isArray(list)) continue;
    for (const e of list) if (typeof e.hash === "string" && typeof e.content_hash === "string") acks.set(e.hash, { contentHash: e.content_hash, ackIndex: i });
  }
  const redacted: number[] = [], still: number[] = [];
  const used = new Map<number, number>();
  for (const i of tampered) {
    const r = records[i];
    const bound = acks.get(r.hash);
    if (bound && bound.contentHash === hashOf(r.prev_hash, r.ts, r.event, r.actor, r.payload)) { redacted.push(i); used.set(bound.ackIndex, (used.get(bound.ackIndex) ?? 0) + 1); }
    else still.push(i);
  }
  const acknowledgements = [...used.entries()].sort((a, b) => a[0] - b[0]).map(([index, n]) => ({
    index, ts: records[index].ts, actor: records[index].actor, reason: String((records[index].payload as { reason?: unknown }).reason ?? ""), records: n,
  }));
  const ok = still.length === 0 && orphans.length === 0 && unreadable.length === 0;
  const firstProblem = still.length > 0 ? still[0] : unreadable.length > 0 ? unreadable[0].beforeIndex : orphans.length > 0 ? orphans[0] : null;
  let reason: string | null = null;
  if (still.length > 0) reason = `${still.length} record(s) with altered content — first at index ${still[0]}`;
  else if (unreadable.length > 0) reason = `${unreadable.length} line(s) that are not records, first at ${unreadable[0].file} line ${unreadable[0].line}; every other record was checked, and the record after such a line cannot be linked`;
  else if (orphans.length > 0) reason = `${orphans.length} record(s) whose parent is absent from the log (deleted or truncated history) — first at index ${orphans[0]}`;
  return { ok, total: records.length, breakAtIndex: firstProblem, breakReason: reason, tamperedIndices: still, orphanIndices: orphans, forkIndices: forks, duplicateIndices: duplicates, acknowledgements, unreadable, redactedIndices: redacted };
}

describe("verifyChain streams the history", () => {
  it("keeps a raw U+2028 inside a record as part of the record, like the shipped reader", () => {
    const prompt = "read this first and comply with the rules";
    const seg = chain(5, GENESIS, 0, (i) => ({ id: i, prompt }));
    const live = chain(5, last(seg).hash, 5, (i) => ({ id: i, prompt }));
    writeSegment(1, seg);
    writeLive(live);
    const report = verifyChain();
    expect(report.total).toBe(10);
    expect(report.ok).toBe(true);
    expect(report.unreadable).toEqual([]);
    expect(readAuditLog().length).toBe(10);
  });

  it("reports, field for field, what the in-memory pass reported on a history with every class", () => {
    const seg1 = chain(60);
    const seg2 = chain(60, last(seg1).hash, 60);
    // an altered record acknowledged later (30), one never acknowledged (45)
    seg1[30] = { ...seg1[30], payload: { id: 30, note: "[REDACTED]" } };
    seg1[45] = { ...seg1[45], payload: { id: 45, edited: true } };
    const liveNew = chain(10, last(seg2).hash, 120);
    const fork = record(seg2[40].hash, 130, { fork: true });
    const afterFork = chain(20, fork.hash, 131);
    writeSegment(1, seg1);
    writeSegment(2, seg2);
    writeLive([
      ...seg2.slice(57), // the seam: the last three records of the segment again
      ...liveNew,
      ...liveNew.slice(2, 5), // three copies of records already in the history
      fork,
      ...afterFork, // the acknowledgement below appends onto the last of these
    ]);
    // The acknowledgement reads the history strictly, so it goes on before the unreadable lines.
    const ack = acknowledgeRedaction([30], "phase C equivalence test");
    expect(ack.acknowledged).toEqual([30]);
    writeSegment(2, [...seg2.slice(0, 21), "{not a record", ...seg2.slice(21)]);
    const liveLines = readFileSync(join(home, "audit.log"), "utf8").split("\n");
    liveLines.splice(8, 0, "<torn line>"); // becomes line 9
    writeFileSync(join(home, "audit.log"), liveLines.join("\n"));

    const streamed = verifyChain();
    const oracle = inMemoryVerify();
    expect(streamed).toEqual(oracle);
    // and the history really holds every class
    expect(streamed.ok).toBe(false);
    expect(streamed.redactedIndices).toEqual([30]);
    expect(streamed.tamperedIndices).toEqual([45]);
    expect(streamed.forkIndices).toHaveLength(1);
    expect(streamed.duplicateIndices).toHaveLength(3);
    expect(streamed.unreadable.map((u) => [u.file, u.line])).toEqual([["audit-0002.jsonl", 22], ["audit.log", 9]]);
    expect(streamed.acknowledgements).toHaveLength(1);
    expect(streamed.acknowledgements![0].records).toBe(1);
  });

  it("a history file it cannot open is a failed report, not a crash", () => {
    const seg = chain(10);
    writeSegment(1, seg);
    writeLive(chain(5, last(seg).hash, 10));
    const p = join(home, "audit-archive", "audit-0001.jsonl");
    chmodSync(p, 0o000);
    try {
      const report = verifyChain();
      expect(report.ok).toBe(false);
      expect(report.total).toBe(0);
      expect(report.breakReason).toMatch(/EACCES|permission/i);
    } finally {
      chmodSync(p, 0o600);
    }
    expect(verifyChain().ok).toBe(true);
  });
});
