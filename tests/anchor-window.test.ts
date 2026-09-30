// The checkpoint's window read from the real history: side branches, rotation, the interrupted-rotation
// seam, a lost segment and both restore cases. [LOCK] [CHECKPOINT-COMMITS-TO-EVERY-RECORD]
// [LOCK] [VERIFY-READS-THE-LOG-AS-IT-STOOD] (src/anchor-window.ts)
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { appendAudit, readAuditLog, rotateAuditLog, restoreSegment, listSegments, verifyChain, type AuditRecord } from "../src/audit.js";
import { readWindow, checkWindows, type Window, type WindowClaim } from "../src/anchor-window.js";
import { ZERO, recordsRoot, recordLeaf, leafHash, makeCheckpoint, digestOf, codeRoot, isoSecond, type CodeLeaf } from "../src/anchor-protocol.js";

let home: string;
let saved: string | undefined;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-anchor-window-"));
  saved = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
});
afterEach(() => {
  if (saved === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = saved;
  rmSync(home, { recursive: true, force: true });
});

const logPath = () => join(home, "audit.log");
const seg = (f: string) => join(home, "audit-archive", f);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** A record chained on `prev`, hashed by OpsContext's rule. */
function rec(prev: string, n: number, extra: Record<string, unknown> = {}): AuditRecord {
  const ts = new Date(Date.now() - 1000 + n).toISOString();
  const payload = { n, ...extra };
  const hash = sha(JSON.stringify({ prev_hash: prev, ts, event: "learning.save", actor: "test", payload }));
  return { ts, event: "learning.save", actor: "test", payload, prev_hash: prev, hash } as AuditRecord;
}

function lastHash(): string {
  if (!existsSync(logPath())) return ZERO;
  const lines = readFileSync(logPath(), "utf8").trimEnd().split("\n");
  return (JSON.parse(lines[lines.length - 1]) as AuditRecord).hash;
}

/** n records chained on the current head, one write. */
function appendMany(n: number, tag = "m"): AuditRecord[] {
  const out: AuditRecord[] = [];
  let prev = lastHash();
  for (let i = 0; i < n; i++) {
    const r = rec(prev, i, { tag });
    out.push(r);
    prev = r.hash;
  }
  appendFileSync(logPath(), out.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return out;
}

const historyHashes = () => readAuditLog().map((r) => r.hash);
const claimOf = (id: string, w: Window, created_at = isoSecond(new Date())): WindowClaim => ({ id, created_at, ...w });

function win(from: { hash: string; at?: Window["end"] }): Window {
  const o = readWindow(from);
  if (o.kind !== "window") throw new Error(`expected a window, got ${o.kind}`);
  return o.window;
}

describe("the window covers every record since the previous checkpoint", () => {
  it("side branches included: two writers on the same head both count", () => {
    appendMany(5);
    const head = lastHash();
    const a = rec(head, 100, { writer: "one" });
    const b = rec(head, 101, { writer: "two" }); // both read the same head
    appendFileSync(logPath(), JSON.stringify(a) + "\n" + JSON.stringify(b) + "\n");
    appendAudit("learning.save", { after: "fork" });
    const w = win({ hash: ZERO });
    const all = historyHashes();
    expect(all.length).toBe(8);
    expect(w.count).toBe(8);
    expect(w.head_hash).toBe(all[7]);
    expect(w.records_root).toBe(recordsRoot(all));
    expect(verifyChain().forkIndices?.length).toBe(1); // the verifier sees the side branch too
  });

  it("the next window starts after the previous head, and is empty when nothing was written", () => {
    appendMany(4);
    const w1 = win({ hash: ZERO });
    expect(readWindow({ hash: w1.head_hash, at: w1.end }).kind).toBe("empty");
    const more = appendMany(3, "later");
    const w2 = win({ hash: w1.head_hash, at: w1.end });
    expect(w2.from_hash).toBe(w1.head_hash);
    expect(w2.count).toBe(3);
    expect(w2.records_root).toBe(recordsRoot(more.map((r) => r.hash)));
  });

  it("the fast record leaf is the canonical one", () => {
    for (let i = 0; i < 50; i++) {
      const h = sha(`leaf ${i}`);
      expect(recordLeaf(h).toString("hex")).toBe(leafHash({ kind: "record", hash: h }).toString("hex"));
    }
  });

  it("a line that is not a record, or a record without a 64-hex hash, is not in the window", () => {
    appendMany(2);
    appendFileSync(logPath(), "not json\n" + JSON.stringify({ ts: "x", event: "e", hash: "short" }) + "\n");
    appendMany(1);
    const w = win({ hash: ZERO });
    expect(w.count).toBe(3);
  });
});

describe("rotation, the seam, a lost head, a busy lock", () => {
  it("a rotation between two windows moves the previous head into a segment and changes nothing", () => {
    appendMany(2500);
    const w1 = win({ hash: ZERO });
    appendMany(3000, "after");
    const r = rotateAuditLog({ maxRecords: 2000 });
    expect(r.rotated).toBe(true);
    const all = historyHashes();
    const at = all.indexOf(w1.head_hash);
    expect(readFileSync(seg(listSegments()[0]), "utf8")).toContain(w1.head_hash); // the head now sits in the segment
    const w2 = win({ hash: w1.head_hash, at: w1.end });
    expect(w2.count).toBe(all.length - at - 1);
    expect(w2.records_root).toBe(recordsRoot(all.slice(at + 1)));
  });

  it("an interrupted rotation (segment placed, live log not cut) is read once, as the verifier reads it", () => {
    appendMany(3000);
    const lines = readFileSync(logPath(), "utf8").trimEnd().split("\n");
    mkdirSync(join(home, "audit-archive"), { recursive: true });
    writeFileSync(seg("audit-0001.jsonl"), lines.slice(0, 1000).join("\n") + "\n"); // no intent note: the seam alone
    const w = win({ hash: ZERO });
    expect(verifyChain().total).toBe(3000);
    expect(w.count).toBe(3000);
    expect(w.records_root).toBe(recordsRoot(historyHashes()));
  });

  it("the previous checkpoint's last record no longer in the log is said, never started over", () => {
    appendMany(3);
    const o = readWindow({ hash: sha("a record that was never here") });
    expect(o.kind).toBe("lost");
  });

  it("a rotation holding the lock makes the reader wait, touching nothing", () => {
    appendMany(3);
    writeFileSync(join(home, "audit.rotate.lock"), `${process.pid}\n`);
    expect(readWindow({ hash: ZERO }).kind).toBe("busy");
    rmSync(join(home, "audit.rotate.lock"));
    expect(readWindow({ hash: ZERO }).kind).toBe("window");
  });
});

/** Segments 0001, 0002, 0003 and a live log, as the restore tests build them. */
function rotateThrice(): void {
  expect(rotateAuditLog({ maxRecords: 6000 }).rotated).toBe(true);
  expect(rotateAuditLog({ maxRecords: 4000 }).rotated).toBe(true);
  expect(rotateAuditLog({ maxRecords: 2000 }).rotated).toBe(true);
  expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0002.jsonl", "audit-0003.jsonl"]);
}

function loseSegmentTwo(): string {
  const lost = join(home, "backup-of-0002.jsonl");
  renameSync(seg("audit-0002.jsonl"), lost);
  return lost;
}

describe("restore-aware verification (contract section 2.2, correction 3)", () => {
  it("a checkpoint made before the loss fails while the segment is missing, and holds with every segment once it is back", () => {
    appendMany(8000);
    rotateThrice();
    const c1 = claimOf("c1", win({ hash: ZERO }));
    const lost = loseSegmentTwo();
    const during = checkWindows([c1]).results.get("c1")!;
    expect(during.ok).toBe(false);
    expect(during.got!.count).toBeLessThan(c1.count);
    const r = restoreSegment(lost, { apply: true, reason: "test: put back from the backup" });
    expect(r.restored).toBe(true);
    const after = checkWindows([c1]);
    expect(after.results.get("c1")).toEqual({ ok: true, reading: "with every segment" });
    expect(after.restored.map((x) => x.segment)).toEqual(["audit-0001-r1.jsonl"]);
  });

  it("a checkpoint made during the hole holds without the segment restored after it; before and after it, with every segment", () => {
    appendMany(1000);
    const w1 = win({ hash: ZERO });
    const c1 = claimOf("c1", w1);
    appendMany(7000, "later");
    rotateThrice();
    expect(readFileSync(seg("audit-0001.jsonl"), "utf8")).toContain(w1.head_hash);
    const lost = loseSegmentTwo();
    const w2 = win({ hash: w1.head_hash, at: w1.end }); // made during the hole
    const c2 = claimOf("c2", w2);
    expect(restoreSegment(lost, { apply: true, reason: "test: put back from the backup" }).segmentFile).toBe("audit-0001-r1.jsonl");
    appendMany(5, "after the restore");
    const w3 = win({ hash: w2.head_hash, at: w2.end });
    const c3 = claimOf("c3", w3);
    const { results } = checkWindows([c1, c2, c3]);
    expect(results.get("c1")).toEqual({ ok: true, reading: "with every segment" });
    expect(results.get("c2")).toEqual({ ok: true, reading: "without audit-0001-r1.jsonl (restored after this checkpoint)" });
    expect(results.get("c3")).toEqual({ ok: true, reading: "with every segment" });
  });

  it("a rewritten record hash fails the checkpoint in every reading", () => {
    appendMany(10);
    const c = claimOf("c", win({ hash: ZERO }));
    const lines = readFileSync(logPath(), "utf8").trimEnd().split("\n");
    const r = JSON.parse(lines[4]) as AuditRecord;
    r.hash = "f".repeat(64);
    lines[4] = JSON.stringify(r);
    writeFileSync(logPath(), lines.join("\n") + "\n");
    const got = checkWindows([c]).results.get("c")!;
    expect(got.ok).toBe(false);
    expect(got.got!.records_root).not.toBe(c.records_root);
  });

  it("a from_hash that appears twice: the occurrence that matches is kept", () => {
    const first = appendMany(5);
    appendFileSync(logPath(), JSON.stringify(first[2]) + "\n"); // a second copy of record 3
    const next = rec(first[2].hash, 99, { after: "copy" });
    appendFileSync(logPath(), JSON.stringify(next) + "\n");
    const claim: WindowClaim = { id: "d", created_at: isoSecond(new Date()), from_hash: first[2].hash, count: 1, head_hash: next.hash, records_root: recordsRoot([next.hash]) };
    expect(checkWindows([claim]).results.get("d")!.ok).toBe(true);
  });
});

// ---------- the fixture's customers, replayed through the real reader ----------

const FIX = process.env.SEALHOUR_FIXTURE_DIR ?? "";
const haveFixture = FIX !== "" && existsSync(join(FIX, "clients"));
const fxText = (p: string) => readFileSync(join(FIX, p), "utf8");
const fxJson = <T = Record<string, unknown>>(p: string) => JSON.parse(fxText(p)) as T;

describe.skipIf(!haveFixture)("the fixture's checkpoints, rebuilt by the reader from each audit log", () => {
  type Cp = { created_at: string; prev_checkpoint_digest: string; client: { version: string }; records: { count: number } };

  it("customer A: two checkpoints, the second over the side branch and the code, give the receipts' digests", () => {
    const lines = fxText("clients/customer-a/audit.jsonl").trimEnd().split("\n");
    const a1 = fxJson<Cp>("clients/customer-a/checkpoint-1.json");
    const a2 = fxJson<Cp & { code: { repos: number } }>("clients/customer-a/checkpoint-2.json");
    writeFileSync(logPath(), lines.slice(0, a1.records.count).join("\n") + "\n");
    const w1 = win({ hash: ZERO });
    const c1 = makeCheckpoint(w1, { created_at: a1.created_at, prev: ZERO, clientVersion: a1.client.version });
    expect(digestOf(c1)).toBe(fxJson("clients/customer-a/receipt-1.json").checkpoint_digest);
    appendFileSync(logPath(), lines.slice(a1.records.count).join("\n") + "\n");
    const w2 = win({ hash: w1.head_hash, at: w1.end });
    const leaves = fxJson<CodeLeaf[]>("clients/customer-a/code-leaves-2.json");
    const c2 = makeCheckpoint(w2, { created_at: a2.created_at, prev: digestOf(c1), clientVersion: a2.client.version, code: { repos: leaves.length, code_root: codeRoot(leaves) } });
    expect(digestOf(c2)).toBe(fxJson("clients/customer-a/receipt-2.json").checkpoint_digest);
    expect(c2).toEqual(a2); // field for field, whatever the file's key order
  });

  it("customer B: one checkpoint gives the receipt's digest", () => {
    writeFileSync(logPath(), fxText("clients/customer-b/audit.jsonl"));
    const b1 = fxJson<Cp>("clients/customer-b/checkpoint-1.json");
    const c = makeCheckpoint(win({ hash: ZERO }), { created_at: b1.created_at, prev: ZERO, clientVersion: b1.client.version });
    expect(digestOf(c)).toBe(fxJson("clients/customer-b/receipt-1.json").checkpoint_digest);
  });
});
