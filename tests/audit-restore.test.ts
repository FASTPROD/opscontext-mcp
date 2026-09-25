import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import {
  appendAudit,
  readAuditLog,
  verifyChain,
  rotateAuditLog,
  restoreSegment,
  listSegments,
  resetCacheForTest,
  type AuditRecord,
} from "../src/audit.js";

let tempHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(join(tmpdir(), "ce-restore-test-"));
  originalHome = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = tempHome;
  resetCacheForTest();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = originalHome;
  resetCacheForTest();
  rmSync(tempHome, { recursive: true, force: true });
});

const logPath = () => join(tempHome, "audit.log");
const archive = () => join(tempHome, "audit-archive");
const seg = (f: string) => join(archive(), f);
const lockPath = () => join(tempHome, "audit.rotate.lock");

/** A hand-built chain, all within the last day, so only the size ceiling decides a rotation. */
function seedChain(count: number): AuditRecord[] {
  const recs: AuditRecord[] = [];
  let prev = "0".repeat(64);
  for (let i = 0; i < count; i++) {
    const ts = new Date(Date.now() - (count - i) * 1000).toISOString();
    const event = "learning.save";
    const actor = "system";
    const payload = { id: `L${i}` };
    const hash = createHash("sha256")
      .update(JSON.stringify({ prev_hash: prev, ts, event, actor, payload }))
      .digest("hex");
    recs.push({ ts, event, actor, payload, prev_hash: prev, hash } as AuditRecord);
    prev = hash;
  }
  writeFileSync(logPath(), recs.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return recs;
}

/** Three real segments: 0001, 0002, 0003, then a live log. */
function threeSegments(): void {
  seedChain(8000);
  expect(rotateAuditLog({ maxRecords: 6000 }).rotated).toBe(true);
  expect(rotateAuditLog({ maxRecords: 4000 }).rotated).toBe(true);
  expect(rotateAuditLog({ maxRecords: 2000 }).rotated).toBe(true);
  expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0002.jsonl", "audit-0003.jsonl"]);
  expect(verifyChain().ok).toBe(true);
}

/** The 2026-09-15 end state: segment 2's records are gone from the archive, kept elsewhere. */
function loseSegmentTwo(): string {
  const lost = join(tempHome, "lost-from-backup.jsonl");
  renameSync(seg("audit-0002.jsonl"), lost);
  return lost;
}

// [LOCK] [ROTATION-HOLDS-THE-LOCK-BEFORE-IT-PLANS]
describe("every rotation takes the rotate lock", () => {
  it("the manual path backs off while another rotation holds the lock, touching nothing", () => {
    seedChain(2500);
    const before = readFileSync(logPath(), "utf-8");
    writeFileSync(lockPath(), "1\n");
    const r = rotateAuditLog({ maxRecords: 2000 });
    expect(r.rotated).toBe(false);
    expect(r.inProgress).toBe(true);
    expect(r.refusedReason).toMatch(/in progress/);
    expect(listSegments()).toEqual([]);
    expect(readFileSync(logPath(), "utf-8")).toBe(before);
    expect(existsSync(lockPath())).toBe(true); // someone else's lock is never removed
  });

  it("releases the lock after a rotation, so the next one can run", () => {
    seedChain(2500);
    expect(rotateAuditLog({ maxRecords: 2000 }).rotated).toBe(true);
    expect(existsSync(lockPath())).toBe(false);
  });

  it("a dry run neither waits for nor takes the lock", () => {
    seedChain(2500);
    writeFileSync(lockPath(), "1\n");
    const r = rotateAuditLog({ maxRecords: 2000, dryRun: true });
    expect(r.inProgress).toBeFalsy();
    expect(r.archiveCount).toBe(500);
    expect(readFileSync(lockPath(), "utf-8")).toBe("1\n");
  });
});

// [LOCK] [SEGMENT-IS-NEVER-OVERWRITTEN]
describe("a segment is never overwritten", () => {
  it("numbers from the highest segment, not the count, so a missing number cannot collide", () => {
    threeSegments();
    loseSegmentTwo();
    const third = readFileSync(seg("audit-0003.jsonl"), "utf-8");
    for (let i = 0; i < 500; i++) appendAudit("learning.save", { more: i });
    // Two segments on disk: count + 1 would be 3, which is the file that already exists.
    const r = rotateAuditLog({ maxRecords: 2000 });
    expect(r.rotated).toBe(true);
    expect(r.segmentFile).toBe("audit-0004.jsonl");
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0003.jsonl", "audit-0004.jsonl"]);
    expect(readFileSync(seg("audit-0003.jsonl"), "utf-8")).toBe(third);
  });

  it("sorts a restored segment right after its predecessor and ignores an r0 name", () => {
    mkdirSync(archive(), { recursive: true });
    for (const f of ["audit-0010.jsonl", "audit-0002.jsonl", "audit-0001-r1.jsonl", "audit-0001.jsonl", "audit-0001-r0.jsonl", "audit-0001-r2.jsonl"]) {
      writeFileSync(seg(f), "");
    }
    expect(listSegments()).toEqual([
      "audit-0001.jsonl",
      "audit-0001-r1.jsonl",
      "audit-0001-r2.jsonl",
      "audit-0002.jsonl",
      "audit-0010.jsonl",
    ]);
  });
});

// [LOCK] [RESTORE-ONLY-CLOSES-A-PROVEN-GAP]
describe("restoreSegment", () => {
  it("reproduces the gap: losing a segment leaves exactly one orphan", () => {
    threeSegments();
    loseSegmentTwo();
    const v = verifyChain();
    expect(v.ok).toBe(false);
    expect(v.orphanIndices).toHaveLength(1);
  });

  it("a dry run finds the gap the block fills and writes nothing", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    const firstSegmentSize = readFileSync(seg("audit-0001.jsonl"), "utf-8").trim().split("\n").length;
    const r = restoreSegment(lost);
    expect(r.refusedReason).toBeNull();
    expect(r.after).toBe("audit-0001.jsonl");
    expect(r.before).toBe("audit-0003.jsonl");
    expect(r.segmentFile).toBe("audit-0001-r1.jsonl");
    expect(r.orphanIndex).toBe(firstSegmentSize);
    expect(r.restored).toBe(false);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0003.jsonl"]);
  });

  it("puts the block back, closes the orphan and records itself on the chain", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    const lostCount = readFileSync(lost, "utf-8").trim().split("\n").length;
    const r = restoreSegment(lost, { apply: true, reason: "test restore from backup" });
    expect(r.refusedReason).toBeNull();
    expect(r.restored).toBe(true);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0001-r1.jsonl", "audit-0003.jsonl"]);
    const v = verifyChain();
    expect(v.ok).toBe(true);
    expect(v.orphanIndices).toEqual([]);
    expect(v.tamperedIndices).toEqual([]);
    const last = readAuditLog().pop()!;
    expect(last.event).toBe("audit.restore");
    expect(last.payload.segment).toBe("audit-0001-r1.jsonl");
    expect(last.payload.records).toBe(lostCount);
    expect(last.payload.reason).toBe("test restore from backup");
    expect(existsSync(lockPath())).toBe(false);
  });

  it("refuses the same block twice", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    expect(restoreSegment(lost, { apply: true, reason: "first" }).restored).toBe(true);
    const again = restoreSegment(lost, { apply: true, reason: "second" });
    expect(again.restored).toBe(false);
    expect(again.refusedReason).toMatch(/already in/);
  });

  it("refuses a block with one altered record, and writes nothing", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    const lines = readFileSync(lost, "utf-8").trim().split("\n");
    const r = JSON.parse(lines[7]);
    r.payload = { id: "EDITED" };
    lines[7] = JSON.stringify(r);
    writeFileSync(lost, lines.join("\n") + "\n");
    const out = restoreSegment(lost, { apply: true, reason: "x" });
    expect(out.restored).toBe(false);
    expect(out.refusedReason).toMatch(/record 8 of the file does not match its own hash/);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0003.jsonl"]);
  });

  it("refuses a block with a side branch, which the chain could not vouch for", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    const lines = readFileSync(lost, "utf-8").trim().split("\n");
    // A self-consistent extra record hanging off record 5: its own hash is right, but it is not
    // an ancestor of the block's last record, so nothing in the chain pins its content.
    const parent = JSON.parse(lines[4]);
    const extra = { ts: parent.ts, event: "learning.save", actor: "system", payload: { id: "INSERTED" }, prev_hash: parent.hash };
    const hash = createHash("sha256")
      .update(JSON.stringify({ prev_hash: extra.prev_hash, ts: extra.ts, event: extra.event, actor: extra.actor, payload: extra.payload }))
      .digest("hex");
    lines.splice(5, 0, JSON.stringify({ ...extra, hash }));
    writeFileSync(lost, lines.join("\n") + "\n");
    const out = restoreSegment(lost, { apply: true, reason: "x" });
    expect(out.restored).toBe(false);
    expect(out.refusedReason).toMatch(/strictly linear/);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0003.jsonl"]);
  });

  it("refuses a block that fills no gap", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    // Drop the block's first record: its parent is then no segment's last record.
    const lines = readFileSync(lost, "utf-8").trim().split("\n");
    writeFileSync(lost, lines.slice(1).join("\n") + "\n");
    const out = restoreSegment(lost);
    expect(out.refusedReason).toMatch(/does not fill a gap/);
  });

  it("requires a reason to apply, and waits for a running rotation", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    expect(restoreSegment(lost, { apply: true }).refusedReason).toMatch(/reason is required/);
    writeFileSync(lockPath(), "1\n");
    const out = restoreSegment(lost, { apply: true, reason: "x" });
    expect(out.refusedReason).toMatch(/rotation is in progress/);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0003.jsonl"]);
  });

  it("after a restore, the next rotation still numbers from the highest segment", () => {
    threeSegments();
    const lost = loseSegmentTwo();
    expect(restoreSegment(lost, { apply: true, reason: "x" }).restored).toBe(true);
    for (let i = 0; i < 500; i++) appendAudit("learning.save", { more: i });
    const r = rotateAuditLog({ maxRecords: 2000 });
    expect(r.segmentFile).toBe("audit-0004.jsonl");
    expect(verifyChain().ok).toBe(true);
  });
});
