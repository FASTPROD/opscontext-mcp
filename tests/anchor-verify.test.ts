// `anchor verify` and `anchor export-evidence`. [LOCK] [VERIFY-TRUSTS-ONLY-PINNED-ROOTS] (src/anchor-verify.ts)
// [LOCK] [VERIFY-READS-THE-LOG-AS-IT-STOOD] (src/anchor-window.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { appendAudit, restoreSegment, rotateAuditLog, listSegments } from "../src/audit.js";
import { anchorTick, newConfig, writeConfig, listCheckpoints, anchorsDir } from "../src/anchor.js";
import { verifyAnchors, formatVerify, exportEvidence } from "../src/anchor-verify.js";
import { findOpenssl } from "../src/anchor-tsa.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";

const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;

let tsaA: FakeTsa;
let tsaB: FakeTsa;
let keys: string;
let home: string;
const saved: Record<string, string | undefined> = {};

beforeAll(async () => {
  if (!haveOpenssl) return;
  keys = mkdtempSync(join(tmpdir(), "ce-anchor-vkeys-"));
  tsaA = await startFakeTsa(keys, "test-a");
  tsaB = await startFakeTsa(keys, "test-b");
});
afterAll(async () => {
  if (!haveOpenssl) return;
  await tsaA.close().catch(() => undefined);
  await tsaB.close().catch(() => undefined);
  rmSync(keys, { recursive: true, force: true });
});
beforeEach(() => {
  for (const k of ["CONTEXTENGINE_HOME", "CONTEXTENGINE_ANCHOR_TEST_PROVIDERS", "CONTEXTENGINE_WORKSPACES", "OPENSSL"]) saved[k] = process.env[k];
  home = mkdtempSync(join(tmpdir(), "ce-anchor-vhome-"));
  process.env.CONTEXTENGINE_HOME = home;
  process.env.CONTEXTENGINE_WORKSPACES = mkdtempSync(join(tmpdir(), "ce-anchor-vws-"));
  if (haveOpenssl) {
    process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS = JSON.stringify([tsaA.entry(), tsaB.entry()]);
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    tsaA.failNext = 0;
    tsaB.failNext = 0;
  }
  writeConfig(newConfig({ code: false, providers: ["test-a", "test-b"], now: new Date() }));
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(home, { recursive: true, force: true });
});

/** A checkpoint now (the real clock, shifted by `skewS`), whatever the hourly slot says. */
async function checkpointNow(skewS = 0, records = 3): Promise<void> {
  for (let i = 0; i < records; i++) appendAudit("learning.save", { i, at: Date.now() });
  const r = await anchorTick({ now: () => new Date(Date.now() + skewS * 1000), force: true, timeoutMs: 3000, clientVersion: "test" });
  expect(r.action).toBe("checkpoint");
}

describe.skipIf(!haveOpenssl)("anchor verify", () => {
  it("three checkpoints hold: shape, chain, window, both stamps, a steady clock", async () => {
    await checkpointNow();
    await checkpointNow();
    await checkpointNow();
    const r = verifyAnchors();
    expect(r.lines.length).toBe(3);
    expect(r.holds).toBe(true);
    expect(r.unstamped).toBe(0);
    for (const l of r.lines) {
      expect([l.shape.mark, l.chain.mark, l.window.mark]).toEqual(["OK", "OK", "OK"]);
      expect(l.stamps.map((s) => s.mark)).toEqual(["OK", "OK"]);
      expect(Math.abs(l.offsetS!)).toBeLessThan(5);
      expect(l.flags).toEqual([]);
    }
    expect(r.lines[0].chain.detail).toBe("first of the chain");
    expect(r.lines[2].chain.detail).toBe("chains to #2");
    expect(r.clock).toMatch(/steady/);
    const text = formatVerify(r);
    expect(text).toMatch(/Result: 3 of 3 checkpoint\(s\) hold; 3 stamped and checked\.$/m);
    expect(text).not.toMatch(/sealed/i);
  });

  it("a clock two hours ahead is a constant offset, not a fault; a jump back is flagged", async () => {
    await checkpointNow(7200);
    await checkpointNow(7200);
    await checkpointNow(0);
    const r = verifyAnchors();
    expect(r.holds).toBe(true);
    expect(r.lines[0].offsetS!).toBeLessThan(-7000); // about -2 h (a busy machine adds seconds of stamping)
    expect(r.lines[0].flags).toEqual([]);
    expect(r.lines[1].flags).toEqual([]);
    expect(r.lines[2].flags).toEqual([expect.stringMatching(/^the clock jumped by \+2\.0 h since the previous stamped checkpoint$/)]);
    expect(r.clock).toMatch(/1 jump\(s\) \(#3\)/);
  });

  it("a record hash rewritten in the log fails the checkpoint that covers it, and only that one", async () => {
    await checkpointNow(0, 3);
    await checkpointNow(0, 3);
    const lines = readFileSync(join(home, "audit.log"), "utf8").trimEnd().split("\n");
    const i = lines.length - 2; // inside the second window
    const rec = JSON.parse(lines[i]);
    rec.hash = "e".repeat(64);
    lines[i] = JSON.stringify(rec);
    writeFileSync(join(home, "audit.log"), lines.join("\n") + "\n");
    const r = verifyAnchors();
    expect(r.lines[0].window.mark).toBe("OK");
    expect(r.lines[1].window.mark).toBe("NO");
    expect(r.holds).toBe(false);
  });

  it("an edited checkpoint.json fails its digest and its stamps", async () => {
    await checkpointNow();
    const [c] = listCheckpoints();
    const cp = JSON.parse(readFileSync(join(c.dir, "checkpoint.json"), "utf8"));
    cp.records.count += 1;
    writeFileSync(join(c.dir, "checkpoint.json"), JSON.stringify(cp, null, 2));
    const [l] = verifyAnchors().lines;
    expect(l.shape.mark).toBe("NO");
    expect(l.stamps.map((s) => s.mark)).toEqual(["NO", "NO"]);
    expect(l.stamps[0].detail).toBe("this stamp is for another fingerprint");
  });

  it("a certificate planted in the anchors folder changes nothing: the roots come from the code", async () => {
    await checkpointNow();
    // Replace the convenience copy of test-a's root with test-b's: a stamp checked against the disk would now fail.
    copyFileSync(tsaB.caFile, join(anchorsDir(), "certs", "test-a-ca.pem"));
    const [l] = verifyAnchors().lines;
    expect(l.stamps.map((s) => s.mark)).toEqual(["OK", "OK"]);
  });

  it("no openssl: every stamp is said as not checkable, never passed", async () => {
    await checkpointNow();
    process.env.CONTEXTENGINE_OPENSSL = join(home, "no-such-openssl");
    try {
      const r = verifyAnchors();
      expect(r.lines[0].stamps.map((s) => s.mark)).toEqual(["??", "??"]);
      expect(r.lines[0].stampChecked).toBe(false);
      expect(r.lines[0].stamped).toBe(true); // the stamps are there, only not checkable here
      expect(r.holds).toBe(true);
      const text = formatVerify(r);
      expect(text).toMatch(/OpenSSL not found: the stamps cannot be checked on this machine/);
      expect(text).toMatch(/Result: 1 of 1 checkpoint\(s\) hold; 0 stamped and checked, 1 stamped but not checkable here\./);
    } finally {
      delete process.env.CONTEXTENGINE_OPENSSL;
    }
  });

  it("a stamp that came late (the services were away) is noted and kept out of the clock reading", async () => {
    tsaA.mode = "http503";
    tsaB.mode = "http503";
    for (let i = 0; i < 3; i++) appendAudit("learning.save", { i });
    const made = new Date(Date.now() - 20 * 60_000); // made 20 minutes ago
    expect((await anchorTick({ now: () => made, force: true, timeoutMs: 3000, clientVersion: "test" })).action).toBe("checkpoint");
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    await anchorTick({ now: () => new Date(), timeoutMs: 3000, clientVersion: "test" });
    const [l] = verifyAnchors().lines;
    expect(l.stamps.map((s) => s.mark)).toEqual(["OK", "OK"]);
    expect(l.offsetS).toBeNull();
    expect(l.flags.join(" ")).toMatch(/stamped it 20 min after it was made \(the services were away\)/);
  });

  it("a checkpoint no service stamped is dated through the chain by the next stamped one, and verify says so", async () => {
    tsaA.mode = "http503";
    tsaB.mode = "http503";
    await checkpointNow();
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    tsaA.failNext = 1;
    tsaB.failNext = 1;
    await checkpointNow();
    const r = verifyAnchors();
    expect(r.lines[0].stampChecked).toBe(false);
    expect(r.lines[0].coveredBy?.seq).toBe(2);
    expect(r.lines[0].flags[0]).toMatch(/^no checked stamp of its own: dated through the chain by #2's stamp of .*Z, a later date$/);
    expect(r.unstamped).toBe(0);
    expect(r.summary).toBe("2 of 2 checkpoint(s) hold; 1 stamped and checked, 1 dated through a later stamp");
    // The standalone checker reads the chain the same way.
    const out = join(home, "ev");
    const day = new Date().toISOString().slice(0, 10);
    exportEvidence({ from: day, to: day, out });
    const v = spawnSync(process.execPath, [join(out, "verify.mjs"), out], { encoding: "utf8", env: { ...process.env, OPENSSL: ssl!.path } });
    expect(v.stdout).toMatch(/\[OK\] no checked stamp of its own: dated through the chain by 000002-/);
    expect(v.stdout).toMatch(/Result: 2 checkpoint\(s\), the rule holds\.$/m);
    expect(v.status).toBe(0);
  });

  it("a checkpoint made while a segment was missing verifies, after the restore, without that segment", async () => {
    for (let i = 0; i < 1000; i++) appendAudit("learning.save", { i });
    await checkpointNow(0, 1); // its last record lands in segment 1, which is kept
    for (let i = 0; i < 4000; i++) appendAudit("learning.save", { j: i });
    expect(rotateAuditLog({ maxRecords: 3000 }).rotated).toBe(true);
    for (let i = 0; i < 2100; i++) appendAudit("learning.save", { k: i });
    expect(rotateAuditLog({ maxRecords: 2000 }).rotated).toBe(true);
    expect(listSegments()).toEqual(["audit-0001.jsonl", "audit-0002.jsonl"]);
    // The second segment is lost; a checkpoint is made during the hole; then it is put back.
    const lost = join(home, "backup.jsonl");
    renameSync(join(home, "audit-archive", "audit-0002.jsonl"), lost);
    await checkpointNow(0, 2);
    expect(restoreSegment(lost, { apply: true, reason: "test: back from the backup" }).restored).toBe(true);
    await checkpointNow(0, 2);
    const r = verifyAnchors();
    expect(r.lines.map((l) => l.window.mark)).toEqual(["OK", "OK", "OK"]);
    expect(r.lines[1].window.detail).toBe("records_root recomputed from this machine's log, read without audit-0001-r1.jsonl (restored after this checkpoint)");
    expect(r.lines[2].window.detail).toMatch(/read with every segment$/);
  }, 60_000); // 7,100 appends, two rotations, a restore: 7.5 s under Node 24, 10.8 s alone under Node 20, 17.5 s in a full run (2026-09-30)
});

describe.skipIf(!haveOpenssl)("anchor export-evidence and its standalone checker", () => {
  it("writes the period's checkpoints, stamps and roots; verify.mjs holds offline, with and without the log, and fails on a changed byte", async () => {
    await checkpointNow();
    await checkpointNow();
    const out = join(home, "evidence");
    const day = new Date().toISOString().slice(0, 10);
    const r = exportEvidence({ from: day, to: day, out });
    expect(r.count).toBe(2);
    expect(readdirSync(out).sort()).toEqual(["LISEZMOI.txt", "README.txt", "certs", "checkpoints", "verify.mjs"]);
    const [first] = readdirSync(join(out, "checkpoints")).sort();
    expect(readdirSync(join(out, "checkpoints", first)).sort()).toEqual(["checkpoint.json", "checkpoint.test-a.tsr", "checkpoint.test-b.tsr", "stamps.json"]);
    expect(existsSync(join(out, "certs", "test-a-ca.pem"))).toBe(true);
    const env = { ...process.env, OPENSSL: ssl!.path };
    const run = (...a: string[]) => spawnSync(process.execPath, [join(out, "verify.mjs"), ...a], { encoding: "utf8", env });
    let v = run(out);
    expect(v.stdout).toMatch(/Result: 2 checkpoint\(s\), the rule holds\./);
    expect(v.status).toBe(0);
    v = run(out, join(home, "audit.log"));
    expect(v.stdout.match(/\[OK\] records_root recomputed from the log/g)?.length).toBe(2);
    expect(v.status).toBe(0);
    // Nothing is ever written over.
    expect(() => exportEvidence({ from: day, to: day, out })).toThrow(/exists/);
    // A changed byte in a stamp.
    const tsr = join(out, "checkpoints", first, "checkpoint.test-a.tsr");
    const b = readFileSync(tsr);
    b[b.length - 10] ^= 0xff;
    writeFileSync(tsr, b);
    v = run(out);
    expect(v.stdout).toMatch(/\[NO\] stamp Test TSA test-a/);
    expect(v.status).toBe(1);
  });

  it("an empty period is said, and no folder is made", () => {
    const out = join(home, "none");
    expect(() => exportEvidence({ from: "2001-01-01", to: "2001-01-02", out })).toThrow(/no checkpoint made between/);
    expect(existsSync(out)).toBe(false);
  });
});
