// [LOCK] [ROTATION-SNAPSHOT-IS-THE-BYTES-READ] and the duplicate class of [VERIFY-FORK-IS-NOT-TAMPER].
// E2E_REVIEW_2026-09 B2-1: a rotation that ran while entries arrived kept them twice, and the
// verifier called the copy a concurrent-append fork. Both tests fail on the code before the fix.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { spawn } from "child_process";
import { verifyChain, rotateAuditLog, type AuditRecord } from "../src/audit.js";

let home: string;
let original: string | undefined;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-dup-test-"));
  original = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
});

afterEach(() => {
  if (original === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = original;
  rmSync(home, { recursive: true, force: true });
});

function chain(count: number, tag = "L"): AuditRecord[] {
  const out: AuditRecord[] = [];
  let prev = "0".repeat(64);
  const t0 = Date.now() - count;
  for (let i = 0; i < count; i++) {
    const ts = new Date(t0 + i).toISOString();
    const payload = { id: `${tag}${i}` };
    const hash = createHash("sha256").update(JSON.stringify({ prev_hash: prev, ts, event: "learning.save", actor: "system", payload })).digest("hex");
    out.push({ ts, event: "learning.save", actor: "system", payload, prev_hash: prev, hash } as AuditRecord);
    prev = hash;
  }
  return out;
}

const write = (recs: AuditRecord[]) =>
  writeFileSync(join(home, "audit.log"), recs.map((r) => JSON.stringify(r)).join("\n") + "\n");

describe("verifier: a second copy of a record is a duplicate, not a fork", () => {
  it("reports the copied block as duplicates, links the record after it, and stays ok", () => {
    // The shape found in audit-0062.jsonl: 20 records, then the same 20 again, then the chain goes on.
    const recs = chain(100);
    write([...recs.slice(0, 60), ...recs.slice(40, 60), ...recs.slice(60)]);
    const r = verifyChain();
    expect(r.ok).toBe(true);
    expect(r.forkIndices).toEqual([]);
    expect(r.orphanIndices).toEqual([]);
    expect(r.duplicateIndices).toEqual(Array.from({ length: 20 }, (_, i) => 60 + i));
    expect(r.total - (r.duplicateIndices ?? []).length).toBe(100);
  });

  it("still calls an altered copy altered", () => {
    const recs = chain(10);
    const copy = { ...recs[4], payload: { id: "changed" } };
    write([...recs.slice(0, 6), copy, ...recs.slice(6)]);
    const r = verifyChain();
    expect(r.tamperedIndices).toEqual([6]);
    expect(r.duplicateIndices).toEqual([6]);
    expect(r.ok).toBe(false);
  });

  it("still reports a deleted record as an orphan even when a copy of another stands in its place", () => {
    const recs = chain(10);
    write([...recs.slice(0, 5), recs[2], ...recs.slice(6)]); // record 5 replaced by a copy of record 2
    const r = verifyChain();
    expect(r.duplicateIndices).toEqual([5]);
    expect(r.orphanIndices).toEqual([6]);
    expect(r.ok).toBe(false);
  });
});

describe("rotation while real processes append", () => {
  it("keeps every record exactly once", async () => {
    const dist = join(process.cwd(), "dist", "audit.js");
    expect(existsSync(dist)).toBe(true);
    write(chain(120_000));
    const worker = join(home, "appender.mjs");
    writeFileSync(
      worker,
      `const { appendAudit } = await import(${JSON.stringify(dist)});\n` +
        `for (let k = 0; k < 2500; k++) appendAudit("learning.save", { w: process.argv[2], k });\n`,
    );
    const env = { ...process.env, CONTEXTENGINE_HOME: home };
    const done = Array.from({ length: 4 }, (_, w) =>
      new Promise<void>((resolve, reject) => {
        const p = spawn(process.execPath, [worker, `w${w}`], { env, stdio: "ignore" });
        p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`appender exited ${code}`))));
      }),
    );
    await new Promise((r) => setTimeout(r, 400)); // let the appenders get going
    const rot = rotateAuditLog({ maxRecords: 50_000 });
    await Promise.all(done);
    expect(rot.rotated).toBe(true);

    // Count every record in the segments and the live log, by hash.
    const files = [
      ...readdirSync(join(home, "audit-archive")).filter((f) => f.endsWith(".jsonl")).map((f) => join(home, "audit-archive", f)),
      join(home, "audit.log"),
    ];
    const counts = new Map<string, number>();
    for (const f of files) {
      for (const line of readFileSync(f, "utf-8").split("\n")) {
        if (!line) continue;
        const h = (JSON.parse(line) as AuditRecord).hash;
        counts.set(h, (counts.get(h) ?? 0) + 1);
      }
    }
    const twice = [...counts.values()].filter((n) => n > 1).length;
    expect(twice).toBe(0);
    expect(counts.size).toBe(120_000 + 4 * 2500 + 1); // + the audit.rotate record
    const r = verifyChain();
    expect(r.ok).toBe(true);
    expect(r.duplicateIndices).toEqual([]);
  }, 60_000);
});
