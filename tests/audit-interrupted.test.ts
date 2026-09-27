// [LOCK] [AN-INTERRUPTED-MOVE-IS-FINISHED], [SCRUB-ACKNOWLEDGES-BEFORE-IT-REWRITES].
// E2E_REVIEW_2026-09 B2-2, B2-3, B3-1, B3-3: real CLI processes killed at one exact write (a preload
// sends SIGKILL right after the named file call), then what the next rotation, restore or scrub does.
// Every test here fails on the code before the fix.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, existsSync, utimesSync, mkdirSync, renameSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { execFileSync } from "child_process";
import {
  verifyChain,
  rotateAuditLog,
  autoRotateAuditLog,
  restoreSegment,
  scrubAuditLog,
  resetCacheForTest,
  type AuditRecord,
} from "../src/audit.js";
import { redactPayload } from "../src/secret-shapes.js";

const CLI = join(process.cwd(), "dist", "cli.js");
let home: string;
let original: string | undefined;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-interrupted-"));
  original = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
  resetCacheForTest();
  writeFileSync(
    join(home, "kill-at.cjs"),
    `const fs = require("fs"); const { syncBuiltinESMExports } = require("module");
const [when, fn, pat] = process.env.PB_KILL.split(":");
const orig = fs[fn];
fs[fn] = function (...a) {
  const hit = a.slice(0, 2).some((x) => typeof x === "string" && x.includes(pat));
  if (hit && when === "before") process.kill(process.pid, "SIGKILL");
  const r = orig.apply(this, a);
  if (hit && when === "after") process.kill(process.pid, "SIGKILL");
  return r;
};
syncBuiltinESMExports();
`,
  );
});

afterEach(() => {
  if (original === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = original;
  rmSync(home, { recursive: true, force: true });
});

const fakeKey = () => ["s", "k", "_", "te", "st_"].join("") + createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 24);
const KEY_RE = new RegExp(["s", "k", "_te", "st_"].join("") + "[0-9a-f]{24}", "g");

/** A chain written straight to the live log. Every `secretEvery`-th record carries a fake key in a capture record. */
function seed(count: number, secretEvery = 0): void {
  const recs: string[] = [];
  let prev = "0".repeat(64);
  const t0 = Date.now() - count;
  for (let i = 0; i < count; i++) {
    const ts = new Date(t0 + i).toISOString();
    const withKey = secretEvery > 0 && i % secretEvery === 0;
    const event = withKey ? "vscode.tool_call" : "learning.save";
    const payload = withKey ? { tool: "Bash", args_preview: `export KEY=${fakeKey()}` } : { id: `L${i}` };
    const hash = createHash("sha256").update(JSON.stringify({ prev_hash: prev, ts, event, actor: "system", payload })).digest("hex");
    recs.push(JSON.stringify({ ts, event, actor: "system", payload, prev_hash: prev, hash }));
    prev = hash;
  }
  writeFileSync(join(home, "audit.log"), recs.join("\n") + "\n");
}

/** Run the real CLI with a SIGKILL at `kill` (when:fsFunction:pathPart). Returns the signal. */
function cliKilledAt(kill: string, args: string[]): string | null {
  const env = { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: home, PB_KILL: kill };
  try {
    execFileSync(process.execPath, ["--require", join(home, "kill-at.cjs"), CLI, ...args], { env, stdio: "ignore" });
    return null;
  } catch (e: any) {
    return e.signal ?? null;
  }
}

/** A crashed holder's locks, aged past their stale limits. */
function ageLocks(): void {
  const old = new Date(Date.now() - 11 * 60_000);
  for (const l of ["audit.rotate.lock", "audit.lock"]) if (existsSync(join(home, l))) utimesSync(join(home, l), old, old);
}

function allRecords(): AuditRecord[] {
  const out: AuditRecord[] = [];
  const adir = join(home, "audit-archive");
  const files = existsSync(adir) ? readdirSync(adir).filter((f) => /^audit-\d+.*\.jsonl$/.test(f)).sort().map((f) => join(adir, f)) : [];
  for (const f of [...files, join(home, "audit.log")]) {
    for (const line of readFileSync(f, "utf-8").split("\n")) if (line) out.push(JSON.parse(line));
  }
  return out;
}

describe("a rotation interrupted after placing its segment", () => {
  it("is finished by the next rotation: nothing archived twice, the missing record chained", () => {
    seed(5000);
    expect(cliKilledAt("after:unlinkSync:.audit-0001.jsonl.tmp", ["audit-rotate", "--max-records", "2500"])).toBe("SIGKILL");
    ageLocks();
    const r = rotateAuditLog({ maxRecords: 2500 });
    expect(r.rotated).toBe(true);

    const recs = allRecords();
    const hashes = recs.map((x) => x.hash);
    expect(new Set(hashes).size).toBe(hashes.length);
    const late = recs.filter((x) => x.event === "audit.rotate" && (x.payload as any).segment === "audit-0001.jsonl");
    expect(late).toHaveLength(1);
    expect(late[0].payload).toMatchObject({ completed_after_interruption: true, duplicates_dropped: 2500, archived_records: 2500 });
    const v = verifyChain();
    expect(v.ok).toBe(true);
    expect(v.duplicateIndices).toEqual([]);
  });
});

describe("a rotation interrupted after cutting the live log", () => {
  it("gets its audit.rotate record from auto-rotation, even below the trigger", () => {
    seed(5000);
    expect(cliKilledAt("after:renameSync:.audit.log.tmp", ["audit-rotate", "--max-records", "2500"])).toBe("SIGKILL");
    ageLocks();
    const o = autoRotateAuditLog({ trigger: 1_000_000 });
    expect(o.action).toBe("finished");
    const rec = allRecords().filter((x) => x.event === "audit.rotate");
    expect(rec).toHaveLength(1);
    expect(rec[0].payload).toMatchObject({ segment: "audit-0001.jsonl", completed_after_interruption: true, duplicates_dropped: 0 });
    expect(verifyChain().ok).toBe(true);
  });
});

describe("a restore interrupted after placing its block", () => {
  it("gets its audit.restore record, with the reason given, at the next holder of the lock", () => {
    seed(6000);
    for (const max of [5000, 4000, 3000]) expect(rotateAuditLog({ maxRecords: max }).rotated).toBe(true);
    const lost = join(home, "lost-0002.jsonl");
    renameSync(join(home, "audit-archive", "audit-0002.jsonl"), lost);
    expect(verifyChain().orphanIndices?.length).toBe(1);

    expect(cliKilledAt("after:linkSync:audit-0001-r1.jsonl", ["audit-restore", lost, "--apply", "--reason", "put back from the Tuesday backup"])).toBe("SIGKILL");
    ageLocks();
    const again = restoreSegment(lost, { apply: true, reason: "retry" });
    expect(again.restored).toBe(false); // its records are in the log already

    const rec = allRecords().filter((x) => x.event === "audit.restore");
    expect(rec).toHaveLength(1);
    expect(rec[0].payload).toMatchObject({ segment: "audit-0001-r1.jsonl", reason: "put back from the Tuesday backup", completed_after_interruption: true });
    expect(verifyChain().ok).toBe(true);
  });
});

describe("a leftover temp file", () => {
  it("does not keep a scrubbed secret", () => {
    seed(5000, 50);
    expect(cliKilledAt("after:linkSync:audit-0001.jsonl", ["audit-rotate", "--max-records", "2500"])).toBe("SIGKILL");
    expect(existsSync(join(home, "audit-archive", ".audit-0001.jsonl.tmp"))).toBe(true);
    ageLocks();
    const r = scrubAuditLog({ apply: true, reason: "test keys", redact: redactPayload });
    expect(r.refusedReason).toBeNull();
    const everyFile = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? everyFile(join(dir, d.name)) : [join(dir, d.name)]));
    const left = everyFile(home).filter((f) => !f.endsWith(".cjs")).reduce((n, f) => n + (readFileSync(f, "utf-8").match(KEY_RE)?.length ?? 0), 0);
    expect(left).toBe(0);
  });
});

describe("a scrub interrupted right after rewriting a segment", () => {
  it("leaves no record reported as altered", () => {
    seed(5000, 50);
    expect(rotateAuditLog({ maxRecords: 2500 }).rotated).toBe(true);
    expect(cliKilledAt("after:renameSync:.audit-0001.jsonl.scrub.tmp", ["audit-scrub", "--apply", "--reason", "test keys"])).toBe("SIGKILL");
    const v = verifyChain();
    expect(v.tamperedIndices).toEqual([]);
    expect(v.redactedIndices?.length).toBe(50);
    expect(v.ok).toBe(true);
  });
});

describe("audit-verify on altered records", () => {
  it("lists every altered index in the command it suggests", () => {
    seed(40);
    const path = join(home, "audit.log");
    const lines = readFileSync(path, "utf-8").split("\n");
    const altered = [2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35];
    for (const i of altered) {
      const r = JSON.parse(lines[i]);
      r.payload = { id: "changed" };
      lines[i] = JSON.stringify(r);
    }
    writeFileSync(path, lines.join("\n"));
    mkdirSync(home, { recursive: true });
    let out = "";
    try {
      execFileSync(process.execPath, [CLI, "audit-verify"], { env: { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: home }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e: any) {
      out = String(e.stderr);
    }
    expect(out).toContain(`audit-redact-ack --index ${altered.join(",")} `);
  });
});

describe("a note cut short by the same crash", () => {
  it("is removed, so auto-rotation stops finding work on every run", () => {
    seed(100);
    mkdirSync(join(home, "audit-archive"), { recursive: true });
    writeFileSync(join(home, "audit-archive", ".rotate-intent.json"), '{"segment":"audit-00');
    expect(autoRotateAuditLog({ trigger: 1_000_000 }).action).toBe("finished");
    expect(existsSync(join(home, "audit-archive", ".rotate-intent.json"))).toBe(false);
    expect(autoRotateAuditLog({ trigger: 1_000_000 }).action).toBe("below_trigger");
  });
});

describe("audit-verify shows who acknowledged a redaction, when and why", () => {
  it("lists each acknowledgement the verdict relied on", () => {
    seed(200, 50);
    expect(scrubAuditLog({ apply: true, reason: "planted test keys removed", redact: redactPayload, actor: "cli" }).redactedRecords).toBe(4);
    const v = verifyChain();
    expect(v.ok).toBe(true);
    expect(v.acknowledgements).toHaveLength(1);
    expect(v.acknowledgements![0]).toMatchObject({ actor: "cli", reason: "planted test keys removed", records: 4 });
    const out = execFileSync(process.execPath, [CLI, "audit-verify"], { env: { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: home }, encoding: "utf8" });
    expect(out).toMatch(/Acknowledged by .*cannot tell a removal from a rewrite/);
    expect(out).toMatch(/cli {2}4 record\(s\) {2}"planted test keys removed"/);
  });
});
