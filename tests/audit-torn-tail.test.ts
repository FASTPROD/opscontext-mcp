// [LOCK] [TORN-TAIL-IS-KEPT-AND-CHAINED], [VERIFY-READS-PAST-AN-UNREADABLE-LINE],
// [A-REFUSED-APPEND-IS-COUNTED-AND-CHAINED]. E2E_REVIEW_2026-09 B1-1: a full disk cut one record in
// half, every later append was refused for good, and audit-verify said "0 record(s) checked".
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, appendFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { appendAudit, safeAppend, verifyChain, readAuditLog, resetCacheForTest } from "../src/audit.js";

let home: string;
let original: string | undefined;
const log = () => join(home, "audit.log");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-torn-test-"));
  original = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
  resetCacheForTest();
});

afterEach(() => {
  if (original === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = original;
  rmSync(home, { recursive: true, force: true });
});

function seed(n: number): void {
  for (let i = 0; i < n; i++) appendAudit("learning.save", { id: `L${i}` });
}

describe("a last record cut short", () => {
  it("is set aside byte for byte, noted on the chain, and the log goes on", () => {
    seed(10);
    const lastComplete = readAuditLog().at(-1)!.hash;
    const fragment = '{"ts":"2026-09-27T10:00:00.000Z","event":"vscode.tool_call","actor":"probe","payload":{"pad":"xxxxxxxx';
    appendFileSync(log(), fragment);

    const rec = appendAudit("learning.save", { id: "after" });

    const kept = readdirSync(home).filter((f) => f.startsWith("audit.torn-") && f.endsWith(".partial"));
    expect(kept).toHaveLength(1);
    expect(readFileSync(join(home, kept[0]), "utf-8")).toBe(fragment);
    const recs = readAuditLog();
    expect(recs).toHaveLength(12);
    const note = recs[10];
    expect(note.event).toBe("audit.torn_tail");
    expect(note.prev_hash).toBe(lastComplete);
    expect(note.payload).toMatchObject({ kept: kept[0], bytes: Buffer.byteLength(fragment), sha256: createHash("sha256").update(fragment).digest("hex") });
    expect(rec.prev_hash).toBe(note.hash);
    expect(verifyChain().ok).toBe(true);
  });

  it("only gets its newline back when the fragment is a whole record", () => {
    seed(5);
    writeFileSync(log(), readFileSync(log(), "utf-8").replace(/\n$/, "")); // the final newline lost
    appendAudit("learning.save", { id: "after" });
    expect(readdirSync(home).some((f) => f.endsWith(".partial"))).toBe(false);
    const r = verifyChain();
    expect(r.ok).toBe(true);
    expect(r.total).toBe(6);
  });

  it("still refuses when the log holds no complete record to continue from", () => {
    writeFileSync(log(), '{"ts":"2026-09-27T10:00:00.000Z","event":"learn');
    expect(() => appendAudit("learning.save", { id: "x" })).toThrow(/not valid JSON/);
    expect(readFileSync(log(), "utf-8")).toBe('{"ts":"2026-09-27T10:00:00.000Z","event":"learn');
  });

  it("still refuses a complete last line that is not a record ([UNREADABLE-HEAD-IS-NOT-GENESIS])", () => {
    seed(3);
    appendFileSync(log(), "garbage that someone typed\n");
    expect(() => appendAudit("learning.save", { id: "x" })).toThrow(/not valid JSON/);
  });
});

describe("the verifier reads past a line that is not a record", () => {
  it("names the line, checks every other record, and fails", () => {
    seed(10);
    const lines = readFileSync(log(), "utf-8").split("\n");
    lines.splice(4, 0, "not a record");
    writeFileSync(log(), lines.join("\n"));
    const r = verifyChain();
    expect(r.ok).toBe(false);
    expect(r.total).toBe(10);
    expect(r.unreadable).toEqual([{ file: "audit.log", line: 5, beforeIndex: 4 }]);
    expect(r.tamperedIndices).toEqual([]);
    expect(r.breakReason).toMatch(/audit\.log line 5/);
  });
});

describe("a refused append is counted and put on the chain", () => {
  it("safeAppend says false, and the next good append chains an audit.append_failed record", () => {
    seed(3);
    const good = readFileSync(log(), "utf-8");
    appendFileSync(log(), "garbage that someone typed\n"); // stuck: every append refused
    expect(safeAppend("vscode.tool_call", { tool: "Edit" }, "claude-code")).toBe(false);
    expect(safeAppend("vscode.tool_call", { tool: "Bash" }, "claude-code")).toBe(false);
    expect(existsSync(join(home, "audit-refused.jsonl"))).toBe(true);

    writeFileSync(log(), good); // the owner repairs the log
    expect(safeAppend("learning.save", { id: "after" })).toBe(true);

    const recs = readAuditLog();
    const gap = recs.find((r) => r.event === "audit.append_failed")!;
    expect(gap).toBeDefined();
    expect(gap.payload).toMatchObject({ count: 2, events: { "vscode.tool_call": 2 } });
    expect(recs.at(-1)!.payload).toEqual({ id: "after" });
    expect(existsSync(join(home, "audit-refused.jsonl"))).toBe(false);
    expect(verifyChain().ok).toBe(true);
  });
});
