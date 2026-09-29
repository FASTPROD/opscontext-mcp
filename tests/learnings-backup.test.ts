// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at the daily backup and the bundled defaults. E2E_REVIEW_2026-09
// C6-5: the daily copy of learnings.json is the store's only restore path and a copy that failed was
// never reported; malformed bundled defaults were skipped in silence.
// Throwaway ~/.contextengine per worker via src/test-setup.ts; learnings.ts fixes its path at import.
import { describe, it, expect, vi, afterEach } from "vitest";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as L from "../src/learnings.js";

const home = () => process.env.CONTEXTENGINE_HOME as string;
const store = () => join(home(), "learnings.json");
const notRoot = (process.getuid?.() ?? 1) !== 0;
const auditEvents = () =>
  existsSync(join(home(), "audit.log"))
    ? readFileSync(join(home(), "audit.log"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).event as string)
    : [];

describe("the daily learnings backup", () => {
  afterEach(() => {
    try { chmodSync(store(), 0o644); } catch { /* not there */ }
    vi.restoreAllMocks();
  });

  it.skipIf(!notRoot)("a copy that failed is said on stderr and chained, instead of nothing", () => {
    mkdirSync(home(), { recursive: true });
    const now = new Date().toISOString();
    const s = { version: 1, count: 1, learnings: [{ id: "a1", category: "testing", rule: "A rule for the backup test", context: "c", tags: [], created: now, updated: now }] };
    writeFileSync(store(), JSON.stringify(s));
    chmodSync(store(), 0o000); // the copy reads the store: it cannot, and the write that follows still lands
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const before = auditEvents().filter((e) => e === "learning.backup_failed").length;
    L.__writeStoreForTests(s as never);
    const said = err.mock.calls.map((c) => c.join(" ")).filter((line) => /daily learnings backup failed/.test(line));
    expect(said).toHaveLength(1);
    expect(said[0]).toMatch(/EACCES/);
    expect(auditEvents().filter((e) => e === "learning.backup_failed").length).toBe(before + 1);
  });

  it("malformed bundled defaults are said once and yield none, not skipped in silence", () => {
    mkdirSync(home(), { recursive: true });
    const p = join(home(), "bad-defaults.json");
    writeFileSync(p, "{ not json");
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(L.loadBundledDefaults(p)).toEqual([]);
    expect(err.mock.calls.map((c) => c.join(" ")).some((line) => line.includes("bundled defaults") && line.includes(p))).toBe(true);
  });
});
