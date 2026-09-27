// [LOCK] [A-READ-NEVER-WRITES-THE-STORE]. E2E_REVIEW_2026-09 B4-1: a plain read merged a missing
// bundled default and wrote the whole store without the lock (a concurrent save was lost when that
// read was slowed), and a deleted default came back at the next read with no audit record.
// Throwaway ~/.contextengine per worker via src/test-setup.ts; learnings.ts fixes its path at import.
import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync, writeFileSync, rmSync, mkdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import * as L from "../src/learnings.js";

const home = () => process.env.CONTEXTENGINE_HOME as string;
const store = () => join(home(), "learnings.json");
const defaults = JSON.parse(readFileSync(join(process.cwd(), "defaults", "learnings.json"), "utf8")) as Array<{ rule: string; category: string; context: string }>;
const auditRecords = () =>
  existsSync(join(home(), "audit.log"))
    ? readFileSync(join(home(), "audit.log"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];

/** A store with every bundled default except the first, plus one ordinary learning. */
function storeMissingOneDefault(): void {
  const now = new Date().toISOString();
  const learnings = [
    ...defaults.slice(1).map((d, i) => ({ id: `d${i}`, category: d.category, rule: d.rule, context: d.context, tags: [], created: now, updated: now })),
    { id: "own1", category: "testing", rule: "An ordinary learning written by the owner for this test", context: "c", tags: [], created: now, updated: now },
  ];
  writeFileSync(store(), JSON.stringify({ version: 1, count: learnings.length, learnings }, null, 2));
}

beforeEach(() => {
  mkdirSync(home(), { recursive: true });
  rmSync(join(home(), "learnings.json.lock"), { recursive: true, force: true });
  rmSync(join(home(), "audit.log"), { force: true });
});

describe("a read and the bundled defaults", () => {
  it("never writes the store while another process holds the lock (it only shows the default)", () => {
    storeMissingOneDefault();
    const holder = spawn("sleep", ["30"]);
    const before = statSync(store());
    const timeout = process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS;
    try {
      mkdirSync(join(home(), "learnings.json.lock"));
      writeFileSync(join(home(), "learnings.json.lock", "pid"), String(holder.pid));
      process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS = "300";
      const shown = L.listLearnings().map((l) => l.rule);
      expect(shown).toContain(defaults[0].rule);
      const after = statSync(store());
      expect(after.ino).toBe(before.ino);
      expect(after.mtimeMs).toBe(before.mtimeMs);
    } finally {
      if (timeout === undefined) delete process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS;
      else process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS = timeout;
      holder.kill();
      rmSync(join(home(), "learnings.json.lock"), { recursive: true, force: true });
    }
  });

  it("persists a missing default under the lock and records it", () => {
    storeMissingOneDefault();
    L.listLearnings();
    const onDisk = JSON.parse(readFileSync(store(), "utf8")).learnings.map((l: { rule: string }) => l.rule);
    expect(onDisk).toContain(defaults[0].rule);
    const rec = auditRecords().filter((r) => r.event === "learning.import" && r.payload.source === "bundled defaults");
    expect(rec).toHaveLength(1);
    expect(rec[0].payload.imported).toBe(1);
  });

  it("does not bring back a default the owner deleted", () => {
    storeMissingOneDefault();
    L.listLearnings(); // all defaults present now
    const target = L.listLearnings().find((l) => l.rule === defaults[2].rule)!;
    expect(L.deleteLearning(target.id)).toBe(true);
    expect(L.listLearnings().some((l) => l.rule === defaults[2].rule)).toBe(false);
    expect(L.listLearnings().some((l) => l.rule === defaults[2].rule)).toBe(false);
    const del = auditRecords().filter((r) => r.event === "learning.delete");
    expect(del.at(-1)!.payload.default_dismissed).toBe(true);
  });
});
