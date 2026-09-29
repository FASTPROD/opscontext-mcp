// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at fleet health, and [DOUBLED-IS-THE-SAME-INPUT-TWICE].
// E2E_REVIEW_2026-09 C6-5 (tailLines read 0 events on an unreadable log; a failed daily backup was
// never counted) and C6-6 (28 "doubled" hook events on 2026-09-29 were 28 distinct Edits on one file,
// one record per call, hooks running one after the other about 1 s apart).
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { computeFleetHealth } from "../src/fleet-health.js";

const HOME = process.env.HOME as string; // the throwaway home of src/test-setup.ts
const rep = { servers: [], removed: 0, warnings: [] as string[] };
const now = new Date();
const notRoot = (process.getuid?.() ?? 1) !== 0;
const rec = (event: string, payload: Record<string, unknown>, msAgo: number) =>
  JSON.stringify({ ts: new Date(now.getTime() - msAgo).toISOString(), event, actor: "t", payload, prev_hash: "0", hash: "0" });
function health(lines: string[]) {
  const h = mkdtempSync(join(HOME, "fh-"));
  const audit = join(h, "audit.log");
  writeFileSync(audit, lines.join("\n") + "\n");
  return { h, audit, run: () => computeFleetHealth({ now, auditPath: audit, report: rep, settingsPath: join(h, "no-such.json") }) };
}

describe("fleet health on a live log it cannot read", () => {
  it.skipIf(!notRoot)("says the log could not be read instead of counting zero of everything", () => {
    const { h, audit, run } = health([rec("hook.block", { check: "secret-scan" }, 60_000)]);
    chmodSync(audit, 0o000);
    try {
      const fh = run();
      expect(fh.auditLog.readError).toMatch(/EACCES/);
      expect(fh.warnings.some((w) => /live audit log could not be read/.test(w))).toBe(true);
    } finally {
      chmodSync(audit, 0o644);
      rmSync(h, { recursive: true, force: true });
    }
  });

  it("a readable log has no read error and counts its block", () => {
    const { h, run } = health([rec("hook.block", { check: "secret-scan" }, 60_000)]);
    try {
      const fh = run();
      expect(fh.auditLog.readError).toBeNull();
      expect(fh.today.blocks).toBe(1);
    } finally { rmSync(h, { recursive: true, force: true }); }
  });
});

describe("a failed daily learnings backup", () => {
  it("is a measured problem with its error, not silence", () => {
    const { h, run } = health([rec("learning.backup_failed", { path: "learnings.json.bak-20260929", error: "EACCES: permission denied" }, 60_000)]);
    try {
      const fh = run();
      expect(fh.today.backupFailures).toBe(1);
      expect(fh.warnings.some((w) => /daily learnings backup failed/.test(w) && /EACCES/.test(w))).toBe(true);
    } finally { rmSync(h, { recursive: true, force: true }); }
  });
});

describe("doubled hook events mean the same call recorded twice", () => {
  const edit = (input_chars: number, msAgo: number) =>
    rec("vscode.tool_call", { surface: "claude-code", tool: "Edit", args_preview: "/x/index.html", input_chars, session: "s", cwd: "/x" }, msAgo);
  it("two identical records 1 s apart count as one doubled event", () => {
    const { h, run } = health([edit(120, 61_000), edit(120, 60_000)]);
    try { expect(run().today.doubledHookEvents).toBe(1); } finally { rmSync(h, { recursive: true, force: true }); }
  });
  it("two Edits on one file with different inputs 1 s apart are two calls, not a double", () => {
    const { h, run } = health([edit(120, 61_000), edit(340, 60_000)]);
    try { expect(run().today.doubledHookEvents).toBe(0); } finally { rmSync(h, { recursive: true, force: true }); }
  });
});
