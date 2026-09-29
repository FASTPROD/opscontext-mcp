// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at the build fingerprint. E2E_REVIEW_2026-09 C6-5: buildHashOf()
// returned null for a missing script and for one it could not read alike, `servers` said "script
// missing on disk" for both, and the stale-build check silently skipped the server.
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildHashOf, buildHashOrError } from "../src/server-registry.js";

const notRoot = (process.getuid?.() ?? 1) !== 0;

describe("buildHashOrError", () => {
  it("a readable build has a 12-character hash and no error", () => {
    const d = mkdtempSync(join(tmpdir(), "ce-build-"));
    const dist = join(d, "dist"); mkdirSync(dist);
    writeFileSync(join(dist, "index.js"), "export const v = 1;\n");
    try {
      const b = buildHashOrError(join(dist, "index.js"));
      expect(b.error).toBeNull();
      expect(b.hash).toMatch(/^[0-9a-f]{12}$/);
      expect(buildHashOf(join(dist, "index.js"))).toBe(b.hash);
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
  it("a missing script says so", () => {
    expect(buildHashOrError("/nonexistent/for/sure/dist/index.js")).toEqual({ hash: null, error: "script missing on disk" });
  });
  it.skipIf(!notRoot)("a build folder it cannot read carries the error, not 'missing'", () => {
    const d = mkdtempSync(join(tmpdir(), "ce-build-"));
    const dist = join(d, "dist"); mkdirSync(dist);
    writeFileSync(join(dist, "index.js"), "export const v = 1;\n");
    chmodSync(dist, 0o000);
    try {
      const b = buildHashOrError(join(dist, "index.js"));
      expect(b.hash).toBeNull();
      expect(b.error).toMatch(/EACCES/);
    } finally { chmodSync(dist, 0o755); rmSync(d, { recursive: true, force: true }); }
  });
});
