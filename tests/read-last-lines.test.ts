import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readLastLines } from "../src/collectors.js";

// E2E_REVIEW_2026-09 A1-1: shell history is read directly, not through `tail -200 ${path}`,
// whose path came from HOME and was pasted into a shell string.
describe("readLastLines", () => {
  const dir = mkdtempSync(join(tmpdir(), "ce last lines $(x) "));

  it("returns the last lines of a file whose path has a space and shell characters", () => {
    const f = join(dir, ".zsh_history");
    writeFileSync(f, Array.from({ length: 300 }, (_, i) => `: 1700000000:0;cmd ${i}`).join("\n") + "\n");
    const out = readLastLines(f, 200).split("\n");
    expect(out).toHaveLength(200);
    expect(out[0]).toBe(": 1700000000:0;cmd 100");
    expect(out[199]).toBe(": 1700000000:0;cmd 299");
  });

  it("drops the line cut by the 256 KB window of a large file", () => {
    const f = join(dir, "big");
    const line = "x".repeat(999);
    writeFileSync(f, Array.from({ length: 400 }, (_, i) => `${i}:${line}`).join("\n"));
    const out = readLastLines(f, 1000).split("\n");
    expect(out[out.length - 1].startsWith("399:")).toBe(true);
    expect(out.every((l) => /^\d+:x+$/.test(l))).toBe(true);
  });
});
