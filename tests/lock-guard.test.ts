// [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE] (src/ingest.ts). E2E_REVIEW_2026-09 batch 3 finding: the fleet's LOCK
// blocks were invisible to the indexer's lock patterns, and the only banner said "do not re-audit".
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { lockBlockTags, lockGuardLine, ingestSources } from "../src/ingest.js";
import { parseCodeFile } from "../src/code-chunker.js";

const BLOCK = [
  "// [LOCKED] [DEMO-GUARD] - 2026-09-30",
  "// [NEVER] remove the check below.",
  "// WHY: it once let a bad record through.",
  "// FIX: keep it.",
].join("\n");

describe("a whole LOCK block in code is flagged, with its own words", () => {
  it("a code chunk holding a whole block names its tag", () => {
    const dir = mkdtempSync(join(tmpdir(), "ce-lockguard-"));
    const f = join(dir, "demo.ts");
    // Inside the body: the chunker keeps a function's body, not the comment lines above it.
    const inBody = BLOCK.split("\n").map((l) => "  " + l).join("\n");
    writeFileSync(f, `export function check(x: number): boolean {\n${inBody}\n  return x > 0;\n}\n`);
    const flagged = parseCodeFile(f, "demo").filter((c) => c.guardedBy);
    expect(flagged.length).toBeGreaterThan(0);
    expect(flagged[0].guardedBy).toEqual(["DEMO-GUARD"]);
  });

  it("the older header that opened with the emoji counts too", () => {
    expect(lockBlockTags("// \u{1F512} LOCKED [OLD-FORM] 2026-06-01\n// ⛔ NEVER do it\n// WHY: because")).toEqual(["OLD-FORM"]);
  });

  it("a cross-reference, or a header without its NEVER and WHY lines, is not a block", () => {
    expect(lockBlockTags("// [LOCK] [DEMO-GUARD] see src/x.ts\nconst a = 1;")).toEqual([]);
    expect(lockBlockTags("// [LOCKED] [DEMO-GUARD] - 2026-09-30\nconst a = 1;")).toEqual([]);
  });

  it("a doc that explains the convention is never flagged", () => {
    const dir = mkdtempSync(join(tmpdir(), "ce-lockguard-doc-"));
    const f = join(dir, "CONVENTION.md");
    writeFileSync(f, "# Convention\n\n## LOCK blocks\n\n```\n" + BLOCK + "\n```\n");
    const chunks = ingestSources([{ name: "doc", path: f, type: "markdown" }]);
    expect(chunks.length).toBeGreaterThan(0);
    expect(chunks.some((c) => c.guardedBy)).toBe(false);
  });

  it("the result line asks for the WHY, never for no one to look", () => {
    const line = lockGuardLine(["DEMO-GUARD", "OTHER"]);
    expect(line).toBe("Guarded by LOCK [DEMO-GUARD] [OTHER]: read its WHY before changing this code.");
    expect(line).not.toMatch(/re-audit/i);
  });
});
