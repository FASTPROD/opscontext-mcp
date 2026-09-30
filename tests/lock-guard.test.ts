// [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE] (src/ingest.ts). E2E_REVIEW_2026-09 batch 3 finding: the fleet's LOCK
// blocks were invisible to the indexer's lock patterns, and the only banner said "do not re-audit".
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { lockBlockTags, lockGuardLine, ingestSources } from "../src/ingest.js";
import { parseCodeFile, scanCodeDir } from "../src/code-chunker.js";

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
    // Inside the body.
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

// [LOCK] [EVERY-LOCK-BLOCK-IS-FINDABLE] (src/code-chunker.ts). E2E_REVIEW_2026-09 batch 5: of the LOCK headers in the
// fleet's indexed code, 34 chunks were flagged; the blocks above functions, at file tops, above constants and in
// files over 100 KB never reached the index. Every test here but the three guards fails on the code before.
const block = (tag: string, indent = "") => BLOCK.replace("DEMO-GUARD", tag).split("\n").map((l) => indent + l).join("\n");
const tmpFile = (name: string, text: string) => {
  const dir = mkdtempSync(join(tmpdir(), "ce-every-lock-"));
  const f = join(dir, name);
  writeFileSync(f, text);
  return f;
};
const pieces = (chunks: ReturnType<typeof parseCodeFile>) => chunks.filter((c) => / > LOCK \[/.test(c.section));

describe("every whole LOCK block in indexed code is findable", () => {
  it("a block directly above a function is part of its chunk, which starts at the block", () => {
    const f = tmpFile("above.ts", `import { x } from "./x.js";\n\n${block("ABOVE-FN")}\nexport function guarded(a: number): number {\n  const b = a * 2;\n  return b + x;\n}\n`);
    const chunks = parseCodeFile(f, "demo");
    const fn = chunks.find((c) => c.section === "above.ts > function guarded");
    expect(fn?.guardedBy).toEqual(["ABOVE-FN"]);
    expect(fn?.lineStart).toBe(3);
    expect(fn?.content.startsWith("// [LOCKED] [ABOVE-FN]")).toBe(true);
    expect(pieces(chunks)).toEqual([]); // held by the function chunk, not repeated
  });
  it("two stacked blocks above a function both flag it", () => {
    const f = tmpFile("stacked.ts", `${block("FIRST")}\n${block("SECOND")}\nfunction xml(v: string): string {\n  const a = v.replace(/&/g, "&amp;");\n  return a;\n}\n`);
    const fn = parseCodeFile(f, "demo").find((c) => c.section === "stacked.ts > function xml");
    expect(fn?.guardedBy).toEqual(["FIRST", "SECOND"]);
  });
  it("a doc comment directly above a declaration is part of it", () => {
    const f = tmpFile("doc.ts", `/**\n * Adds the tax to a price.\n */\nexport function withTax(p: number): number {\n  const t = p * 0.081;\n  return p + t;\n}\n`);
    const fn = parseCodeFile(f, "demo")[0];
    expect(fn.lineStart).toBe(1);
    expect(fn.content).toContain("Adds the tax to a price.");
  });
  it("guard: a comment separated by a blank line stays out of the chunk", () => {
    const f = tmpFile("gap.ts", `// Section: pricing helpers\n\nexport function withTax(p: number): number {\n  const t = p * 0.081;\n  return p + t;\n}\n`);
    const fn = parseCodeFile(f, "demo")[0];
    expect(fn.lineStart).toBe(3);
    expect(fn.content).not.toContain("Section: pricing helpers");
  });
  it("a block above a constant, and one at the top of the file, become chunks of their own with the line they guard", () => {
    const f = tmpFile("consts.ts", `${block("TOP-OF-FILE")}\nimport { join } from "path";\n\n${block("ABOVE-CONST")}\nconst QUIET_MS = 30_000;\n\nexport function later(a: number): number {\n  const b = a + QUIET_MS;\n  return join(String(b));\n}\n`);
    const p = pieces(parseCodeFile(f, "demo"));
    expect(p.map((c) => c.section)).toEqual(["consts.ts > LOCK [TOP-OF-FILE]", "consts.ts > LOCK [ABOVE-CONST]"]);
    expect(p[0].guardedBy).toEqual(["TOP-OF-FILE"]);
    expect(p[0].content.split("\n").pop()).toBe(`import { join } from "path";`);
    expect(p[1].content.split("\n").pop()).toBe("const QUIET_MS = 30_000;");
    expect([p[1].lineStart, p[1].lineEnd]).toEqual([7, 11]);
  });
  it("guard: a block inside a function is not repeated as a chunk of its own", () => {
    const f = tmpFile("inside.ts", `export function check(x: number): boolean {\n${block("IN-BODY", "  ")}\n  return x > 0;\n}\n`);
    const chunks = parseCodeFile(f, "demo");
    expect(chunks.filter((c) => c.guardedBy?.includes("IN-BODY"))).toHaveLength(1);
    expect(pieces(chunks)).toEqual([]);
  });
  it("guard: a sentence that mentions a header, or a cross-reference, is not a block", () => {
    const mention = ["// [LOCKED] [REAL-ONE] - 2026-09-30", "// [NEVER] drop it.", "// WHY: the fleet's blocks (a [LOCKED] [TAG] header, then [NEVER], WHY and", "//      FIX lines) were invisible.", "// FIX: flag them."].join("\n");
    const f = tmpFile("mention.ts", `${mention}\nconst A = 1;\n\n// [LOCK] [REAL-ONE] see above\nconst B = 2;\n\nexport function useThem(): number {\n  const c = A + B;\n  return c;\n}\n`);
    const chunks = parseCodeFile(f, "demo");
    expect(pieces(chunks).map((c) => c.section)).toEqual(["mention.ts > LOCK [REAL-ONE]"]);
    expect(chunks.some((c) => c.guardedBy?.includes("TAG"))).toBe(false);
  });
  it("a file with no declarations and more than 200 lines still gives its blocks", () => {
    const filler = Array.from({ length: 220 }, (_, i) => `const v${i} = ${i};`).join("\n");
    const f = tmpFile("long.ts", `${filler}\n${block("IN-A-LONG-FILE")}\nconst last = 1;\n`);
    expect(pieces(parseCodeFile(f, "demo")).map((c) => c.section)).toEqual(["long.ts > LOCK [IN-A-LONG-FILE]"]);
  });
  it("a file too large for function chunks still gives its blocks, and nothing else", () => {
    const dir = mkdtempSync(join(tmpdir(), "ce-every-lock-big-"));
    mkdirSync(join(dir, "src"));
    const body = Array.from({ length: 2600 }, (_, i) => `export function f${i}(a: number): number {\n  const b = a + ${i};\n  return b;\n}`).join("\n");
    writeFileSync(join(dir, "src", "big.ts"), `${block("IN-A-BIG-FILE")}\nconst x = 1;\n${body}\n`);
    const chunks = scanCodeDir(join(dir, "src"), "demo");
    expect(chunks.map((c) => c.section)).toEqual(["big.ts > LOCK [IN-A-BIG-FILE]"]);
    expect(chunks[0].source).toBe("demo/big.ts");
  });
  it("Python: comments and decorators above a def are part of it; a module-level block is its own chunk", () => {
    const pyBlock = block("PY-MODULE").replace(/^\/\/ /gm, "# ");
    const f = tmpFile("app.py", `${pyBlock}\nTIMEOUT = 30\n\n# Serves the health page.\n@app.route("/health")\ndef health():\n    status = "ok"\n    return status\n`);
    const chunks = parseCodeFile(f, "demo");
    const fn = chunks.find((c) => c.section === "app.py > function health");
    expect(fn?.content).toContain("# Serves the health page.");
    expect(fn?.content).toContain('@app.route("/health")');
    expect(pieces(chunks).map((c) => c.section)).toEqual(["app.py > LOCK [PY-MODULE]"]);
  });
});
