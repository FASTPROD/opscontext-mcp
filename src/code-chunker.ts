import { readFileSync, readdirSync, statSync } from "fs";
import { join, extname, basename, relative } from "path";
import type { Chunk } from "./ingest.js";
import { hasLockMarker, lockBlockTags } from "./ingest.js";

/**
 * Code Chunker — parse TS/JS/Python files into function/class/method chunks.
 *
 * Uses regex-based parsing (no AST dependency) to extract:
 * - Functions (regular, arrow, async)
 * - Classes and their methods
 * - Interfaces and type aliases (TS)
 * - Python def/class/async def
 *
 * Each chunk includes the full function body with enough context
 * for semantic search to work well.
 */

const CODE_EXTENSIONS = new Set([".ts", ".js", ".mts", ".mjs", ".py"]);
/** Above this size a file gets no function chunks, only its LOCK blocks. */
const FUNCTION_CHUNKS_MAX_BYTES = 100_000;
/** Above this size a file gets nothing: bundles and generated code. */
const LOCK_PIECES_MAX_BYTES = 1_000_000;

// [LOCKED] [EVERY-LOCK-BLOCK-IS-FINDABLE] - 2026-09-30
// [NEVER] cut a code chunk at its declaration line again, leaving the comment above it out, or let a
//         whole LOCK block in an indexed code file stay out of the index because no function holds it.
// WHY: a LOCK block usually sits directly above the code it guards, at the top of a file, or above a
//      constant, and the chunker kept only function bodies and skipped files over 100 KB. Measured on
//      the owner's fleet on 2026-09-30 (E2E_REVIEW_2026-09 batch 4 finding, re-measured in batch 5):
//      1,213 code chunks, 34 flagged "Guarded by LOCK"; of the LOCK headers in the indexed code files,
//      69 sat inside a function chunk, 36 directly above one, 128 elsewhere, and 80 more in three
//      files skipped for size (this repository's own cli.ts and agents.ts among them). An agent
//      searching for guarded code mostly found it unflagged, and the WHY words were not searchable.
// FIX: a function, class, interface or type chunk starts at the comment and decorator lines directly
//      above it (no blank line between); every whole block not inside such a chunk becomes a chunk of
//      its own (the block and the line of code under it), also in files up to LOCK_PIECES_MAX_BYTES
//      that are too large for function chunks. A header counts only where it opens its comment line:
//      a sentence that mentions the convention is not a block. The owner's yes, 2026-09-30.
//      [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE] (src/ingest.ts)
const HEADER_OPENS_LINE = /^\s*(?:\/\/+|\/\*+|\*|#)\s*(?:\[LOCKED\]|\u{1F512}\s*LOCKED)\s*\[([A-Z0-9][A-Z0-9_-]*)\]/u;

function isCommentLine(line: string, py: boolean): boolean {
  const t = line.trim();
  if (py) return t.startsWith("#");
  return t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");
}

/** First line (1-based) of the comment and decorator lines directly above `lineStart`, no blank line between. */
function leadingCommentStart(lines: string[], lineStart: number, py: boolean): number {
  let first = lineStart;
  for (let i = lineStart - 2; i >= 0; i--) {
    const l = lines[i];
    if (l.trim() === "") break;
    if (isCommentLine(l, py) || /^\s*@[\w.]+/.test(l)) { first = i + 1; continue; }
    break;
  }
  return first;
}

/** A chunk per whole LOCK block whose header line no chunk in `covered` holds. [LOCK] [EVERY-LOCK-BLOCK-IS-FINDABLE] */
function lockBlockChunks(filePath: string, sourceName: string, lines: string[], covered: Array<[number, number]>, py: boolean): Chunk[] {
  const out: Chunk[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!HEADER_OPENS_LINE.test(lines[i])) continue;
    const header = i + 1;
    if (covered.some(([s, e]) => header >= s && header <= e)) continue;
    let j = i + 1; // the block: its comment lines, up to the next header or the first line of code
    while (j < lines.length && isCommentLine(lines[j], py) && !HEADER_OPENS_LINE.test(lines[j])) j++;
    let k = j; // the line of code it guards, past any comment or blank line
    while (k < lines.length && (lines[k].trim() === "" || isCommentLine(lines[k], py))) k++;
    const guarded = k < lines.length ? lines[k].slice(0, 200) : null;
    const content = lines.slice(i, j).join("\n") + (guarded !== null ? `\n${guarded}` : "");
    // The tag is the header's own; the block must be whole (its NEVER and WHY lines) to count.
    const tag = HEADER_OPENS_LINE.exec(lines[i])?.[1];
    if (!tag || lockBlockTags(content).length === 0) continue;
    const guardedBy = [tag];
    out.push({
      source: sourceName,
      section: `${basename(filePath)} > LOCK ${guardedBy.map((t) => `[${t}]`).join(" ")}`,
      content,
      lineStart: header,
      lineEnd: guarded !== null ? k + 1 : j,
      ...(hasLockMarker(content) && { locked: true }),
      guardedBy,
    });
  }
  return out;
}
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "coverage",
  "__pycache__", ".venv", "venv", ".next", ".cache",
]);

// ---------------------------------------------------------------------------
// TypeScript / JavaScript parser (regex-based)
// ---------------------------------------------------------------------------

interface CodeBlock {
  kind: string; // "function" | "class" | "interface" | "type" | "method"
  name: string;
  lineStart: number;
  lineEnd: number;
  content: string;
}

/**
 * Find the matching closing brace for an opening brace at position `start`.
 */
function findClosingBrace(text: string, start: number): number {
  let depth = 0;
  let inString: string | null = null;
  let inTemplate = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    const prev = i > 0 ? text[i - 1] : "";

    // Skip escaped characters
    if (prev === "\\") continue;

    // String tracking
    if (!inString && !inTemplate) {
      if (ch === '"' || ch === "'" || ch === "`") {
        if (ch === "`") inTemplate = true;
        else inString = ch;
        continue;
      }
    } else if (inString && ch === inString && prev !== "\\") {
      inString = null;
      continue;
    } else if (inTemplate && ch === "`" && prev !== "\\") {
      inTemplate = false;
      continue;
    } else {
      continue; // inside string, skip
    }

    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }

  return -1; // unmatched
}

/**
 * Parse a TypeScript/JavaScript file into code blocks.
 */
function parseTSJS(text: string): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  const lines = text.split("\n");

  // Build line-offset map for position → line number conversion
  const lineOffsets: number[] = [0];
  for (let i = 0; i < lines.length; i++) {
    lineOffsets.push(lineOffsets[i] + lines[i].length + 1);
  }

  function posToLine(pos: number): number {
    for (let i = 0; i < lineOffsets.length - 1; i++) {
      if (pos < lineOffsets[i + 1]) return i + 1;
    }
    return lines.length;
  }

  // Patterns for top-level declarations
  const patterns: Array<{ regex: RegExp; kind: string }> = [
    // export function / async function / function
    { regex: /(?:export\s+)?(?:async\s+)?function\s+(\w+)/g, kind: "function" },
    // export const name = (...) => (arrow functions)
    { regex: /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(/g, kind: "function" },
    // export class / class
    { regex: /(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/g, kind: "class" },
    // export interface
    { regex: /(?:export\s+)?interface\s+(\w+)/g, kind: "interface" },
    // export type (block types only, not simple aliases)
    { regex: /(?:export\s+)?type\s+(\w+)\s*=\s*\{/g, kind: "type" },
  ];

  for (const { regex, kind } of patterns) {
    let match;
    regex.lastIndex = 0;

    while ((match = regex.exec(text)) !== null) {
      const name = match[1];
      const matchStart = match.index;
      const lineStart = posToLine(matchStart);

      // Find the opening brace after the match
      const braceStart = text.indexOf("{", match.index + match[0].length);
      if (braceStart === -1) continue;

      // Check it's not too far (within 200 chars — accounts for type annotations)
      if (braceStart - (match.index + match[0].length) > 200) continue;

      const braceEnd = findClosingBrace(text, braceStart);
      if (braceEnd === -1) continue;

      const lineEnd = posToLine(braceEnd);
      const content = text.slice(matchStart, braceEnd + 1);

      // Skip tiny blocks (less than 2 lines of real content)
      if (lineEnd - lineStart < 2) continue;

      blocks.push({ kind, name, lineStart, lineEnd, content });
    }
  }

  // Deduplicate overlapping blocks (keep the outer one)
  blocks.sort((a, b) => a.lineStart - b.lineStart);
  const result: CodeBlock[] = [];
  for (const block of blocks) {
    const last = result[result.length - 1];
    if (last && block.lineStart >= last.lineStart && block.lineEnd <= last.lineEnd) {
      // This block is inside the last one — skip (it's a method inside a class)
      continue;
    }
    result.push(block);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Python parser (regex-based)
// ---------------------------------------------------------------------------

/**
 * Parse a Python file into function/class blocks using indentation.
 */
function parsePython(text: string): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match def/async def/class at module level (no leading whitespace)
    const funcMatch = line.match(/^(async\s+)?def\s+(\w+)\s*\(/);
    const classMatch = line.match(/^class\s+(\w+)/);

    if (funcMatch || classMatch) {
      const kind = classMatch ? "class" : "function";
      const name = classMatch ? classMatch[1] : funcMatch![2];
      const lineStart = i + 1; // 1-based

      // Find end of block by indentation
      let lineEnd = i + 1;
      for (let j = i + 1; j < lines.length; j++) {
        const nextLine = lines[j];
        // Empty lines don't end blocks
        if (nextLine.trim() === "") {
          lineEnd = j + 1;
          continue;
        }
        // Non-indented non-empty line = end of block
        if (!nextLine.match(/^\s/)) break;
        lineEnd = j + 1;
      }

      const content = lines.slice(i, lineEnd).join("\n");

      // Skip tiny blocks
      if (lineEnd - lineStart < 2) continue;

      blocks.push({ kind, name, lineStart, lineEnd, content });
    }
  }

  return blocks;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a single code file into Chunks.
 */
export function parseCodeFile(
  filePath: string,
  sourceName: string,
  opts: { lockBlocksOnly?: boolean } = {}
): Chunk[] {
  const ext = extname(filePath).toLowerCase();
  const py = ext === ".py";
  const text = readFileSync(filePath, "utf-8");
  const lines = text.split("\n");
  // [LOCK] [EVERY-LOCK-BLOCK-IS-FINDABLE]: a file too large for function chunks still gives its blocks.
  if (opts.lockBlocksOnly) return lockBlockChunks(filePath, sourceName, lines, [], py);

  const blocks: CodeBlock[] = py ? parsePython(text) : parseTSJS(text);

  // If no blocks found, create a single chunk for the whole file
  // (but only if it's not too large)
  if (blocks.length === 0) {
    if (lines.length <= 200 && text.trim().length > 0) {
      const locked = hasLockMarker(text);
      const guardedBy = lockBlockTags(text); // [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE]
      return [{
        source: sourceName,
        section: `${basename(filePath)} (entire file)`,
        content: text,
        lineStart: 1,
        lineEnd: lines.length,
        ...(locked && { locked: true }),
        ...(guardedBy.length > 0 && { guardedBy }),
      }];
    }
    return lockBlockChunks(filePath, sourceName, lines, [], py);
  }

  const chunks: Chunk[] = blocks.map((b) => {
    // The comment above a declaration is part of it: a LOCK block or a doc comment usually sits
    // there. [LOCK] [EVERY-LOCK-BLOCK-IS-FINDABLE]
    const first = leadingCommentStart(lines, b.lineStart, py);
    const content = first < b.lineStart ? `${lines.slice(first - 1, b.lineStart - 1).join("\n")}\n${b.content}` : b.content;
    const locked = hasLockMarker(content);
    const guardedBy = lockBlockTags(content); // [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE]
    return {
      source: sourceName,
      section: `${basename(filePath)} > ${b.kind} ${b.name}`,
      content,
      lineStart: first,
      lineEnd: b.lineEnd,
      ...(locked && { locked: true }),
      ...(guardedBy.length > 0 && { guardedBy }),
    };
  });
  return chunks.concat(lockBlockChunks(filePath, sourceName, lines, chunks.map((c) => [c.lineStart, c.lineEnd]), py));
}

/**
 * Scan a directory for code files and parse them all.
 * Scans recursively but respects SKIP_DIRS.
 * Returns chunks with source set to `projectName/relative/path.ts`.
 */
export function scanCodeDir(
  dirPath: string,
  projectName: string,
  maxDepth: number = 3
): Chunk[] {
  const allChunks: Chunk[] = [];

  function walk(dir: string, depth: number): void {
    if (depth > maxDepth) return;

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.startsWith(".")) continue;
      if (SKIP_DIRS.has(entry)) continue;

      const full = join(dir, entry);
      try {
        const stat = statSync(full);
        if (stat.isDirectory()) {
          walk(full, depth + 1);
        } else if (stat.isFile() && CODE_EXTENSIONS.has(extname(entry).toLowerCase())) {
          // Skip test files, config files, and very large files
          if (entry.includes(".test.") || entry.includes(".spec.")) continue;
          if (entry === "jest.config.js" || entry === "webpack.config.js") continue;
          if (stat.size > LOCK_PIECES_MAX_BYTES) continue;

          const relPath = relative(dirPath, full);
          const sourceName = `${projectName}/${relPath}`;
          // [LOCK] [EVERY-LOCK-BLOCK-IS-FINDABLE]: over 100 KB, only the file's LOCK blocks.
          const chunks = parseCodeFile(full, sourceName, { lockBlocksOnly: stat.size > FUNCTION_CHUNKS_MAX_BYTES });
          allChunks.push(...chunks);
        }
      } catch {
        continue;
      }
    }
  }

  walk(dirPath, 0);
  return allChunks;
}
