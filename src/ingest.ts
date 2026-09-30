import { readFileSync, existsSync, statSync } from "fs";
import { basename } from "path";
import { createHash } from "crypto";
import { KnowledgeSource } from "./config.js";

/**
 * Number of overlap lines to carry over from the end of the previous chunk
 * to the beginning of the next chunk. Provides context continuity at
 * section boundaries (inspired by OpenClaw's 80-token overlap strategy).
 */
const OVERLAP_LINES = 4;

/**
 * A chunk of text extracted from a knowledge source,
 * suitable for embedding or keyword search.
 */
export interface Chunk {
  /** Which source file this came from */
  source: string;
  /** Section heading path (e.g. "## Architecture > ### Docker") */
  section: string;
  /** The actual text content */
  content: string;
  /** Starting line number in the original file (1-based) */
  lineStart: number;
  /** Ending line number in the original file (1-based) */
  lineEnd: number;
  /** SHA-256 hash of content for deduplication */
  contentHash?: string;
  /** Timestamp when chunk was indexed (ISO string) */
  indexedAt?: string;
  /** True if chunk contains a lock marker (LOCKED / ALREADY IMPLEMENTED) — signals agents should not re-audit */
  locked?: boolean;
  /** Code only: the tags of the whole LOCK blocks this chunk holds. [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE] */
  guardedBy?: string[];
}

/**
 * Lock marker patterns that signal verified/audited content.
 * Agents should NOT re-audit chunks containing these markers.
 * Supports code comments (// LOCKED, /* LOCKED, # LOCKED),
 * HTML comments (<!-- LOCKED -->), and markdown headings (## ALREADY IMPLEMENTED).
 */
const LOCK_PATTERNS = [
  /\/\/\s*LOCKED/i,
  /\/\*\s*LOCKED/i,
  /#\s*LOCKED/i,
  /<!--\s*LOCKED/i,
  /LOCKED\s*[—–-]\s*verified/i,
  /DO\s*NOT\s*RE-?AUDIT/i,
  /ALREADY\s+IMPLEMENTED/i,
  /VERIFIED\s*[—–-]\s*DO\s*NOT/i,
];

/** Check if a chunk's content contains a lock marker */
export function hasLockMarker(text: string): boolean {
  return LOCK_PATTERNS.some(p => p.test(text));
}

// [LOCKED] [LOCK-BLOCK-IS-FLAGGED-IN-CODE] - 2026-09-30
// [NEVER] flag a doc chunk as guarded because it quotes or explains a LOCK block, flag a code chunk
//         on a cross-reference alone, or give a LOCK block the "do not re-audit" words.
// WHY: the fleet's LOCK blocks (a [LOCKED] [TAG] header, then [NEVER], WHY and FIX lines; the older
//      form opened with an emoji) were invisible to LOCK_PATTERNS: in the live index of 2026-09-30,
//      6 chunks of 5,183 were flagged and 70 carried a marker unflagged (E2E_REVIEW_2026-09 batch 3
//      finding, the owner's yes on 2026-09-30). The old banner says "verified, DO NOT re-audit",
//      the wrong words for a LOCK, which asks for its WHY to be read before a change. Of the 41
//      chunks holding a whole block, 32 were code and 9 were docs explaining the convention.
// FIX: lockBlockTags() returns the tags of whole blocks (a tagged header, a [NEVER] line and a WHY
//      line in the same chunk); only the code chunker sets `guardedBy` from it (docs go through
//      parseMarkdown, which never does), and a search result says lockGuardLine().
const LOCK_HEADER = /(?:\[LOCKED\]|\u{1F512}\s*LOCKED)\s*\[([A-Z0-9][A-Z0-9_-]*)\]/gu;
const LOCK_NEVER = /\[NEVER\]|\u26D4\s*NEVER/u;
const LOCK_WHY = /(?:^|\n)\s*(?:\/\/|#|\*|<!--)?\s*WHY:/;

/** The tags of the whole LOCK blocks in `text`, in order, each once; [] when there is none. */
export function lockBlockTags(text: string): string[] {
  if (!LOCK_NEVER.test(text) || !LOCK_WHY.test(text)) return [];
  return [...new Set([...text.matchAll(LOCK_HEADER)].map((m) => m[1]))];
}

/** The line a search result carries for a chunk guarded by LOCK blocks (tags non-empty). */
export function lockGuardLine(tags: string[]): string {
  return `Guarded by LOCK ${tags.map((t) => `[${t}]`).join(" ")}: read its WHY before changing this code.`;
}

/**
 * Compute SHA-256 hash of a string for content deduplication.
 */
function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

/**
 * Parse a markdown file into chunks, splitting on headings.
 * Each chunk captures the heading hierarchy for context.
 *
 * v1.10: Adds overlap lines from the end of each chunk to the start
 * of the next chunk, providing context continuity at heading boundaries.
 * Also computes SHA-256 content hashes for deduplication.
 */
function parseMarkdown(filePath: string, sourceName: string): Chunk[] {
  let mtime: string | undefined;
  try {
    mtime = statSync(filePath).mtime.toISOString();
  } catch {
    mtime = new Date().toISOString();
  }

  const text = readFileSync(filePath, "utf-8");
  const lines = text.split("\n");
  const rawChunks: Array<{
    section: string;
    contentLines: string[];
    startLine: number;
    endLine: number;
  }> = [];

  // Track heading hierarchy
  const headingStack: string[] = [];
  let currentContent: string[] = [];
  let chunkStartLine = 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const headingMatch = line.match(/^(#{1,6})\s+(.+)/);

    if (headingMatch) {
      // Flush previous chunk
      if (currentContent.length > 0) {
        const content = currentContent.join("\n").trim();
        if (content.length > 0) {
          rawChunks.push({
            section: headingStack.join(" > ") || basename(filePath),
            contentLines: [...currentContent],
            startLine: chunkStartLine,
            endLine: i,
          });
        }
      }

      const level = headingMatch[1].length;
      const title = headingMatch[2].trim();

      // Pop headings at same or deeper level
      while (headingStack.length >= level) {
        headingStack.pop();
      }
      headingStack.push(`${"#".repeat(level)} ${title}`);

      currentContent = [];
      chunkStartLine = i + 1; // 1-based
    } else {
      currentContent.push(line);
    }
  }

  // Flush last chunk
  if (currentContent.length > 0) {
    const content = currentContent.join("\n").trim();
    if (content.length > 0) {
      rawChunks.push({
        section: headingStack.join(" > ") || basename(filePath),
        contentLines: [...currentContent],
        startLine: chunkStartLine,
        endLine: lines.length,
      });
    }
  }

  // Build final chunks with overlap
  const chunks: Chunk[] = [];
  for (let i = 0; i < rawChunks.length; i++) {
    const raw = rawChunks[i];
    let finalLines = raw.contentLines;

    // Add overlap from previous chunk's tail (if not the first chunk)
    if (i > 0 && OVERLAP_LINES > 0) {
      const prevLines = rawChunks[i - 1].contentLines;
      const overlapCount = Math.min(OVERLAP_LINES, prevLines.length);
      const overlap = prevLines.slice(-overlapCount);
      finalLines = [...overlap, "---", ...raw.contentLines];
    }

    const content = finalLines.join("\n").trim();
    if (content.length > 0) {
      const locked = hasLockMarker(content) || hasLockMarker(raw.section);
      chunks.push({
        source: sourceName,
        section: raw.section,
        content,
        lineStart: raw.startLine,
        lineEnd: raw.endLine,
        contentHash: hashContent(content),
        indexedAt: mtime,
        ...(locked && { locked: true }),
      });
    }
  }

  return chunks;
}

/**
 * Ingest all configured knowledge sources into chunks.
 * Skips files that don't exist (with a warning to stderr).
 * Deduplicates chunks by content hash.
 */
export function ingestSources(sources: KnowledgeSource[]): Chunk[] {
  const allChunks: Chunk[] = [];
  const seenHashes = new Set<string>();
  let dupCount = 0;
  let indexed = 0;

  for (const source of sources) {
    if (!existsSync(source.path)) {
      console.error(`[ContextEngine] ⚠ Skipping missing: ${source.path}`);
      continue;
    }

    const chunks = parseMarkdown(source.path, source.name);
    for (const chunk of chunks) {
      if (chunk.contentHash && seenHashes.has(chunk.contentHash)) {
        dupCount++;
        continue;
      }
      if (chunk.contentHash) seenHashes.add(chunk.contentHash);
      allChunks.push(chunk);
    }
    // No line per source: one "Indexed:" line per file at every build filled the daemon log with
    // 2 million lines for 880 files. [LOCK] [DAEMON-LOG-TRIMS-ITSELF] (src/daemon-log.ts)
    indexed++;
  }

  if (dupCount > 0) {
    console.error(
      `[ContextEngine] 🔁 Deduplicated: ${dupCount} duplicate chunks removed`
    );
  }

  console.error(
    `[ContextEngine] 📦 Total: ${allChunks.length} chunks from ${indexed} of ${sources.length} sources`
  );
  return allChunks;
}
