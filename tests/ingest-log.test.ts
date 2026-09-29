// [LOCK] [DAEMON-LOG-TRIMS-ITSELF] (src/daemon-log.ts), the other half: ingestSources() printed one
// "Indexed:" line per source at every build, 2,007,508 lines for 880 files in the daemon log
// (E2E_REVIEW_2026-09 C5-1). One line per build now. This test fails on the code before the fix.
import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { ingestSources } from "../src/ingest.js";
import type { KnowledgeSource } from "../src/config.js";

afterEach(() => vi.restoreAllMocks());

describe("ingestSources logging", () => {
  it("prints one line for the build, not one per source", () => {
    const dir = mkdtempSync(join(tmpdir(), "ce-ingest-log-"));
    try {
      const sources: KnowledgeSource[] = [];
      for (let i = 0; i < 3; i++) {
        const path = join(dir, `doc${i}.md`);
        writeFileSync(path, `# Doc ${i}\n\nSome text about topic ${i}.\n\n## Section\n\nMore text.\n`);
        sources.push({ path, name: `demo — doc${i}.md` } as unknown as KnowledgeSource);
      }
      sources.push({ path: join(dir, "missing.md"), name: "demo — missing.md" } as unknown as KnowledgeSource);
      const lines: string[] = [];
      vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(" ")); });
      const chunks = ingestSources(sources);
      expect(chunks.length).toBeGreaterThan(0);
      expect(lines.filter((l) => l.includes("Indexed:"))).toHaveLength(0);
      const total = lines.filter((l) => l.includes("Total:"));
      expect(total).toHaveLength(1);
      expect(total[0]).toMatch(/3 of 4 sources/);
      expect(lines.filter((l) => l.includes("Skipping missing"))).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
