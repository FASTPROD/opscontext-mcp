import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { buildCostReport } from "../src/cost-report.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// [LOCK] [COST-REPORT-ONE-RENDERER]
describe("cost report, one renderer for CLI and MCP", () => {
  it("returns text and never throws, with or without runs on this machine", () => {
    const r = buildCostReport({ days: 1, top: 3 });
    expect(typeof r.text).toBe("string");
    expect(r.text.length).toBeGreaterThan(0);
    if (r.runs === 0) {
      expect(r.json).toBeNull();
      expect(r.text).toContain("No multi-agent runs found");
    } else {
      expect(r.json).not.toBeNull();
      expect(r.text).toContain("MULTI-AGENT COST");
      expect((r.json as any).runs.length).toBe(r.runs);
      expect((r.json as any).runs.length).toBeLessThanOrEqual(1000);
    }
  });

  it("a run filter that matches nothing yields the empty report, not a crash", () => {
    const r = buildCostReport({ run: "wf_does-not-exist-0000" });
    expect(r.runs).toBe(0);
    expect(r.json).toBeNull();
  });

  it("neither cli.ts nor index.ts renders the report themselves", () => {
    for (const f of ["cli.ts", "index.ts"]) {
      const src = readFileSync(join(root, "src", f), "utf-8");
      expect(src).not.toMatch(/NOTIONAL, NOT BILLED|TOP RUNS BY VALUED COST|NEVER-RENDER-AN-UNKNOWN/);
    }
    expect(readFileSync(join(root, "src", "cli.ts"), "utf-8")).toContain("buildCostReport(");
  });

  it("the CLI is the one surface: the MCP tool agent_cost stays retired (2026-09-30)", () => {
    // Retired with 0 calls on the owner's decision (E2E_REVIEW_2026-09 C1-1). Bringing it back
    // means reading the carried [COST-POLICY-DIR-IS-EXPLICIT] note in src/cost-report.ts first.
    const idx = readFileSync(join(root, "src", "index.ts"), "utf-8");
    expect(idx).not.toMatch(/server\.tool\(\s*"agent_cost"/);
    const manifest = readFileSync(join(root, "src", "tools-manifest.ts"), "utf-8");
    expect(manifest).not.toMatch(/^\s*"agent_cost",$/m);
  });

  it("thresholds follow the directory passed, not the process cwd", () => {
    const here = buildCostReport({ days: 1 }, root);
    const nowhere = buildCostReport({ days: 1 }, "/");
    if (here.runs > 0) {
      // This repo has an agent_cost block in .contextengine/policy.json; "/" has none.
      expect(here.text).toContain("thresholds: .contextengine/policy.json");
      expect(nowhere.text).toContain("built-in defaults");
    }
  });
});
