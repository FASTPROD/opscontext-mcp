import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import {
  ALL_TOOLS,
  PREMIUM_TOOL_NAMES,
  TOOL_COUNT,
  FREE_TOOL_COUNT,
} from "../src/tools-manifest.js";
import { PREMIUM_TOOLS } from "../src/activation.js";

/**
 * Regression guard for "Active on all 17 MCP tools" → "20" → "21" drift.
 *
 * Three properties enforced:
 *   1. ALL_TOOLS.length matches the actual count of `server.tool(...)` calls in
 *      src/index.ts. If a tool is added/removed in index.ts, this fails.
 *   2. Every name in ALL_TOOLS appears as a tool registration in index.ts.
 *   3. PREMIUM_TOOL_NAMES is a subset of ALL_TOOLS and matches the re-export
 *      from activation.ts.
 */
describe("tools-manifest", () => {
  // Read index.ts ONCE and extract every `server.tool("<name>", ...)` call.
  const indexSrc = readFileSync(join(__dirname, "..", "src", "index.ts"), "utf-8");
  const registeredNames = Array.from(
    indexSrc.matchAll(/^server\.tool\(\s*\n?\s*"([a-z_]+)"/gm)
  ).map((m) => m[1]);

  it("ALL_TOOLS.length matches the number of server.tool() registrations in index.ts", () => {
    expect(registeredNames.length).toBeGreaterThan(0);
    expect(ALL_TOOLS.length).toBe(registeredNames.length);
  });

  it("every name in ALL_TOOLS is registered in index.ts", () => {
    const registeredSet = new Set(registeredNames);
    const missing = ALL_TOOLS.filter((name) => !registeredSet.has(name));
    expect(missing).toEqual([]);
  });

  it("every registered tool in index.ts appears in ALL_TOOLS", () => {
    const manifestSet = new Set<string>(ALL_TOOLS);
    const orphan = registeredNames.filter((name) => !manifestSet.has(name));
    expect(orphan).toEqual([]);
  });

  it("TOOL_COUNT === ALL_TOOLS.length", () => {
    expect(TOOL_COUNT).toBe(ALL_TOOLS.length);
  });

  it("FREE_TOOL_COUNT === ALL_TOOLS.length - PREMIUM_TOOL_NAMES.length", () => {
    expect(FREE_TOOL_COUNT).toBe(ALL_TOOLS.length - PREMIUM_TOOL_NAMES.length);
  });

  it("PREMIUM_TOOL_NAMES is a subset of ALL_TOOLS", () => {
    const allSet = new Set<string>(ALL_TOOLS);
    const notInAll = PREMIUM_TOOL_NAMES.filter((name) => !allSet.has(name));
    expect(notInAll).toEqual([]);
  });

  it("PREMIUM_TOOLS (re-exported from activation.ts) === PREMIUM_TOOL_NAMES", () => {
    expect([...PREMIUM_TOOLS]).toEqual([...PREMIUM_TOOL_NAMES]);
  });
});

// Retired 2026-09-30 (E2E_REVIEW_2026-09 C1-1). The list_sources description still told agents to call
// read_source after the tool was gone; found on the release build, fixed the same day.
describe("no string an agent reads names a retired tool", () => {
  const RETIRED = ["read_source", "delete_session", "audit_verify", "drift_status", "agent_cost", "import_learnings"];
  it("outside comments, src/ names none of them (agent_cost stays only as the policy.json key)", () => {
    const dir = join(__dirname, "..", "src");
    const hits: string[] = [];
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts"))) {
      const code = readFileSync(join(dir, f), "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:])\/\/.*$/gm, "$1");
      for (const name of RETIRED) {
        const re = new RegExp(`\\b${name}\\b`, "g");
        for (const m of code.matchAll(re)) {
          const around = code.slice(Math.max(0, m.index! - 20), m.index! + name.length + 20);
          if (name === "agent_cost" && /policy\.agent_cost|agent_cost:|agent_cost\.pricing|no agent_cost in policy/.test(around)) continue;
          hits.push(`${f}: ${around.replace(/\s+/g, " ")}`);
        }
      }
    }
    expect(hits).toEqual([]);
  });
});
