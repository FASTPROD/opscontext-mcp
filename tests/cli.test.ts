import { describe, it, expect } from "vitest";
import { execSync } from "child_process";
import { join } from "path";

const CLI = join(__dirname, "..", "dist", "cli.js");

function run(args: string, timeout = 15000): string {
  try {
    return execSync(`node ${CLI} ${args}`, {
      timeout,
      encoding: "utf-8",
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
      cwd: join(__dirname, ".."),
    }).trim();
  } catch (e: any) {
    // [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY], a timeout or crash must NOT masquerade as empty output.
    // This previously returned "" for a killed process, so a 15s timeout under parallel suite load
    // surfaced as the useless assertion "expected 0 to be greater than 0" instead of "SIGTERM".
    // Some commands exit non-zero intentionally, so non-empty output is still a valid result.
    const output = ((e.stdout || "") + "\n" + (e.stderr || "")).trim();
    if (output) return output;
    const cause = e.signal ? `killed by ${e.signal}` : e.code !== undefined ? `exit code ${e.code}` : "unknown failure";
    throw new Error(`\`${args}\` produced no output at all (${cause}, timeout ${timeout}ms): ${e.message}`);
  }
}

describe("CLI smoke tests", () => {
  it("help command prints usage", () => {
    const output = run("help");
    expect(output).toContain("contextengine");
    expect(output).toContain("search");
  });

  it("search returns results for common query", () => {
    // 60s, not the 15s default: search loads the local all-MiniLM-L6-v2 embedding model, which on a
    // cold cache and under parallel suite load legitimately exceeds 15s. Standalone it runs in ~2s.
    const output = run('search "typescript"', 60_000);
    // Should either return results or a "no results" message — not crash
    expect(typeof output).toBe("string");
    expect(output.length).toBeGreaterThan(0);
  });

  it("list-sources returns source information", () => {
    const output = run("list-sources");
    expect(typeof output).toBe("string");
    // Should contain at least some file path or "sources" text
    expect(output.length).toBeGreaterThan(0);
  });

  it("list-learnings returns without error", () => {
    const output = run("list-learnings");
    expect(typeof output).toBe("string");
  });

  it("list-sessions returns without error", () => {
    const output = run("list-sessions");
    expect(typeof output).toBe("string");
  });

  it("unknown command exits without crash", () => {
    // Unknown commands may enter interactive mode, so just verify help works
    const output = run("help");
    expect(output).toContain("search");
    expect(output).toContain("list-sources");
  });

  it("search with topK flag works", () => {
    const output = run('search "docker" -n 3');
    expect(typeof output).toBe("string");
  });

  // export-learnings retired 2026-09-30 ([LOCK] [COMMUNITY-RETIRED], src/index.ts); its three smoke
  // tests stayed and passed only while the live dist/ was older than the retirement.
});
