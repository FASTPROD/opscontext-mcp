// [LOCK] [ADAPTERS-ONLY-FROM-THE-USERS-OWN-CONFIG]: E2E_REVIEW_2026-09 A6-5. Throwaway folders only;
// the adapter module is harmless (it returns one chunk with a marker sentence).
import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { loadAdapters, collectFromAdapters } from "../src/adapters.js";

const MARKER = "ADAPTER-MARKER-" + "4412";
const adapterSource = `export default { name: "t", description: "test", async collect() { return [{ source: "t", section: "m", content: "${MARKER}", lineStart: 1, lineEnd: 1 }]; } };\n`;

describe("loadAdapters", () => {
  it("resolves a relative module path from the config's folder, not from the current one", async () => {
    const cfgDir = mkdtempSync(join(tmpdir(), "ce-adapter-cfg-"));
    mkdirSync(join(cfgDir, "adapters"));
    writeFileSync(join(cfgDir, "adapters", "t.mjs"), adapterSource);
    const entries = [{ name: "rel-test", module: "./adapters/t.mjs" }];
    expect(await loadAdapters(entries, cfgDir)).toBe(1);
    const chunks = await collectFromAdapters(entries);
    expect(chunks.map((c) => c.content)).toContain(MARKER);
  });
});

describe("the MCP server started inside a project that ships its own contextengine.json", () => {
  it("does not load that config's adapters, and says why", async () => {
    const root = mkdtempSync(join(tmpdir(), "ce-adapter-cwd-"));
    const repo = join(root, "repo");
    const home = join(root, "home");
    mkdirSync(repo);
    mkdirSync(home);
    writeFileSync(join(repo, "contextengine.json"), JSON.stringify({ sources: [], collectOps: false, collectSystemOps: false, adapters: [{ name: "repo-adapter", module: "./adapter.mjs" }] }));
    writeFileSync(join(repo, "adapter.mjs"), adapterSource);

    const child = spawn(process.execPath, [join(process.cwd(), "dist", "index.js")], {
      cwd: repo,
      env: { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: join(home, ".contextengine"), OPSCONTEXT_EVENT_PORT: "17899", TMPDIR: root },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const send = (id: number, method: string, params: unknown) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    send(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    // Search only once the adapter step has run either way, or a "not found" would prove nothing.
    for (let i = 0; i < 150 && !/Adapters contributed|were NOT loaded/.test(err); i++) await new Promise((r) => setTimeout(r, 100));
    send(2, "tools/call", { name: "search_context", arguments: { query: `${MARKER} m`, mode: "keyword" } });
    for (let i = 0; i < 100 && !/"id":2/.test(out); i++) await new Promise((r) => setTimeout(r, 100));
    child.kill();

    expect(out).toMatch(/"id":2/);
    expect(out).not.toContain("Source: repo-adapter"); // the adapter's chunk (the query itself is echoed back)
    expect(err).toMatch(/were NOT loaded: a config found in the current folder may not run code/);
  }, 30_000);
});
