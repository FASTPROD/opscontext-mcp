// [LOCK] [RECEIVER-ACCEPTS-ONLY-KNOWN-SENDERS] [EVENT-PORT-BELONGS-TO-THE-DAEMON] [EMIT-EVENT-GOES-THROUGH-THE-DOOR]
// E2E_REVIEW_2026-09 A2-1 to A2-6, replayed against an in-process receiver on a throwaway port and
// a throwaway HOME (src/test-setup.ts). The live receiver on 7842 is never contacted.
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import http from "node:http";
import net from "node:net";
import { mkdirSync, writeFileSync, readFileSync, existsSync, mkdtempSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir, tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

const PORT = 20000 + (process.pid % 20000);
process.env.OPSCONTEXT_EVENT_PORT = String(PORT);
const SECRET = "s".repeat(64);
const AUDIT = () => join(process.env.CONTEXTENGINE_HOME as string, "audit.log");

type Recv = typeof import("../src/http-server.js");
let R: Recv;

function req(method: string, path: string, opts: { headers?: Record<string, string>; body?: string } = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "127.0.0.1", port: PORT, method, path, headers: opts.headers }, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
    });
    r.on("error", reject);
    if (opts.body) r.write(opts.body);
    r.end();
  });
}
const H = { "Content-Type": "application/json", "X-OpsContext-Secret": SECRET };
const ev = (event: string, payload: Record<string, unknown> = { a: 1 }, extra: Record<string, unknown> = {}) => ({ v: 1, ts: new Date().toISOString(), event, payload, ...extra });
const post = (events: unknown[]) => req("POST", "/events", { headers: H, body: JSON.stringify({ events }) });

beforeAll(async () => {
  expect(homedir()).toMatch(/ce-test-home-/);
  mkdirSync(join(homedir(), ".contextengine"), { recursive: true });
  writeFileSync(join(homedir(), ".contextengine", "extension-secret"), SECRET + "\n", { mode: 0o600 });
  R = await import("../src/http-server.js");
  expect(await R.startEventIngestServer()).toBe(PORT);
});
afterAll(async () => {
  await R.stopEventIngestServer();
});

describe("who may read the receiver", () => {
  it("gives a web page no CORS header, and a browser extension its own origin", async () => {
    const page = await req("GET", "/health", { headers: { Origin: "https://any-website.example" } });
    expect(page.status).toBe(200);
    expect(page.headers["access-control-allow-origin"]).toBeUndefined();
    const pre = await req("OPTIONS", "/events", { headers: { Origin: "https://any-website.example", "Access-Control-Request-Method": "POST" } });
    expect(pre.headers["access-control-allow-origin"]).toBeUndefined();
    const ext = await req("GET", "/health", { headers: { Origin: "chrome-extension://abcdefghijklmnop" } });
    expect(ext.headers["access-control-allow-origin"]).toBe("chrome-extension://abcdefghijklmnop");
  });

  it("refuses a Host header that does not name this machine (DNS rebinding)", async () => {
    expect((await req("GET", "/health", { headers: { Host: `rebind.attacker.example:${PORT}` } })).status).toBe(403);
    expect((await req("GET", "/health", { headers: { Host: `localhost:${PORT}` } })).status).toBe(200);
  });
});

describe("what the receiver accepts", () => {
  it("takes exactly the capture kinds", async () => {
    for (const k of ["cli.anything_at_all", "vscode.", "browser.x", "audit.redact", "learning.save"]) {
      expect((await post([ev(k)])).status, k).toBe(400);
    }
    expect((await post([ev("vscode.tool_call")])).status).toBe(200);
  });

  it("refuses the reserved actors and odd names, keeps real ones", async () => {
    for (const actor of ["system", "cli", "System", "a b", "x".repeat(40)]) {
      expect((await post([ev("vscode.tool_call", { a: 1 }, { actor })])).status, actor).toBe(400);
    }
    expect((await post([ev("vscode.tool_call", { a: 1 }, { actor: "claude-code" })])).status).toBe(200);
  });

  it("answers an oversized body with a 413 before closing", async () => {
    const big = JSON.stringify({ events: [ev("vscode.tool_call", { pad: "x".repeat(70 * 1024) })] });
    const reply = await new Promise<string>((resolve) => {
      const s = net.connect(PORT, "127.0.0.1", () => {
        s.write(`POST /events HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\nContent-Type: application/json\r\nX-OpsContext-Secret: ${SECRET}\r\nContent-Length: ${big.length}\r\n\r\n`);
        s.write(big);
      });
      let out = "";
      s.on("data", (d) => (out += d));
      s.on("close", () => resolve(out));
      s.on("error", () => resolve(out));
    });
    expect(reply.split("\r\n")[0]).toBe("HTTP/1.1 413 Payload Too Large");
    expect((await req("GET", "/health")).status).toBe(200);
  });

  it("refuses a flood with 429 past the burst, and records how many it dropped", async () => {
    // 40 batches at once (2,000 records): twice the burst, so the refill during the run (200 a
    // second) cannot make room for all of them even on a loaded machine.
    const batch = Array.from({ length: 50 }, () => ev("vscode.tool_call", { tool: "Bash" }));
    const statuses = (await Promise.all(Array.from({ length: 40 }, () => post(batch)))).map((r) => r.status);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    expect(statuses.every((s) => s === 200 || s === 429)).toBe(true);
    await R.stopEventIngestServer(); // flushes the dropped count
    const drops = readFileSync(AUDIT(), "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((r) => r.event === "ingest.rate_limited");
    expect(drops).toHaveLength(1);
    expect(drops[0].payload.dropped).toBeGreaterThanOrEqual(50);
    expect(await R.startEventIngestServer()).toBe(PORT);
  });
});

describe("[EVENT-PORT-BELONGS-TO-THE-DAEMON] handover", () => {
  it("a chat server hands the port to a launchd agent, and the agent keeps retrying until it binds", async () => {
    await R.stopEventIngestServer();
    let agentAlive = false;
    const chatPorts: Array<number | null> = [];
    const chat = R; // this module instance plays the chat server
    expect(await chat.startEventIngestServer({ onPortChange: (p) => chatPorts.push(p), liveDaemon: () => (agentAlive ? 424242 : null), retryMs: 30, handoverMs: 30 })).toBe(PORT);

    vi.resetModules();
    const agent: Recv = await import("../src/http-server.js");
    const agentPorts: Array<number | null> = [];
    // The chat still holds the port: the agent gets null and keeps retrying.
    expect(await agent.startEventIngestServer({ daemon: true, onPortChange: (p) => agentPorts.push(p), retryMs: 30 })).toBeNull();

    agentAlive = true; // the agent registers; the chat server lets go, the agent takes over
    for (let i = 0; i < 100 && agentPorts.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    expect(chatPorts).toEqual([PORT, null]);
    expect(agentPorts).toEqual([PORT]);
    expect((await req("GET", "/health")).status).toBe(200);

    // While the agent lives, the chat server does not take the port back.
    await new Promise((r) => setTimeout(r, 150));
    expect(chatPorts).toEqual([PORT, null]);
    await agent.stopEventIngestServer();
    await chat.stopEventIngestServer();
  });

  it("a chat server does not bind at all while an agent is alive", async () => {
    vi.resetModules();
    const late: Recv = await import("../src/http-server.js");
    expect(await late.startEventIngestServer({ liveDaemon: () => 424242, retryMs: 30 })).toBeNull();
    await late.stopEventIngestServer();
  });
});

describe("liveDaemonPid and the servers warning", () => {
  it("finds a live agent record and names a non-agent holder of the port", async () => {
    const reg = await import("../src/server-registry.js");
    const dir = join(process.env.CONTEXTENGINE_HOME as string, "servers");
    mkdirSync(dir, { recursive: true });
    const base = { started: new Date().toISOString(), heartbeat: new Date().toISOString(), version: "t", script: "/nonexistent/index.js", build: "unknown", cwd: "/", node: "v" };
    writeFileSync(join(dir, `${process.ppid}.json`), JSON.stringify({ ...base, pid: process.ppid, ppid: 1, parent: "launchd", daemon: true }));
    writeFileSync(join(dir, `${process.pid}.json`), JSON.stringify({ ...base, pid: process.pid, ppid: process.ppid, parent: "claude", eventPort: 7842 }));
    expect(reg.liveDaemonPid(process.pid)).toBe(process.ppid);
    const report = reg.listServers();
    expect(report.warnings.join("\n")).toMatch(new RegExp(`held by pid ${process.pid}, not by the launchd agent pid ${process.ppid}`));
    expect(reg.formatServers(report)).toMatch(/launchd agent/);
    expect(reg.formatServers(report)).toMatch(/holds :7842/);
  });
});

describe("[EMIT-EVENT-GOES-THROUGH-THE-DOOR] contextengine emit-event", () => {
  const home = mkdtempSync(join(tmpdir(), "ce-emit-"));
  const env = { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: join(home, ".contextengine") };
  const emit = (args: string[]) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [join(process.cwd(), "dist", "cli.js"), "emit-event", ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
    } catch (e: any) {
      return { code: e.status as number, out: String(e.stderr) };
    }
  };
  const log = () => (existsSync(join(home, ".contextengine", "audit.log")) ? readFileSync(join(home, ".contextengine", "audit.log"), "utf8") : "");

  it("refuses kinds outside the capture list and the system actor", () => {
    expect(emit(["audit.redact", '{"reason":"forged","redacted":[]}']).code).toBe(1);
    expect(emit(["vscode.tool_call", '{"a":1}', "--actor", "system"]).code).toBe(1);
    expect(log()).not.toMatch(/audit\.redact/);
  });

  it("redacts the payload and drops prompt text like the receiver", () => {
    const pw = "Cnry" + "Zq7Kx9Wm";
    expect(emit(["vscode.tool_call", JSON.stringify({ tool: "Bash", args_preview: `mysql -u root -p${pw} db` }), "--actor", "vscode-ext"]).code).toBe(0);
    expect(emit(["vscode.prompt_submit", JSON.stringify({ text: `my prompt ${pw}` })]).code).toBe(0);
    const text = log();
    expect(text).not.toContain(pw);
    expect(text).toContain("[REDACTED:mysql_password]");
    expect(text).toMatch(/"text_fingerprint":"[0-9a-f]{16}"/);
  });
});
