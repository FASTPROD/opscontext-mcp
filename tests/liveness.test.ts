// [LOCK] [A-DEAD-HOLDER-LOSES-THE-LOCK-AT-ONCE], [A-DEAD-STORE-HOLDER-LOSES-THE-LOCK-AT-ONCE],
// [A-RECORD-BELONGS-TO-ITS-OWN-PROCESS], [A-CHAT-SERVER-ENDS-WITH-ITS-CHAT].
// E2E_REVIEW_2026-09 B1-2, B4-2, B5-1, B5-2. Each test fails on the code before the fix, except the
// guards, which say what must NOT change (a live holder keeps its lock, the launchd agent stays).
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync, utimesSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";
import { spawn, spawnSync, type ChildProcess } from "child_process";
import { appendAudit, rotateAuditLog, readAuditLog, resetCacheForTest } from "../src/audit.js";
import { listServers, liveDaemonPid } from "../src/server-registry.js";

let home: string;
let original: string | undefined;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-liveness-"));
  original = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = home;
  resetCacheForTest();
});

afterEach(() => {
  if (original === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = original;
  rmSync(home, { recursive: true, force: true });
});

/** The pid of a process that has already exited. */
function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid!;
}

describe("the append lock of a dead holder", () => {
  it("is broken at once when its pid is gone", () => {
    appendAudit("learning.save", { id: "before" });
    writeFileSync(join(home, "audit.lock"), `${deadPid()}\n2026-09-27T17:01:14Z\n`);
    const t0 = Date.now();
    appendAudit("learning.save", { id: "after" });
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(readAuditLog()).toHaveLength(2);
  });

  it("is broken at once when it is empty and older than a second (killed before writing its pid)", () => {
    writeFileSync(join(home, "audit.lock"), "");
    const old = new Date(Date.now() - 2000);
    utimesSync(join(home, "audit.lock"), old, old);
    appendAudit("learning.save", { id: "after" });
    expect(readAuditLog()).toHaveLength(1);
  });

  it("guard: a live holder keeps it, the writer waits and gives up as before", () => {
    const holder = spawn("sleep", ["30"]);
    try {
      writeFileSync(join(home, "audit.lock"), `${holder.pid}\n`);
      expect(() => appendAudit("learning.save", { id: "x" })).toThrow(/Failed to acquire audit lock/);
    } finally {
      holder.kill();
    }
  });

  it("does not block the next rotation for ten minutes when the rotator died", () => {
    appendAudit("learning.save", { id: "one" });
    writeFileSync(join(home, "audit.rotate.lock"), `${deadPid()}\n`);
    const r = rotateAuditLog({ maxRecords: 50_000 });
    expect(r.inProgress).toBeUndefined();
  });
});

describe("the learnings-store lock of a dead holder", () => {
  it("is taken over at once, and the dead writer's temp copy goes", async () => {
    // learnings.ts fixes its path at its first import, which happens here, under this test's home.
    const L = await import("../src/learnings.js");
    const store = home;
    const dead = deadPid();
    mkdirSync(join(store, "learnings.json.lock"), { recursive: true });
    writeFileSync(join(store, "learnings.json.lock", "pid"), String(dead));
    writeFileSync(join(store, `learnings.json.tmp-${dead}-1790500000000`), "{}");
    const before = process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS;
    process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS = "1500";
    try {
      L.saveLearning("testing", "A dead holder's lock is taken over at once, never waited out", "liveness test", "pbproj");
    } finally {
      if (before === undefined) delete process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS;
      else process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS = before;
    }
    expect(readdirSync(store).filter((f) => f.startsWith("learnings.json.tmp-"))).toEqual([]);
  });
});

describe("a registry record whose pid now belongs to another process", () => {
  it("is not a live server, not the daemon, and is removed", async () => {
    const other = spawn("sleep", ["30"]);
    try {
      await new Promise((r) => setTimeout(r, 1500)); // started well after the record says its server did
      const dir = join(home, "servers");
      mkdirSync(dir, { recursive: true });
      const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
      writeFileSync(join(dir, `${other.pid}.json`), JSON.stringify({ pid: other.pid, ppid: 1, parent: "launchd", started: hourAgo, heartbeat: hourAgo, version: "2.10.0", script: "/x/dist/index.js", build: "b", cwd: "/", node: "v", daemon: true, eventPort: 7842, role: "indexer", corpus: "c" }));
      expect(liveDaemonPid(process.pid)).toBeNull();
      const report = listServers();
      expect(report.servers.map((s) => s.pid)).not.toContain(other.pid);
      expect(existsSync(join(dir, `${other.pid}.json`))).toBe(false);
    } finally {
      other.kill();
    }
  });

  it("guard: a record written by its own running process stays", () => {
    const dir = join(home, "servers");
    mkdirSync(dir, { recursive: true });
    const now = new Date().toISOString();
    writeFileSync(join(dir, `${process.pid}.json`), JSON.stringify({ pid: process.pid, ppid: process.ppid, parent: "node", started: now, heartbeat: now, version: "t", script: "/x/dist/index.js", build: "b", cwd: "/", node: "v" }));
    expect(listServers().servers.map((s) => s.pid)).toContain(process.pid);
  });
});

describe("a chat server whose client closed the connection", () => {
  const start = (extra: Record<string, string>): { child: ChildProcess; ready: Promise<void>; ceHome: string; stderr: () => string } => {
    const h = mkdtempSync(join(tmpdir(), "ce-liveness-server-"));
    mkdirSync(join(h, "ws"), { recursive: true });
    const env = {
      HOME: h,
      PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
      CONTEXTENGINE_HOME: join(h, ".contextengine"),
      CONTEXTENGINE_WORKSPACES: join(h, "ws"),
      CONTEXTENGINE_AUTO_ROTATE: "0",
      OPSCONTEXT_EVENT_PORT: String(30000 + (process.pid % 20000)),
      ...extra,
    };
    const child = spawn(process.execPath, [join(process.cwd(), "dist", "index.js")], { env, cwd: h, stdio: ["pipe", "ignore", "pipe"] });
    let err = "";
    const ready = new Promise<void>((resolve) => {
      child.stderr!.on("data", (d) => { err += d; if (/running on stdio/.test(err)) resolve(); });
    });
    return { child, ready, ceHome: env.CONTEXTENGINE_HOME, stderr: () => err };
  };
  const exited = (child: ChildProcess, ms: number) =>
    new Promise<string | null>((resolve) => {
      const t = setTimeout(() => resolve(null), ms);
      child.on("exit", (code, signal) => { clearTimeout(t); resolve(signal ?? `code ${code}`); });
    });

  it("stops, and removes its registry record", async () => {
    const { child, ready, ceHome } = start({});
    await ready;
    child.stdin!.end();
    const how = await exited(child, 10_000);
    if (how === null) child.kill("SIGKILL");
    expect(["code 0", "SIGKILL"]).toContain(how);
    expect(existsSync(join(ceHome, "servers", `${child.pid}.json`))).toBe(false);
  }, 40_000);

  it("ends without the model runtime's native abort once the model is loaded", async () => {
    const { child, ceHome, stderr } = start({});
    await new Promise<void>((resolve) => { const t = setInterval(() => { if (/Semantic search ready|Embeddings unavailable|Semantic search disabled/.test(stderr())) { clearInterval(t); resolve(); } }, 100); });
    child.stdin!.end();
    const how = await exited(child, 10_000);
    if (how === null) child.kill("SIGKILL");
    expect(how).not.toBeNull();
    expect(how).not.toBe("SIGABRT");
    expect(stderr()).not.toMatch(/libc\+\+abi/);
    expect(existsSync(join(ceHome, "servers", `${child.pid}.json`))).toBe(false);
  }, 60_000);

  it("guard: the launchd agent stays (its stdin is /dev/null by design)", async () => {
    const { child, ready } = start({ OPSCONTEXT_DAEMON: "1", OPSCONTEXT_EVENT_PORT: String(31000 + (process.pid % 20000)) });
    // (the daemon's own stop signal also ends it without the abort: covered by endThisServer)
    await ready;
    child.stdin!.end();
    const code = await exited(child, 3_000);
    child.kill("SIGKILL");
    expect(code).toBeNull();
  }, 40_000);
});
