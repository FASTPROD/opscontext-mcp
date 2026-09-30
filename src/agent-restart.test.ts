// [LOCK] [THE-AGENT-FOLLOWS-THE-BUILD]: the launchd agent leaves for a new build once its folder is
// quiet, once per build, only when launchd brings it back; chat servers never leave. E2E_REVIEW_2026-09
// point 20, the owner's yes on 2026-09-30. Throwaway HOME via src/test-setup.ts.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { decideAgentRestart, checkAgentRestart, recordAgentRestart, lastRestartTo, keepAliveIsTrue, preflightBuild, QUIET_MS, MIN_UP_MS, PREFLIGHT_RETRY_AFTER_TIMEOUT_MS, type RestartInputs } from "./agent-restart.js";
import { buildPlist } from "./install-autostart.js";
import { buildHashOf } from "./server-registry.js";

const NOW = Date.parse("2026-09-30T18:00:00Z");
const PLIST = buildPlist("/usr/local/bin/node", "/x/dist/index.js", "/usr/local/bin");
const base = (over: Partial<RestartInputs> = {}): RestartInputs => ({
  daemon: true, platform: "darwin", ppid: 1, loadedBuild: "old111old111", diskBuild: "new222new222",
  now: NOW, startedAt: NOW - MIN_UP_MS - 1, plistText: () => PLIST,
  newestCompiledMs: () => NOW - QUIET_MS - 1, lastRestartTo: () => null, ...over,
});

describe("decideAgentRestart", () => {
  it("leaves for a new build once it is quiet, the agent has run long enough and launchd brings it back", () => {
    expect(decideAgentRestart(base())).toEqual({ restart: true, from: "old111old111", to: "new222new222" });
  });
  it("never for a chat server, and says nothing", () => {
    expect(decideAgentRestart(base({ daemon: false }))).toEqual({ restart: false, state: "not-the-agent", note: null });
  });
  it("a current agent reads nothing else: no plist, no folder, no marker", () => {
    const touched: string[] = [];
    const d = decideAgentRestart(base({
      diskBuild: "old111old111",
      plistText: () => { touched.push("plist"); return PLIST; },
      newestCompiledMs: () => { touched.push("folder"); return 0; },
      lastRestartTo: () => { touched.push("marker"); return null; },
    }));
    expect(d).toEqual({ restart: false, state: "current", note: null });
    expect(touched).toEqual([]);
  });
  it("stays while the build folder is still changing (tsc file by file, the prune, the rubric encoding)", () => {
    const d = decideAgentRestart(base({ newestCompiledMs: () => NOW - 5_000 }));
    expect(d).toMatchObject({ restart: false, state: "changing" });
    expect(decideAgentRestart(base({ newestCompiledMs: () => null }))).toMatchObject({ restart: false, state: "changing" });
  });
  it("stays when it started less than MIN_UP_MS ago", () => {
    expect(decideAgentRestart(base({ startedAt: NOW - 60_000 }))).toMatchObject({ restart: false, state: "too-soon" });
  });
  it("never twice for the same build: a fresh agent that still looks stale stays and says how to restart it", () => {
    const d = decideAgentRestart(base({ lastRestartTo: () => "new222new222" }));
    expect(d).toMatchObject({ restart: false, state: "already-restarted" });
    expect((d as { note: string }).note).toMatch(/launchctl kickstart -k gui\/\$\(id -u\)\/com\.opscontext\.mcp/);
    expect(decideAgentRestart(base({ lastRestartTo: () => "older0older0" }))).toMatchObject({ restart: true });
  });
  it("stays when launchd would not start it again, or when launchd did not start it", () => {
    expect(decideAgentRestart(base({ plistText: () => null }))).toMatchObject({ restart: false, state: "no-keepalive" });
    const dict = PLIST.replace(/<key>KeepAlive<\/key>\s*<true\/>/, "<key>KeepAlive</key>\n    <dict><key>SuccessfulExit</key><false/></dict>");
    expect(dict).not.toBe(PLIST);
    expect(decideAgentRestart(base({ plistText: () => dict }))).toMatchObject({ restart: false, state: "no-keepalive" });
    expect(decideAgentRestart(base({ ppid: 4242 }))).toMatchObject({ restart: false, state: "not-under-launchd" });
    expect(decideAgentRestart(base({ platform: "linux" }))).toMatchObject({ restart: false, state: "not-under-launchd" });
  });
  it("stays when either build cannot be known", () => {
    expect(decideAgentRestart(base({ loadedBuild: "unknown" }))).toMatchObject({ restart: false, state: "unknown-build" });
    expect(decideAgentRestart(base({ diskBuild: null }))).toMatchObject({ restart: false, state: "unknown-build" });
  });
  it("the plist our installer writes passes the KeepAlive check", () => {
    expect(keepAliveIsTrue(PLIST)).toBe(true);
  });
});

describe("checkAgentRestart and the marker, on real files", () => {
  const prev = process.env.OPSCONTEXT_DAEMON;
  afterEach(() => { if (prev === undefined) delete process.env.OPSCONTEXT_DAEMON; else process.env.OPSCONTEXT_DAEMON = prev; });

  it("compares the loaded build with the folder on disk", () => {
    const d = mkdtempSync(join(tmpdir(), "ce-follow-"));
    const dist = join(d, "dist"); mkdirSync(dist);
    const script = join(dist, "index.js");
    writeFileSync(script, "export const v = 1;\n");
    writeFileSync(join(dist, "audit.js"), "export const a = 1;\n");
    const loaded = buildHashOf(script) as string;
    try {
      process.env.OPSCONTEXT_DAEMON = "1";
      expect(checkAgentRestart({ script, loadedBuild: loaded, startedAt: 0 })).toEqual({ restart: false, state: "current", note: null });
      writeFileSync(join(dist, "audit.js"), "export const a = 2;\n"); // a rebuild of one module
      const after = checkAgentRestart({ script, loadedBuild: loaded, startedAt: 0 });
      expect(after.restart).toBe(false); // a test runner is never launchd's child
      expect(after).toMatchObject({ state: process.platform === "darwin" && process.ppid === 1 ? "changing" : "not-under-launchd" });
      expect((after as { note: string }).note).toContain(`build ${buildHashOf(script)} is on disk, this agent runs ${loaded}`);
      delete process.env.OPSCONTEXT_DAEMON;
      expect(checkAgentRestart({ script, loadedBuild: loaded, startedAt: 0 })).toEqual({ restart: false, state: "not-the-agent", note: null });
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
  it("the marker names the build the last restart was for", () => {
    expect(lastRestartTo()).toBeNull();
    recordAgentRestart({ pid: 123, from: "old111old111", to: "new222new222" });
    expect(lastRestartTo()).toBe("new222new222");
  });
});

describe("preflightBuild: leave only for a build that starts", () => {
  it("runs the entry with CONTEXTENGINE_PREFLIGHT=1 in a scratch CE home, not the agent's, and once per build", async () => {
    const d = mkdtempSync(join(tmpdir(), "ce-preflight-test-"));
    const log = join(d, "runs.txt");
    const ok = join(d, "ok.mjs");
    writeFileSync(ok, `import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(log)}, JSON.stringify({ pre: process.env.CONTEXTENGINE_PREFLIGHT, home: process.env.CONTEXTENGINE_HOME, daemon: process.env.OPSCONTEXT_DAEMON ?? null }) + "\\n");
if (process.env.CONTEXTENGINE_PREFLIGHT === "1") process.exit(0);
setInterval(() => {}, 1000); // a real server would stay up: the check must never wait for that
`);
    const prev = process.env.OPSCONTEXT_DAEMON;
    process.env.OPSCONTEXT_DAEMON = "1";
    try {
      expect(await preflightBuild(ok, "okbuild00001")).toEqual({ ok: true });
      expect(await preflightBuild(ok, "okbuild00001")).toEqual({ ok: true }); // cached: no second run
      const runs = readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(runs).toHaveLength(1);
      expect(runs[0].pre).toBe("1");
      expect(runs[0].daemon).toBeNull();
      expect(runs[0].home).not.toBe(process.env.CONTEXTENGINE_HOME);
      expect(existsSync(runs[0].home)).toBe(false); // the scratch home is gone afterwards
    } finally {
      if (prev === undefined) delete process.env.OPSCONTEXT_DAEMON; else process.env.OPSCONTEXT_DAEMON = prev;
      rmSync(d, { recursive: true, force: true });
    }
  });
  it("a build that throws while loading does not start, and says why", async () => {
    const d = mkdtempSync(join(tmpdir(), "ce-preflight-test-"));
    const bad = join(d, "bad.mjs");
    const log = join(d, "runs.txt");
    writeFileSync(bad, `import { appendFileSync } from "node:fs";\nappendFileSync(${JSON.stringify(log)}, "run\\n");\nthrow new Error("boom at import");\n`);
    try {
      const r = await preflightBuild(bad, "badbuild0001");
      expect(r.ok).toBe(false);
      expect((r as { error: string }).error).toMatch(/boom at import/);
      await preflightBuild(bad, "badbuild0001", { now: Date.now() + PREFLIGHT_RETRY_AFTER_TIMEOUT_MS + 1 });
      expect(readFileSync(log, "utf8").trim().split("\n")).toHaveLength(1); // a build that fails is never tried again
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
  it("a build that only ran out of time is asked again after a while, a failed one never", async () => {
    const d = mkdtempSync(join(tmpdir(), "ce-preflight-test-"));
    const log = join(d, "runs.txt");
    const slow = join(d, "slow.mjs");
    writeFileSync(slow, `import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(log)}, "run\\n");
setInterval(() => {}, 1000); // never exits: a hung build, or a Mac too loaded to answer in time
`);
    const t0 = Date.parse("2026-09-30T18:00:00Z");
    try {
      const first = await preflightBuild(slow, "slowbuild001", { now: t0, timeoutMs: 400 });
      expect(first).toMatchObject({ ok: false, timedOut: true });
      expect(await preflightBuild(slow, "slowbuild001", { now: t0 + 60_000, timeoutMs: 400 })).toMatchObject({ ok: false, timedOut: true });
      expect(readFileSync(log, "utf8").trim().split("\n")).toHaveLength(1); // remembered for a while
      await preflightBuild(slow, "slowbuild001", { now: t0 + PREFLIGHT_RETRY_AFTER_TIMEOUT_MS + 1, timeoutMs: 400 });
      expect(readFileSync(log, "utf8").trim().split("\n")).toHaveLength(2); // then asked again
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
