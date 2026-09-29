// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY], widened to the collectors. E2E_REVIEW_2026-09 C6-4: exec()
// returned "" on any failure, so collectPM2() gave the same [] with pm2 absent, failing or empty, and
// the sources list said "no PM2 processes" about a box that has no pm2. A collector that could not
// run says so through onFail, and the caller counts "N collector(s) failed (pm2: not found)".
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, chmodSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execFileSync } from "child_process";
import {
  collectPM2, collectDocker, collectCrontab, collectPackageJson, collectGitLog, collectSystemOps, collectProjectOps,
} from "../src/collectors.js";

let dir: string;
let bin: string;
let savedPath: string | undefined;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ce-collectors-test-"));
  bin = join(dir, "bin");
  mkdirSync(bin);
  savedPath = process.env.PATH;
  // Only our stand-ins and /bin (for sh): no real pm2, docker or crontab (macOS keeps crontab in /usr/bin).
  process.env.PATH = `${bin}:/bin`;
});
afterEach(() => {
  process.env.PATH = savedPath;
  const g = join(dir, "repo", ".git");
  if (existsSync(g)) { try { chmodSync(g, 0o755); } catch { /* */ } }
  rmSync(dir, { recursive: true, force: true });
});

/** A stand-in command: prints `stdout`, writes `stderr`, exits with `code`. */
function fake(name: string, stdout: string, code = 0, stderr = ""): void {
  writeFileSync(join(bin, name), `#!/bin/sh\nprintf '%s' ${JSON.stringify(stdout)}\n${stderr ? `printf '%s\\n' ${JSON.stringify(stderr)} >&2\n` : ""}exit ${code}\n`);
  chmodSync(join(bin, name), 0o755);
}
type Failure = { collector: string; reason: string };
function recorder(): { failures: Failure[]; onFail: (collector: string, reason: string) => void } {
  const failures: Failure[] = [];
  return { failures, onFail: (collector, reason) => failures.push({ collector, reason }) };
}
const notRoot = (process.getuid?.() ?? 1) !== 0;

describe("pm2", () => {
  it("absent: no chunks, and the failure says 'not found'", () => {
    const r = recorder();
    expect(collectPM2("System", r.onFail)).toEqual([]);
    expect(r.failures).toEqual([{ collector: "pm2", reason: "not found" }]);
  });
  it("present with no process: no chunks and no failure (a real empty)", () => {
    fake("pm2", "[]");
    const r = recorder();
    expect(collectPM2("System", r.onFail)).toEqual([]);
    expect(r.failures).toEqual([]);
  });
  it("present but failing: no chunks, and the failure carries what pm2 said", () => {
    fake("pm2", "", 1, "pm2: daemon not reachable");
    const r = recorder();
    expect(collectPM2("System", r.onFail)).toEqual([]);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0].collector).toBe("pm2");
    expect(r.failures[0].reason).toContain("daemon not reachable");
  });
  it("present with one process: one chunk", () => {
    fake("pm2", JSON.stringify([{ name: "api", pid: 4, pm2_env: { status: "online", PORT: 8003 } }]));
    const r = recorder();
    const chunks = collectPM2("System", r.onFail);
    expect(chunks).toHaveLength(1);
    expect(chunks[0].content).toContain("api: online");
    expect(r.failures).toEqual([]);
  });
});

describe("docker and crontab", () => {
  it("docker absent is a counted failure, not 'no containers'", () => {
    const r = recorder();
    expect(collectDocker("System", r.onFail)).toEqual([]);
    expect(r.failures).toEqual([{ collector: "docker", reason: "not found" }]);
  });
  it("crontab with no table for the user is a real empty, a refused crontab is a failure", () => {
    fake("crontab", "", 1, "no crontab for yan");
    const none = recorder();
    expect(collectCrontab("System", none.onFail)).toEqual([]);
    expect(none.failures).toEqual([]);
    fake("crontab", "", 1, "crontab: you are not allowed to use this program");
    const refused = recorder();
    expect(collectCrontab("System", refused.onFail)).toEqual([]);
    expect(refused.failures).toHaveLength(1);
    expect(refused.failures[0].reason).toContain("not allowed");
  });
  it("crontab absent is 'not found'", () => {
    const r = recorder();
    collectCrontab("System", r.onFail);
    expect(r.failures).toEqual([{ collector: "crontab", reason: "not found" }]);
  });
});

describe("project files", () => {
  it("a package.json that is not JSON is a failure, not a project without one", () => {
    const proj = join(dir, "proj");
    mkdirSync(proj);
    writeFileSync(join(proj, "package.json"), "{ not json");
    const r = recorder();
    expect(collectPackageJson(proj, "proj", r.onFail)).toEqual([]);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0].collector).toBe("package.json");
    expect(r.failures[0].reason).toMatch(/^proj: /);
  });
  it("a folder that is not a repository is absent, in silence", () => {
    const proj = join(dir, "plain");
    mkdirSync(proj);
    const r = recorder();
    expect(collectGitLog(proj, "plain", r.onFail)).toEqual([]);
    expect(r.failures).toEqual([]);
  });
  it.skipIf(!notRoot)("a repository git cannot read is a failure, not an empty history", () => {
    const repo = join(dir, "repo");
    mkdirSync(repo);
    const env = { ...process.env, PATH: savedPath as string, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
    execFileSync("git", ["init", "-q"], { cwd: repo, env });
    execFileSync("git", ["commit", "-q", "--allow-empty", "-m", "init"], { cwd: repo, env });
    process.env.PATH = savedPath as string; // git itself is real here
    const ok = recorder();
    expect(collectGitLog(repo, "repo", ok.onFail).length).toBeGreaterThan(0);
    expect(ok.failures).toEqual([]);
    chmodSync(join(repo, ".git"), 0o000);
    const r = recorder();
    expect(collectGitLog(repo, "repo", r.onFail)).toEqual([]);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0].collector).toBe("git");
    expect(r.failures[0].reason).toMatch(/^repo: /);
  });
});

describe("the aggregators pass the failures up", () => {
  it("collectSystemOps names every tool that could not run", () => {
    const r = recorder();
    collectSystemOps(r.onFail);
    const names = r.failures.map((f) => `${f.collector}: ${f.reason}`).sort();
    expect(names).toEqual(expect.arrayContaining(["crontab: not found", "docker: not found", "pm2: not found"]));
  });
  it("collectProjectOps reports a project's unreadable files", () => {
    const proj = join(dir, "proj2");
    mkdirSync(proj);
    writeFileSync(join(proj, "package.json"), "{ not json");
    writeFileSync(join(proj, "composer.json"), "{ not json either");
    const r = recorder();
    collectProjectOps(proj, "proj2", r.onFail);
    expect(r.failures.map((f) => f.collector).sort()).toEqual(["composer.json", "package.json"]);
  });
});
