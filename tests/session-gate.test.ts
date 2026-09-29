// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY], widened to the Stop hook. E2E_REVIEW_2026-09 C6-1: a repository
// git could not read (.git at mode 000) made the session gate exit 0 in silence, the same answer as
// "not a repository", and the turn ended with the session unsaved and nobody told.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, chmodSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execFileSync, spawnSync } from "child_process";
import { evaluateSessionGate } from "../src/session-gate.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ce-gate-test-"));
});
afterEach(() => {
  // a .git left at mode 000 cannot be removed: give it back first
  for (const sub of readdirSync(dir)) {
    const g = join(dir, sub, ".git");
    if (existsSync(g)) { try { chmodSync(g, 0o755); } catch { /* a gitfile, not a folder */ } }
  }
  rmSync(dir, { recursive: true, force: true });
});

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
function repo(name: string, commit = true): string {
  const p = join(dir, name);
  mkdirSync(p);
  execFileSync("git", ["init", "-q"], { cwd: p, env: GIT_ENV });
  if (commit) execFileSync("git", ["commit", "-q", "--allow-empty", "-m", "init"], { cwd: p, env: GIT_ENV });
  return p;
}
function sessionsDir(): string {
  const s = join(dir, "sessions");
  mkdirSync(s, { recursive: true });
  return s;
}
/** Root reads a mode-000 folder anyway; the permission cases mean nothing there. */
const notRoot = (process.getuid?.() ?? 1) !== 0;

describe("the session gate tells 'not a repository' from 'git could not answer'", () => {
  it("blocks on a repository with a commit and no saved session (the gate itself)", () => {
    const r = evaluateSessionGate({ repo: repo("repo"), sessionsDir: sessionsDir() });
    expect(r.block).toBe(true);
    expect(r.reason).toBe("stale");
  });

  it("passes in silence on a plain folder", () => {
    const plain = join(dir, "plain");
    mkdirSync(plain);
    const r = evaluateSessionGate({ repo: plain, sessionsDir: sessionsDir() });
    expect(r).toMatchObject({ block: false, reason: "not_git", message: "" });
  });

  it("passes in silence on a repository with no commit yet", () => {
    const r = evaluateSessionGate({ repo: repo("empty", false), sessionsDir: sessionsDir() });
    expect(r).toMatchObject({ block: false, reason: "no_commits", message: "" });
  });

  it.skipIf(!notRoot)("a repository whose .git cannot be read passes, with one line saying so", () => {
    const p = repo("locked");
    chmodSync(join(p, ".git"), 0o000);
    const r = evaluateSessionGate({ repo: p, sessionsDir: sessionsDir() });
    expect(r.block).toBe(false);
    expect(r.reason).toBe("git_failed");
    expect(r.message).toContain(`session gate could not check ${p}: `);
    expect(r.message).toMatch(/\.git entry is there but git cannot read it/);
  });

  it("a corrupt .git file is a failure git names, not a plain folder", () => {
    const p = join(dir, "corrupt");
    mkdirSync(p);
    writeFileSync(join(p, ".git"), "garbage\n");
    const r = evaluateSessionGate({ repo: p, sessionsDir: sessionsDir() });
    expect(r.block).toBe(false);
    expect(r.reason).toBe("git_failed");
    expect(r.message).toContain("invalid gitfile format");
  });

  it.skipIf(!notRoot)("the Stop hook prints that line on stderr and exits 0 (never traps the user)", () => {
    const p = repo("locked-cli");
    chmodSync(join(p, ".git"), 0o000);
    const home = join(dir, "home");
    mkdirSync(join(home, "sessions"), { recursive: true });
    const run = spawnSync(process.execPath, [join(process.cwd(), "dist", "cli.js"), "session-gate"], {
      encoding: "utf8",
      input: "{}",
      env: { ...process.env, CLAUDE_PROJECT_DIR: p, CONTEXTENGINE_HOME: home },
    });
    expect(run.status).toBe(0);
    expect(run.stderr).toContain(`session gate could not check ${p}`);
    expect(run.stdout).toBe("");
  });
});
