// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at end_session. E2E_REVIEW_2026-09 C6-5: a project whose git status
// failed was listed neither clean nor dirty, and the checklist said ALL CLEAR over it.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, chmodSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execFileSync } from "child_process";
import { repoStatus } from "../src/repo-status.js";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ce-repo-status-")); });
afterEach(() => {
  for (const sub of readdirSync(dir)) { const g = join(dir, sub, ".git"); if (existsSync(g)) { try { chmodSync(g, 0o755); } catch { /* a file */ } } }
  rmSync(dir, { recursive: true, force: true });
});
const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
function repo(name: string): string {
  const p = join(dir, name); mkdirSync(p);
  execFileSync("git", ["init", "-q"], { cwd: p, env });
  execFileSync("git", ["commit", "-q", "--allow-empty", "-m", "init"], { cwd: p, env });
  return p;
}
const notRoot = (process.getuid?.() ?? 1) !== 0;

describe("repoStatus", () => {
  it("clean and dirty repositories", () => {
    const p = repo("clean");
    expect(repoStatus(p)).toMatchObject({ state: "clean" });
    writeFileSync(join(p, "new.txt"), "x");
    const st = repoStatus(p);
    expect(st.state).toBe("dirty");
    if (st.state === "dirty") expect(st.files).toEqual(["?? new.txt"]);
  });
  it("a plain folder is not a repository", () => {
    const p = join(dir, "plain"); mkdirSync(p);
    expect(repoStatus(p)).toEqual({ state: "not_git" });
  });
  it.skipIf(!notRoot)("a repository git cannot read is 'failed' with the error, never 'not a repository'", () => {
    const p = repo("locked");
    chmodSync(join(p, ".git"), 0o000);
    const st = repoStatus(p);
    expect(st.state).toBe("failed");
    if (st.state === "failed") expect(st.error).toMatch(/not a git repository/);
  });
  it("a corrupt gitfile is 'failed' with git's words", () => {
    const p = join(dir, "corrupt"); mkdirSync(p);
    writeFileSync(join(p, ".git"), "garbage\n");
    const st = repoStatus(p);
    expect(st.state).toBe("failed");
    if (st.state === "failed") expect(st.error).toMatch(/invalid gitfile format/);
  });
});
