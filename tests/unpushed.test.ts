// `contextengine unpushed`: per project, the commits not yet on GitHub. Real throwaway repos; the
// GitHub remote is a URL that is never fetched, and refs/remotes/<remote>/* are set by hand to
// stand for what the last fetch saw. Nothing reaches the network.
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { unpushedFor, unpushedReport } from "../src/unpushed.js";

const HOME = process.env.HOME as string;
function git(cwd: string, ...args: string[]): string {
  const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", ...args], { cwd, encoding: "utf-8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}
function repo(name: string, remoteUrl: string | null): string {
  const dir = mkdtempSync(join(HOME, `${name}-`));
  git(dir, "init", "-q", "-b", "main");
  if (remoteUrl) git(dir, "remote", "add", "origin", remoteUrl);
  return dir;
}
function commit(dir: string, subject: string): string {
  writeFileSync(join(dir, `${subject.replace(/\W+/g, "_")}.txt`), subject);
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", subject);
  return git(dir, "rev-parse", "HEAD");
}
const project = (dir: string, name = "proj") => ({ name, path: dir });

describe("unpushedFor", () => {
  it("counts nothing when every local branch is on the GitHub remote", () => {
    const dir = repo("clean", "https://github.com/org/clean.git");
    const sha = commit(dir, "first");
    git(dir, "update-ref", "refs/remotes/origin/main", sha);
    const r = unpushedFor(project(dir));
    expect(r).toMatchObject({ git: true, githubRemote: "origin", commits: 0, branches: [], error: null });
  });

  it("lists each branch with its count and newest commit, and the union as the project total", () => {
    const dir = repo("work", "git@github.com:org/work.git");
    const pushed = commit(dir, "first");
    git(dir, "update-ref", "refs/remotes/origin/main", pushed);
    commit(dir, "second");
    commit(dir, "third: the newest on main");
    git(dir, "checkout", "-q", "-b", "feature");
    commit(dir, "feature work");
    const r = unpushedFor(project(dir, "work"));
    expect(r.githubRemote).toBe("origin");
    expect(r.branches.map((b) => [b.branch, b.commits])).toEqual([["feature", 3], ["main", 2]]);
    expect(r.branches[1].newestSubject).toBe("third: the newest on main");
    expect(r.branches[0].newestAge).toMatch(/second|minute|now/);
    expect(r.commits).toBe(3); // second, third, feature work: the union, not 3 + 2
  });

  it("says when there is no GitHub remote: every commit stays on this machine", () => {
    const dir = repo("drive-only", "/Volumes/Drive/x.git");
    commit(dir, "a");
    commit(dir, "b");
    const r = unpushedFor(project(dir));
    expect(r).toMatchObject({ git: true, githubRemote: null, commits: 2 });
    expect(r.branches).toEqual([expect.objectContaining({ branch: "main", commits: 2 })]);
  });

  it("prefers origin when two remotes point at GitHub, and reads a remote named otherwise", () => {
    const dir = repo("two", "https://github.com/org/two.git");
    git(dir, "remote", "add", "fork", "https://github.com/me/two.git");
    const sha = commit(dir, "x");
    git(dir, "update-ref", "refs/remotes/origin/main", sha);
    expect(unpushedFor(project(dir)).githubRemote).toBe("origin");
    const dir2 = repo("named", null);
    git(dir2, "remote", "add", "gh", "ssh://git@github.com/org/named.git");
    commit(dir2, "y");
    expect(unpushedFor(project(dir2))).toMatchObject({ githubRemote: "gh", commits: 1 });
  });

  it("reports a folder that is not a repository, a folder that is gone, and a repository without commits", () => {
    const plain = mkdtempSync(join(HOME, "plain-"));
    mkdirSync(join(plain, "docs"));
    expect(unpushedFor(project(plain))).toMatchObject({ git: false, commits: 0, branches: [], error: "not a git repository" });
    expect(unpushedFor(project(join(plain, "gone")))).toMatchObject({ git: false, commits: 0, error: "folder not found" });
    const empty = repo("empty", "https://github.com/org/empty.git");
    expect(unpushedFor(project(empty))).toMatchObject({ git: true, githubRemote: "origin", commits: 0, branches: [] });
  });
});

describe("unpushedReport", () => {
  it("prints one line per branch with work to push, one for a project without GitHub, and a footer with the counts", () => {
    const text = unpushedReport([
      { name: "Clean", path: "/p/clean", git: true, githubRemote: "origin", branches: [], commits: 0, error: null },
      { name: "Work", path: "/p/work", git: true, githubRemote: "origin", commits: 3, error: null, branches: [
        { branch: "feature", commits: 3, newestAge: "2 hours ago", newestSubject: "feature work" },
        { branch: "main", commits: 2, newestAge: "3 days ago", newestSubject: "third" },
      ] },
      { name: "DriveOnly", path: "/p/d", git: true, githubRemote: null, commits: 812, error: null, branches: [{ branch: "main", commits: 812, newestAge: "1 year ago", newestSubject: "z" }] },
      { name: "Plain", path: "/p/plain", git: false, githubRemote: null, commits: 0, error: "not a git repository", branches: [] },
    ]);
    expect(text).toMatch(/^Commits not yet on GitHub/m);
    expect(text).toMatch(/Work +feature +3 commits, newest 2 hours ago: feature work/);
    expect(text).toMatch(/Work +main +2 commits, newest 3 days ago: third/);
    expect(text).toMatch(/DriveOnly +no GitHub remote: 812 commits on 1 branch never leave this machine/);
    expect(text).toMatch(/Plain +not a git repository/);
    expect(text).not.toMatch(/Clean/);
    expect(text).toMatch(/2 of 4 projects have commits not on GitHub \(815 commits\); 1 up to date; 1 not a repository/);
    expect(text).toMatch(/nothing was fetched/);
  });

  it("cuts a long subject at 72 characters so one branch stays on one readable line", () => {
    const long = "feat(forecast): " + "x".repeat(200);
    const text = unpushedReport([{ name: "W", path: "/w", git: true, githubRemote: "origin", commits: 1, error: null, branches: [{ branch: "main", commits: 1, newestAge: "now", newestSubject: long }] }]);
    const line = text.split("\n").find((l) => l.includes("main")) ?? "";
    expect(line).toMatch(/: feat\(forecast\): x+\.\.\.$/);
    expect(line.length).toBeLessThan(120);
  });
});
