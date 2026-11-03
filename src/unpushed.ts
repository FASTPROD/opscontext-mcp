// `contextengine unpushed`: per project, the commits not yet on GitHub. Read-only: every git call
// is a hardcoded argument list run without a shell (CLAUDE.md rule 4), nothing is fetched, so the
// answer is as of each repository's last fetch (the refs under refs/remotes/<github remote>/).
import { spawnSync } from "child_process";
import { existsSync } from "fs";
import type { ProjectDirectory } from "./config.js";

export interface UnpushedBranch {
  branch: string;
  /** Commits reachable from this branch and from no ref of the GitHub remote. */
  commits: number;
  newestAge: string;
  newestSubject: string;
}

export interface UnpushedProject {
  name: string;
  path: string;
  git: boolean;
  /** The remote whose URL points at github.com (origin when several do); null when none does. */
  githubRemote: string | null;
  /** Only the branches with commits to push (every branch when there is no GitHub remote). */
  branches: UnpushedBranch[];
  /** The union over all local branches: shared commits are counted once. */
  commits: number;
  error: string | null;
}

interface Run {
  ok: boolean;
  out: string;
  err: string;
}

function git(cwd: string, args: string[]): Run {
  const r = spawnSync("git", args, { cwd, encoding: "utf-8", timeout: 15_000, stdio: ["ignore", "pipe", "pipe"] });
  if (r.error) return { ok: false, out: "", err: r.error.message };
  return { ok: r.status === 0, out: (r.stdout ?? "").trim(), err: ((r.stderr ?? "").trim().split("\n")[0] ?? "").replace(/^fatal: /, "") };
}

/** The remote to compare with, from `git remote -v`: origin when it points at GitHub, else the first that does. */
export function githubRemoteOf(remoteList: string): string | null {
  const found: string[] = [];
  for (const line of remoteList.split("\n")) {
    const m = /^(\S+)\s+(\S+)\s+\(fetch\)$/.exec(line.trim());
    if (m && /(?:^|[@/.])github\.com(?:[:/]|$)/i.test(m[2])) found.push(m[1]);
  }
  if (found.length === 0) return null;
  return found.includes("origin") ? "origin" : found[0];
}

const count = (r: Run): number => (r.ok && /^\d+$/.test(r.out) ? Number(r.out) : 0);

export function unpushedFor(dir: ProjectDirectory): UnpushedProject {
  const base: UnpushedProject = { name: dir.name, path: dir.path, git: false, githubRemote: null, branches: [], commits: 0, error: null };
  if (!existsSync(dir.path)) return { ...base, error: "folder not found" };
  const inside = git(dir.path, ["rev-parse", "--is-inside-work-tree"]);
  if (!inside.ok || inside.out !== "true") {
    return { ...base, error: /not a git repository/i.test(inside.err) || inside.ok ? "not a git repository" : inside.err || "git failed" };
  }
  const remotes = git(dir.path, ["remote", "-v"]);
  const remote = remotes.ok ? githubRemoteOf(remotes.out) : null;
  const refs = git(dir.path, ["for-each-ref", "--format=%(refname:short)", "refs/heads/"]);
  const names = refs.ok && refs.out ? refs.out.split("\n").filter(Boolean) : [];
  const not = remote ? ["--not", `--remotes=${remote}`] : [];
  const branches: UnpushedBranch[] = [];
  for (const branch of names) {
    const n = count(git(dir.path, ["rev-list", "--count", `refs/heads/${branch}`, ...not]));
    if (n === 0) continue;
    const newest = git(dir.path, ["log", "-1", "--format=%cr%x1f%s", `refs/heads/${branch}`, ...not]);
    const [newestAge = "", newestSubject = ""] = newest.ok ? newest.out.split("\x1f") : [];
    branches.push({ branch, commits: n, newestAge, newestSubject });
  }
  const total = names.length === 0 ? 0 : count(git(dir.path, ["rev-list", "--count", "--branches", ...not]));
  return { ...base, git: true, githubRemote: remote, branches, commits: total };
}

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
const SUBJECT_MAX = 72;
const cut = (subject: string): string => (subject.length > SUBJECT_MAX ? subject.slice(0, SUBJECT_MAX).trimEnd() + "..." : subject);

export function unpushedReport(projects: UnpushedProject[]): string {
  const lines = ["Commits not yet on GitHub (as of each project's last fetch; nothing was fetched here):"];
  const toPush = projects.filter((p) => p.git && p.commits > 0);
  const upToDate = projects.filter((p) => p.git && p.commits === 0);
  const notRepo = projects.filter((p) => !p.git);
  const nameWidth = Math.max(0, ...projects.map((p) => p.name.length)) + 2;
  const branchWidth = Math.max(0, ...toPush.flatMap((p) => p.branches.map((b) => b.branch.length))) + 2;
  for (const p of toPush) {
    if (p.githubRemote === null) {
      lines.push(`  ${p.name.padEnd(nameWidth)}no GitHub remote: ${plural(p.commits, "commit")} on ${plural(p.branches.length, "branch", "branches")} never leave this machine`);
      continue;
    }
    for (const b of p.branches) {
      lines.push(`  ${p.name.padEnd(nameWidth)}${b.branch.padEnd(branchWidth)}${plural(b.commits, "commit")}, newest ${b.newestAge}: ${cut(b.newestSubject)}`);
    }
  }
  for (const p of notRepo) lines.push(`  ${p.name.padEnd(nameWidth)}${p.error ?? "not a git repository"}`);
  if (toPush.length === 0 && notRepo.length === 0) lines.push("  (nothing: every project is on GitHub)");
  const total = toPush.reduce((n, p) => n + p.commits, 0);
  const tail = [`${toPush.length} of ${projects.length} projects have commits not on GitHub (${plural(total, "commit")})`, `${upToDate.length} up to date`];
  if (notRepo.length > 0) tail.push(`${notRepo.length} not a repository`);
  lines.push(tail.join("; ") + ".");
  return lines.join("\n");
}

export const UNPUSHED_USAGE = `Usage: contextengine unpushed [--json]

Lists, per project of the configured workspaces, the commits that are not yet on GitHub: for each
local branch, the commits reachable from it and from no branch of the GitHub remote (origin when it
points at github.com, else the first remote that does), with the newest one's age and subject.
A project without a GitHub remote is listed with everything it holds. Nothing is fetched: the
answer is as of each repository's last fetch. Read-only. Pro licence, like list-projects.

  --json   The same as JSON (name, path, git, githubRemote, branches, commits, error).
`;
