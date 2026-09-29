// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] (src/agents.ts), widened to end_session on 2026-09-29.
// Both end-of-session checklists (the MCP tool in index.ts, the CLI in cli.ts) ran `git status` in a
// try block whose catch said "not a git repo": a repository git could not read was listed neither
// clean nor dirty, and the summary said ALL CLEAR over it (E2E_REVIEW_2026-09 C6-5). git prints the
// same "not a git repository" for an unreadable .git as for a plain folder, so, like the session
// gate, this looks for the .git entry itself before calling a folder plain.
import { execFileSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

export type RepoStatus =
  | { state: "clean"; root: string }
  | { state: "dirty"; root: string; files: string[] }
  | { state: "not_git" }
  | { state: "failed"; error: string };

function firstLine(err: unknown): string {
  const e = err as NodeJS.ErrnoException & { stderr?: string | Buffer };
  if (e.code === "ENOENT") return "git could not start (ENOENT: git not installed, or the folder is gone)";
  const stderr = e.stderr ? String(e.stderr).trim().split("\n")[0] : "";
  return stderr || (e.code ? String(e.code) : "") || e.message || "git failed";
}

/** Hardcoded argv, no shell; the only variable part is the folder. */
function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/** The git status of the repository holding `path`: clean, dirty, a plain folder, or a failure named. */
export function repoStatus(path: string): RepoStatus {
  let root: string;
  try {
    root = git(path, ["rev-parse", "--show-toplevel"]);
  } catch (err) {
    const error = firstLine(err);
    if (/not a git repository/i.test(error) && !existsSync(join(path, ".git"))) return { state: "not_git" };
    return { state: "failed", error };
  }
  try {
    const out = git(root, ["status", "--porcelain"]);
    return out ? { state: "dirty", root, files: out.split("\n") } : { state: "clean", root };
  } catch (err) {
    return { state: "failed", error: firstLine(err) };
  }
}
