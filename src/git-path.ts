// [LOCKED] [THE-TOOL-CALLS-A-GIT-THAT-STARTS] - 2026-10-13
// [NEVER] trust that the first git on the PATH this process was given can start; [NEVER] write a
//         PATH for the background agent that lists /usr/local/bin ahead of /opt/homebrew/bin;
//         [NEVER] add a setting that names the git to use.
// WHY: 2026-10-07, macOS 27.0.1 removed the translator for Intel programs overnight. The owner's
//      Mac held an Intel-only git of 2022 in /usr/local/bin, and the PATH this tool writes for its
//      own background agent (install-autostart) listed that folder first and /opt/homebrew/bin
//      not at all. Measured with a stand-in that cannot start, under Node 24: with or without a
//      shell, Node stops at the first git on PATH ("Unknown system error -86", "Bad CPU type in
//      executable"), where zsh would have passed over it. So the day that translator goes for
//      good, every git call of the agent fails at once: the repository collectors, the status of
//      the workspaces, the SealHour code fingerprint. The fleet's git hooks were fixed for the
//      same cause on 2026-10-07 (LOCK [HOOK-GIT-MUST-START], hooks/pre-commit).
// FIX: at the start of the server the first git on PATH is asked for its version. It answers:
//      nothing changes, at the cost of one short process. It does not: the other gits on PATH,
//      then /opt/homebrew/bin, /usr/local/bin and /usr/bin are tried, and the folder of the first
//      one that answers (its own program folder, `git --exec-path`) goes first on this process's
//      PATH, which every child inherits: the hourly SealHour job, the daily chain check. None
//      answers: PATH is left as it is, fleet health says so, and each git call fails in its own
//      words as before. The agent's own PATH now lists /opt/homebrew/bin, and first.
import { spawnSync } from "child_process";
import { accessSync, constants, statSync } from "fs";
import { delimiter, dirname, join } from "path";

/** Where a git usually lives on a Mac or a Linux box, tried after PATH: the one built for this Mac first. */
const USUAL_GITS = ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"];

export interface GitChoice {
  /** PATH was changed: `git` now names a git that starts. */
  changed: boolean;
  /** The git in use, or null when none starts (or on Windows, where nothing is looked at). */
  git: string | null;
  /** One line for the log when something was found or done; null when all was well. */
  note: string | null;
}

let problem: string | null = null;
/** Set when the last look found no git that starts: fleet health carries it as a warning. */
export const gitProblem = (): string | null => problem;

function isProgram(file: string): boolean {
  try {
    if (!statSync(file).isFile()) return false;
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Does this git start? Its version is asked and nothing else. A program that cannot start, that
 *  refuses or that hangs is a no. Hardcoded arguments, no shell. */
export function gitStarts(git: string): boolean {
  const r = spawnSync(git, ["--version"], { stdio: "ignore", timeout: 5000 });
  return !r.error && r.status === 0;
}

/** Why it does not, in the system's or the program's own words, on one line. */
function whyNot(git: string): string {
  const r = spawnSync(git, ["--version"], { encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
  if (r.error) {
    const e = r.error as NodeJS.ErrnoException;
    // macOS answers -86 (EBADARCH) for a program built for another processor; Node has no name for it.
    if (e.errno === -86) return "Bad CPU type in executable: built for a processor this machine does not run";
    return (e.code ? `${e.code}: ` : "") + e.message.split("\n")[0].slice(0, 120);
  }
  const said = `${r.stderr ?? ""}${r.stdout ?? ""}`.trim().split("\n")[0] ?? "";
  return (said || `exit ${r.status}`).slice(0, 160);
}

/** The folder of a git's own programs when it holds a git that starts, else the folder the git is in. */
function folderOf(git: string, starts: (g: string) => boolean): string {
  const r = spawnSync(git, ["--exec-path"], { encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] });
  const own = r.error || r.status !== 0 ? "" : String(r.stdout).trim();
  return own && isProgram(join(own, "git")) && starts(join(own, "git")) ? own : dirname(git);
}

/**
 * Make sure `git`, called by name from this process and its children, is a git that starts.
 * Changes `env.PATH` only when the first git on it does not. [LOCK] [THE-TOOL-CALLS-A-GIT-THAT-STARTS]
 */
export function ensureGitStarts(
  env: NodeJS.ProcessEnv = process.env,
  opts: { usual?: string[]; starts?: (git: string) => boolean } = {},
): GitChoice {
  if (process.platform === "win32") return { changed: false, git: null, note: null };
  const starts = opts.starts ?? gitStarts;
  const onPath = (env.PATH ?? "").split(delimiter).filter(Boolean).map((dir) => join(dir, "git")).filter(isProgram);
  const first = onPath[0] ?? null;
  if (first && starts(first)) {
    if (env === process.env) problem = null;
    return { changed: false, git: first, note: null };
  }
  const why = first ? `${first} cannot start on this machine (${whyNot(first)})` : "no git on PATH";
  for (const git of new Set([...onPath.slice(1), ...(opts.usual ?? USUAL_GITS)])) {
    if (git === first || !isProgram(git) || !starts(git)) continue;
    env.PATH = `${folderOf(git, starts)}${delimiter}${env.PATH ?? ""}`;
    if (env === process.env) problem = null;
    return { changed: true, git, note: `git: ${why}; using ${git}` };
  }
  // Without any git on PATH and none in the usual places, git is simply not installed: nothing to say.
  const note = first ? `git: ${why}, and no other git was found: every git call will fail until one is installed` : null;
  if (env === process.env) problem = note;
  return { changed: false, git: null, note };
}
