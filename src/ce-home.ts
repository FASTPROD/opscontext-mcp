// [LOCKED] [CE-HOME-IS-PRIVATE] - 2026-09-25
// [NEVER] leave ~/.contextengine (or CONTEXTENGINE_HOME) readable by other accounts, and never
//         chmod a folder this user does not own.
// WHY: every file in it was created with the default modes: the folder 0755, and audit.log with
//      its 59 archived segments, learnings.json and 20 backups, sessions, the shared index (which
//      holds dotenv, shell history and crontab chunks), license.json and the daemon log all 0644.
//      Only extension-secret and keys/ were private. On a Mac whose home folder is 0755, or a
//      shared Linux box, any other account could read the lot (E2E_REVIEW_2026-09 A7-1, A4-3).
// FIX: both entry points (the MCP server's main() and the CLI's dispatcher) call secureCeHome()
//      first: the folder is created 0700, or set to 0700 when it has any group or other bit. A
//      private folder shields every file inside, whatever its own mode, so no writer has to
//      remember a mode. A folder owned by someone else is left alone.
import { chmodSync, existsSync, mkdirSync, statSync } from "fs";
import { join } from "path";
import { homedir } from "os";

export function ceHome(): string {
  return process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine");
}

/** Makes `dir` private to this user (0700), creating it if needed. Never throws. */
export function securePrivateDir(dir: string, create: boolean): void {
  try {
    if (!existsSync(dir)) {
      if (!create) return;
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const st = statSync(dir);
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return;
    if ((st.mode & 0o077) !== 0) chmodSync(dir, 0o700);
  } catch {
    /* permissions are hardening, never a reason to stop */
  }
}

/** The CE home (created if missing) and, when CONTEXTENGINE_HOME points elsewhere, the default one
 *  if it exists: the receiver's secret always lives in ~/.contextengine. */
export function secureCeHome(): void {
  securePrivateDir(ceHome(), true);
  const fallback = join(homedir(), ".contextengine");
  if (fallback !== ceHome()) securePrivateDir(fallback, false);
}
