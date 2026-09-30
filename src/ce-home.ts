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

// [LOCKED] [SESSIONS-FOLLOW-THE-CE-HOME] - 2026-09-30
// [NEVER] build the sessions folder from homedir(), or fix it once when a module loads.
// WHY: src/sessions.ts fixed ~/.contextengine/sessions from the login home at import, while the
//      session gate read CONTEXTENGINE_HOME at every call. With a CE home set (the tests, every
//      isolated probe of the E2E review), save_session wrote into the owner's real folder and the
//      gate looked in another one: a command-line replay in a scratch home listed the real sessions
//      (E2E_REVIEW_2026-09 batches 2 and 3, C1-2). Nothing on the owner's Mac sets
//      CONTEXTENGINE_HOME, so daily use never showed it.
// FIX: one function, read at every call, used by the store (src/sessions.ts) and the gate
//      (src/session-gate.ts).
export function sessionsDir(): string {
  return join(ceHome(), "sessions");
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
