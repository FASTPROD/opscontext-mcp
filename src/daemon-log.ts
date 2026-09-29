/**
 * The launchd agent's own log, ~/.contextengine/logs/mcp-stderr.log: launchd opens it for append
 * as the agent's standard error and never rotates it.
 *
 * [LOCKED] [DAEMON-LOG-TRIMS-ITSELF] - 2026-09-29
 * [NEVER] truncate a file that is not the one standard error is open on (inode and device must
 *         match), and [NEVER] let a failed trim stop the daemon.
 * WHY: launchd never rotates StandardErrorPath. On 2026-09-29 the daemon log was 266.8 MB and
 *      2,179,921 lines, 95 % of them one line repeated for 880 files at every index build
 *      (E2E_REVIEW_2026-09 C5-1); nothing had ever trimmed it, and nobody could read it.
 * FIX: at daemon start, when the file is above 50 MB, its last 5 MB (from a line boundary) are
 *      kept as mcp-stderr.1.log and the open file is truncated in place: launchd opens it for
 *      append, so the next write lands at the new end without reopening anything. A chat server
 *      has a pipe on stderr and is left alone; the per-source "Indexed:" line that filled the file
 *      is gone from ingestSources() as well.
 */
import { closeSync, fstatSync, ftruncateSync, openSync, readSync, renameSync, statSync, writeFileSync } from "fs";
import { join } from "path";
import { ceHome } from "./ce-home.js";

export interface TrimLimits {
  /** Above this many bytes the log is trimmed. */
  maxBytes: number;
  /** How many of its last bytes are kept in the `.1.log` copy. */
  keepBytes: number;
}

export interface TrimResult {
  trimmed: boolean;
  /** Size of the log when it was looked at. */
  bytes: number;
  /** Bytes kept in the copy. */
  kept?: number;
  keptTo?: string;
  /** Why nothing was trimmed. */
  reason?: string;
}

export const DAEMON_LOG_LIMITS: TrimLimits = { maxBytes: 50 * 1024 * 1024, keepBytes: 5 * 1024 * 1024 };

export function daemonLogPath(): string {
  return join(ceHome(), "logs", "mcp-stderr.log");
}

/**
 * Keep the last `keepBytes` of the log as `<name>.1.log` and truncate the log in place, when it is
 * above `maxBytes` and `fd` (standard error by default) is open on that very file. Never throws.
 */
export function trimDaemonLog(fd = 2, path = daemonLogPath(), limits: TrimLimits = DAEMON_LOG_LIMITS): TrimResult {
  try {
    const own = fstatSync(fd);
    if (!own.isFile()) return { trimmed: false, bytes: 0, reason: "standard error is not a file" };
    const st = statSync(path);
    if (st.ino !== own.ino || st.dev !== own.dev) return { trimmed: false, bytes: st.size, reason: "standard error is not the daemon log" };
    if (st.size <= limits.maxBytes) return { trimmed: false, bytes: st.size };

    const keep = Math.min(limits.keepBytes, st.size);
    const buf = Buffer.allocUnsafe(keep);
    const rfd = openSync(path, "r");
    let got = 0;
    try {
      got = readSync(rfd, buf, 0, keep, st.size - keep);
    } finally {
      closeSync(rfd);
    }
    const nl = buf.indexOf(10);
    const tail = nl >= 0 && nl < got - 1 ? buf.subarray(nl + 1, got) : buf.subarray(0, got);
    const keptTo = path.replace(/\.log$/, "") + ".1.log";
    const tmp = `${keptTo}.tmp-${process.pid}`;
    writeFileSync(tmp, tail);
    renameSync(tmp, keptTo);
    ftruncateSync(fd, 0);
    return { trimmed: true, bytes: st.size, kept: tail.length, keptTo };
  } catch (e) {
    return { trimmed: false, bytes: 0, reason: e instanceof Error ? e.message : String(e) };
  }
}
