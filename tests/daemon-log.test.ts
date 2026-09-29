// [LOCK] [DAEMON-LOG-TRIMS-ITSELF] (src/daemon-log.ts). E2E_REVIEW_2026-09 C5-1: the launchd agent's
// log was 267 MB and had never been trimmed. The trim keeps the tail as a copy and truncates the open
// file in place, and only when standard error really is that file.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { closeSync, existsSync, fstatSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { trimDaemonLog } from "../src/daemon-log.js";

let dir: string;
const fds: number[] = [];
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ce-daemon-log-")); });
afterEach(() => { for (const fd of fds.splice(0)) { try { closeSync(fd); } catch { /* closed */ } } rmSync(dir, { recursive: true, force: true }); });

/** A log opened the way launchd opens StandardErrorPath: for append. */
function openLog(name = "mcp-stderr.log"): { fd: number; path: string } {
  const path = join(dir, name);
  const fd = openSync(path, "a");
  fds.push(fd);
  return { fd, path };
}
const line = (i: number) => `[ContextEngine] line ${String(i).padStart(6, "0")}\n`;

describe("trimDaemonLog", () => {
  it("keeps the tail from a line boundary as .1.log, truncates the open file, and the next write lands at the start", () => {
    const { fd, path } = openLog();
    for (let i = 0; i < 300; i++) writeSync(fd, line(i)); // 300 lines of 31 bytes
    const size = statSync(path).size;
    const r = trimDaemonLog(fd, path, { maxBytes: 4096, keepBytes: 1000 });
    expect(r.trimmed).toBe(true);
    expect(r.bytes).toBe(size);
    const kept = readFileSync(join(dir, "mcp-stderr.1.log"), "utf8");
    expect(kept.startsWith("[ContextEngine] line ")).toBe(true); // a whole line, not a cut one
    expect(kept.endsWith(line(299))).toBe(true);
    expect(kept.length).toBeLessThanOrEqual(1000);
    expect(r.kept).toBe(kept.length);
    expect(statSync(path).size).toBe(0);
    writeSync(fd, "after the trim\n");
    expect(readFileSync(path, "utf8")).toBe("after the trim\n");
    expect(fstatSync(fd).size).toBe("after the trim\n".length);
  });

  it("does nothing below the limit", () => {
    const { fd, path } = openLog();
    writeSync(fd, line(1));
    const r = trimDaemonLog(fd, path, { maxBytes: 4096, keepBytes: 1000 });
    expect(r.trimmed).toBe(false);
    expect(r.reason).toBeUndefined();
    expect(statSync(path).size).toBe(line(1).length);
    expect(existsSync(join(dir, "mcp-stderr.1.log"))).toBe(false);
  });

  it("refuses when the descriptor is not open on the log named, and never throws", () => {
    const { fd, path } = openLog();
    const other = openLog("other.log");
    for (let i = 0; i < 300; i++) writeSync(other.fd, line(i));
    const r = trimDaemonLog(fd, other.path, { maxBytes: 4096, keepBytes: 1000 });
    expect(r.trimmed).toBe(false);
    expect(r.reason).toMatch(/not the daemon log/);
    expect(statSync(other.path).size).toBe(300 * line(0).length);
    const missing = trimDaemonLog(fd, join(dir, "absent.log"), { maxBytes: 1, keepBytes: 1 });
    expect(missing.trimmed).toBe(false);
    expect(missing.reason).toMatch(/ENOENT/);
    void path;
  });
});
