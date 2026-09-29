// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at the autostart status. E2E_REVIEW_2026-09 C6-5: portIsOurs()
// said "not listening" when lsof itself was missing, and the installer then waited 30 s to report a
// server that "didn't bind" without ever having been able to look.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

describe("autostart-status without lsof", () => {
  it.skipIf(process.platform !== "darwin")("says the port state is unknown, not 'not listening'", () => {
    // PATH with only /bin: launchctl is there, lsof (/usr/sbin) is not.
    const run = spawnSync(process.execPath, [join(process.cwd(), "dist", "cli.js"), "autostart-status"], {
      encoding: "utf8",
      env: { ...process.env, PATH: "/bin" },
    });
    expect(run.stdout).toMatch(/port 7842:\s+.*unknown \(lsof is not available here\)/);
    expect(run.stdout).not.toMatch(/not listening/);
  });
});
