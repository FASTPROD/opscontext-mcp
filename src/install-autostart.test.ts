// [LOCK] [AUTOSTART-IS-THE-STANDING-INDEXER]: the launchd agent runs at Standard priority with
// the shared-index flag and the same corpus inputs as the chats. Throwaway HOME via test-setup.
import { describe, it, expect, beforeAll } from "vitest";

let A: typeof import("./install-autostart.js");
beforeAll(async () => { A = await import("./install-autostart.js"); });

describe("buildPlist", () => {
  it("runs the agent at Standard priority with the shared-index flag, and never as Background", () => {
    const p = A.buildPlist("/usr/local/bin/node", "/x/dist/index.js", "/usr/local/bin", {});
    expect(p).toMatch(/<key>ProcessType<\/key>\s*<string>Standard<\/string>/);
    expect(p).not.toMatch(/Background/);
    expect(p).toMatch(/<key>CONTEXTENGINE_SHARED_INDEX<\/key>\s*<string>1<\/string>/);
    expect(p).toMatch(/<key>OPSCONTEXT_DAEMON<\/key>\s*<string>1<\/string>/);
    expect(p).not.toMatch(/OPSCONTEXT_SKIP_CLAUDE_MEMORY/);
  });
  it("passes the installing shell's corpus inputs through, so its corpus id equals the chats'", () => {
    const p = A.buildPlist("/n", "/e", "/b", { CONTEXTENGINE_CONFIG: "/Users/me/Projects/CE/contextengine.json", CONTEXTENGINE_WORKSPACES: "/a:/b", OPSCONTEXT_SKIP_CLAUDE_MEMORY: "1" });
    expect(p).toMatch(/<key>CONTEXTENGINE_CONFIG<\/key>\s*<string>\/Users\/me\/Projects\/CE\/contextengine\.json<\/string>/);
    expect(p).toMatch(/<key>CONTEXTENGINE_WORKSPACES<\/key>\s*<string>\/a:\/b<\/string>/);
    expect(p).toMatch(/<key>OPSCONTEXT_SKIP_CLAUDE_MEMORY<\/key>\s*<string>1<\/string>/);
  });
  it("escapes XML in a path", () => {
    const p = A.buildPlist("/n", "/e", "/b", { CONTEXTENGINE_WORKSPACES: "/a&b/<c>" });
    expect(p).toContain("/a&amp;b/&lt;c>");
  });
  // [LOCK] [AUTOSTART-ARGV-AND-XML-ESCAPED]: E2E_REVIEW_2026-09 A3-3, a home named "R&D home".
  it("escapes every value, the home folder, node and entry paths included, and launchd can read it", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { spawnSync } = await import("node:child_process");
    const saved = process.env.HOME;
    process.env.HOME = "/Users/R&D home";
    try {
      const p = A.buildPlist("/opt/n&n/node", "/x/<dist>/index.js", "/opt/n&n", {});
      expect(p).not.toMatch(/&(?!amp;|lt;)/);
      expect(p).toContain("<string>/Users/R&amp;D home</string>");
      if (process.platform === "darwin") {
        const f = join(mkdtempSync(join(tmpdir(), "ce-plist-")), "t.plist");
        writeFileSync(f, p);
        expect(spawnSync("/usr/bin/plutil", ["-lint", f]).status).toBe(0);
      }
    } finally {
      process.env.HOME = saved;
    }
  });
});
