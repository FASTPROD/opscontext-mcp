// [LOCK] [HOOK-PATHS-ARE-SHELL-QUOTED] [UNINSTALL-REMOVES-ONLY-OUR-COMMANDS] [AUTOSTART-ARGV-AND-XML-ESCAPED]
// E2E_REVIEW_2026-09 A3-1 to A3-5: the installers against a home folder named "John Smith".
// HOME is set before the installer module loads (vitest gives each test file fresh modules), and
// every path lives under a throwaway folder: the real ~/.claude and the real launchd are never used.
import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync, execFileSync } from "node:child_process";

const ROOT = mkdtempSync(join(tmpdir(), "ce-space-home-"));
const HOME = join(ROOT, "John Smith");
mkdirSync(HOME, { recursive: true });
process.env.HOME = HOME;

let I: typeof import("../src/install-claude-hook.js");
const HOOKS = join(HOME, ".claude", "hooks");
const EMIT = join(HOOKS, "opscontext-emit.sh");
const GATE = join(HOOKS, "opscontext-session-gate.sh");
const SETTINGS = join(HOME, ".claude", "settings.json");
const KINDS = ["UserPromptSubmit", "PostToolUse", "SessionStart"];

beforeAll(async () => {
  I = await import("../src/install-claude-hook.js");
});
afterEach(() => vi.restoreAllMocks());

async function quiet<T>(fn: () => Promise<T>): Promise<{ out: string; err: string }> {
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new Error(`exit ${code}`);
  }) as never);
  try {
    await fn();
  } catch (e) {
    error.mock.calls.push([String(e)]);
  }
  return { out: log.mock.calls.flat().join("\n"), err: error.mock.calls.flat().join("\n") };
}
const readSettings = () => JSON.parse(readFileSync(SETTINGS, "utf-8"));
const allCommands = (s: any): string[] => Object.values(s.hooks ?? {}).flat().flatMap((e: any) => e.hooks.map((h: any) => h.command));
const backups = () => readdirSync(join(HOME, ".claude")).filter((f) => f.includes(".bak-pre-opscontext-"));

describe("install-claude-hook with a home folder that has a space", () => {
  it("refuses a malformed settings.json before writing anything", async () => {
    mkdirSync(join(HOME, ".claude"), { recursive: true });
    writeFileSync(SETTINGS, "{ not json");
    const r = await quiet(() => I.cliInstallClaudeHook([]));
    expect(r.err).toMatch(/not valid JSON/);
    expect(readFileSync(SETTINGS, "utf-8")).toBe("{ not json");
    expect(existsSync(EMIT)).toBe(false);
  });

  it("writes quoted commands that the shell runs, verifies one per event, and a re-run changes nothing", async () => {
    writeFileSync(SETTINGS, JSON.stringify({ hooks: {} }));
    const first = await quiet(() => I.cliInstallClaudeHook([]));
    expect(first.err).toBe("");
    expect(first.out).toMatch(/exactly one registration for UserPromptSubmit, PostToolUse, SessionStart, Stop\./);
    for (const c of allCommands(readSettings())) expect(c.startsWith("'")).toBe(true);

    // Run each command the way Claude Code does: through a shell. The emit hook exits 0 (no
    // secret configured here); the gate starts node, so the shell found and ran the script.
    for (const c of allCommands(readSettings())) {
      const x = spawnSync("/bin/sh", ["-c", c], { cwd: ROOT, input: "{}", encoding: "utf8", env: { HOME, PATH: "/usr/bin:/bin" } });
      expect(x.status, `${c}: ${x.stderr}`).not.toBe(127);
      expect(x.status, `${c}: ${x.stderr}`).not.toBe(2);
      if (c.includes("opscontext-emit.sh")) expect(x.status).toBe(0);
    }
    expect(spawnSync("/bin/sh", ["-n", GATE]).status).toBe(0);
    expect(readFileSync(GATE, "utf-8")).toMatch(/^exec '[^']+' '[^']+' session-gate$/m);

    const backupsAfterFirst = backups().length;
    const again = await quiet(() => I.cliInstallClaudeHook([]));
    expect(again.out).toMatch(/0 hook entries added, 4 already present\./);
    expect(I.countOurHooks(readSettings(), KINDS, EMIT)).toEqual({ UserPromptSubmit: 1, PostToolUse: 1, SessionStart: 1 });
    expect(backups().length, "no backup when nothing changes").toBe(backupsAfterFirst);
  });

  it("repairs the unquoted copies an older install wrote, instead of adding more", async () => {
    writeFileSync(
      SETTINGS,
      JSON.stringify({
        hooks: {
          UserPromptSubmit: [{ hooks: [{ type: "command", command: `${EMIT} UserPromptSubmit`, timeout: 5 }] }],
          PostToolUse: [{ matcher: ".*", hooks: [{ type: "command", command: `${EMIT} PostToolUse`, timeout: 5 }] }],
          SessionStart: [{ hooks: [{ type: "command", command: `${EMIT} SessionStart`, timeout: 5 }] }],
          Stop: [{ hooks: [{ type: "command", command: GATE, timeout: 15 }] }],
        },
      }),
    );
    const r = await quiet(() => I.cliInstallClaudeHook([]));
    expect(r.err).toBe("");
    const cmds = allCommands(readSettings());
    expect(cmds).toHaveLength(4);
    expect(cmds.every((c) => c.startsWith("'"))).toBe(true);
  });
});

describe("uninstall-claude-hook", () => {
  it("removes only our commands and keeps a user's hook that shares the entry or the name", async () => {
    writeFileSync(
      SETTINGS,
      JSON.stringify({
        hooks: {
          PostToolUse: [
            { matcher: ".*", hooks: [{ type: "command", command: "/usr/local/bin/company-audit.sh" }, { type: "command", command: `'${EMIT}' PostToolUse` }] },
          ],
          Stop: [{ hooks: [{ type: "command", command: "/usr/local/bin/notify-opscontext-emit.sh.done" }] }, { hooks: [{ type: "command", command: `'${GATE}'` }] }],
        },
      }),
    );
    const r = await quiet(() => I.cliUninstallClaudeHook([]));
    expect(r.out).toMatch(/Removed 2 OpsContext hook command/);
    const cmds = allCommands(readSettings());
    expect(cmds).toEqual(["/usr/local/bin/company-audit.sh", "/usr/local/bin/notify-opscontext-emit.sh.done"]);
    expect(readSettings().hooks.PostToolUse[0].matcher).toBe(".*");
  });
});

describe("install-autostart through the built CLI, with fake launchctl and lsof", () => {
  it.skipIf(process.platform !== "darwin")("hands launchctl the plist path as one argument and writes a valid plist", () => {
    const shims = join(ROOT, "shims");
    mkdirSync(shims, { recursive: true });
    const log = join(ROOT, "argv.log");
    for (const name of ["launchctl", "lsof"]) {
      writeFileSync(join(shims, name), `#!/bin/sh\nprintf '%s' "${name}" >> '${log}'; for a in "$@"; do printf ' <%s>' "$a" >> '${log}'; done; echo >> '${log}'\nexit 0\n`);
      chmodSync(join(shims, name), 0o755);
    }
    const env = { HOME, PATH: `${shims}:${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: join(HOME, ".contextengine"), TMPDIR: ROOT };
    // Guard: the fake launchctl must be the one found, or the test would stop the real agent.
    expect(execFileSync("/bin/sh", ["-c", "command -v launchctl"], { env, encoding: "utf8" }).trim()).toBe(join(shims, "launchctl"));

    const cli = join(process.cwd(), "dist", "cli.js");
    const r = spawnSync(process.execPath, [cli, "install-autostart", "--entry", cli], { cwd: ROOT, env, encoding: "utf8", timeout: 60_000 });
    const plist = join(HOME, "Library", "LaunchAgents", "com.opscontext.mcp.plist");
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(spawnSync("/usr/bin/plutil", ["-lint", plist]).status).toBe(0);
    const calls = readFileSync(log, "utf8");
    expect(calls).toContain(`launchctl <bootstrap> <gui/${process.getuid!()}> <${plist}>`);
  });
});
