// [LOCK] [HEALTH-SEES-THE-CHAIN]: every full check leaves its result; the scheduled one runs one at a time.
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

const CLI = join(process.cwd(), "dist", "cli.js");

function sandbox(): { home: string; ce: string; run: (args: string[]) => { code: number; out: string } } {
  const home = mkdtempSync(join(tmpdir(), "ce-chain-health-"));
  const ce = join(home, ".contextengine");
  mkdirSync(ce, { recursive: true });
  const env = { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, CONTEXTENGINE_HOME: ce };
  const run = (args: string[]) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [CLI, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
    } catch (e: any) {
      return { code: e.status as number, out: String(e.stdout) + String(e.stderr) };
    }
  };
  return { home, ce, run };
}

describe("audit-verify records its result", () => {
  it("by hand: the verdict and the counts land in audit-verify.json", () => {
    const s = sandbox();
    s.run(["emit-event", "vscode.tool_call", '{"tool":"Edit"}']);
    s.run(["emit-event", "vscode.tool_call", '{"tool":"Bash"}']);
    const r = s.run(["audit-verify"]);
    expect(r.code).toBe(0);
    const st = JSON.parse(readFileSync(join(s.ce, "audit-verify.json"), "utf8"));
    expect(st).toMatchObject({ by: "cli", ok: true, total: 2, unique: 2, altered: 0, orphans: 0 });
    rmSync(s.home, { recursive: true, force: true });
  });

  it("scheduled: prints nothing, records, and steps aside while another check holds the lock", () => {
    const s = sandbox();
    s.run(["emit-event", "vscode.tool_call", '{"tool":"Edit"}']);
    writeFileSync(join(s.ce, "audit-verify.lock"), `${process.pid}\n`); // a live holder
    expect(s.run(["audit-verify", "--scheduled"])).toEqual({ code: 0, out: "" });
    expect(existsSync(join(s.ce, "audit-verify.json"))).toBe(false);
    rmSync(join(s.ce, "audit-verify.lock"));
    expect(s.run(["audit-verify", "--scheduled"])).toEqual({ code: 0, out: "" });
    expect(JSON.parse(readFileSync(join(s.ce, "audit-verify.json"), "utf8"))).toMatchObject({ by: "scheduled", ok: true, total: 1 });
    expect(existsSync(join(s.ce, "audit-verify.lock"))).toBe(false);
    rmSync(s.home, { recursive: true, force: true });
  });
});
