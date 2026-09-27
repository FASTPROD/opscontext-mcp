// [LOCK] [GIT-FAILURE-IS-UNKNOWN-NOT-CLEAN] (src/firewall.ts). E2E_REVIEW_2026-09 B6-2: a repository
// git could not read was reported "Git: ok, clean". Fails on the code before the fix.
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { ProtocolFirewall } from "../src/firewall.js";

function repo(root: string, name: string, dirty: number): string {
  const d = join(root, name);
  mkdirSync(d, { recursive: true });
  const git = (...a: string[]) => execFileSync("git", ["-C", d, ...a], { stdio: "ignore" });
  git("init", "-q");
  git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init");
  for (let i = 0; i < dirty; i++) writeFileSync(join(d, `f${i}.txt`), "x");
  return d;
}

function gitObligation(dirs: Array<{ path: string; name: string }>): { status: string; detail: string } {
  const fw = new ProtocolFirewall({ skipRestore: true });
  fw.setProjectDirs(dirs);
  // evaluate() is private in TypeScript; the class is exercised as the server uses it.
  return (fw as unknown as { evaluate: () => Array<{ id: string; status: string; detail: string }> }).evaluate().find((o) => o.id === "git")!;
}

describe("the firewall's git obligation", () => {
  it("reports a repository git cannot read as unknown, never clean", () => {
    const root = mkdtempSync(join(tmpdir(), "ce-fw-git-"));
    const broken = repo(root, "broken", 8);
    writeFileSync(join(broken, ".git", "index"), "DIRC garbage");
    const o = gitObligation([{ path: broken, name: "broken" }]);
    expect(o.detail).toMatch(/broken\(unknown/);
    expect(o.status).not.toBe("ok");
  });

  it("guard: counts a readable repository's changes and skips a folder that is not a repository", () => {
    const root = mkdtempSync(join(tmpdir(), "ce-fw-git-"));
    const dirty = repo(root, "dirty", 3);
    const plain = join(root, "plain");
    mkdirSync(plain);
    const o = gitObligation([{ path: dirty, name: "dirty" }, { path: plain, name: "plain" }]);
    expect(o.detail).toBe("dirty(3)");
    expect(o.status).toBe("warn");
  });
});
