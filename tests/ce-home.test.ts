// [LOCK] [CE-HOME-IS-PRIVATE]: E2E_REVIEW_2026-09 A7-1. Throwaway folders only.
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, statSync, existsSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { securePrivateDir } from "../src/ce-home.js";

const mode = (p: string) => statSync(p).mode & 0o777;

describe("securePrivateDir", () => {
  it("makes an open folder private and creates a missing one private", () => {
    const root = mkdtempSync(join(tmpdir(), "ce-home-"));
    const open = join(root, "open");
    mkdirSync(open);
    chmodSync(open, 0o755);
    securePrivateDir(open, true);
    expect(mode(open)).toBe(0o700);
    const fresh = join(root, "a", "fresh");
    securePrivateDir(fresh, true);
    expect(mode(fresh)).toBe(0o700);
    securePrivateDir(join(root, "absent"), false);
    expect(existsSync(join(root, "absent"))).toBe(false);
  });
});

describe("the built CLI", () => {
  const run = (home: string, args: string[]) =>
    execFileSync(process.execPath, [join(process.cwd(), "dist", "cli.js"), ...args], {
      env: { HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, TMPDIR: tmpdir() },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    });

  it("turns an existing 0755 ~/.contextengine private, files inside and all", () => {
    const home = mkdtempSync(join(tmpdir(), "ce-home-cli-"));
    const ce = join(home, ".contextengine");
    mkdirSync(ce, { mode: 0o755 });
    chmodSync(ce, 0o755);
    writeFileSync(join(ce, "audit.log"), "", { mode: 0o644 });
    run(home, ["servers"]);
    expect(mode(ce)).toBe(0o700);
  });

  it("creates a missing ~/.contextengine private, and leaves none for --version", () => {
    const home = mkdtempSync(join(tmpdir(), "ce-home-cli-"));
    run(home, ["--version"]);
    expect(existsSync(join(home, ".contextengine"))).toBe(false);
    run(home, ["servers"]);
    expect(mode(join(home, ".contextengine"))).toBe(0o700);
  });
});
