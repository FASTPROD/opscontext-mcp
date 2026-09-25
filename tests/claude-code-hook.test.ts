import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, chmodSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execFileSync } from "child_process";
import { buildHashOf } from "../src/server-registry.js";

const HOOK = join(process.cwd(), "defaults", "claude-code-hook.sh");

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ce-hook-test-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Fire the real bundled hook under bash, with a stand-in curl that records what it was given. */
function fire(kind: string, input: object) {
  const home = join(dir, "home");
  mkdirSync(join(home, ".contextengine"), { recursive: true });
  const shared = "t3st-shared-" + "0123456789abcdef";
  writeFileSync(join(home, ".contextengine", "extension-secret"), shared + "\n");
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(
    join(bin, "curl"),
    [
      "#!/usr/bin/env bash",
      'printf "%s\\n" "$@" > "$FAKE_OUT.argv"',
      'for a in "$@"; do case "$a" in @/dev/fd/*|@/proc/*) cat "${a#@}" > "$FAKE_OUT.header" ;; esac; done',
      'cat > "$FAKE_OUT.stdin"',
      "",
    ].join("\n"),
  );
  chmodSync(join(bin, "curl"), 0o755);
  const out = join(dir, "out");
  execFileSync("bash", [HOOK, kind], {
    input: JSON.stringify(input),
    env: { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}`, FAKE_OUT: out },
  });
  const read = (s: string) => (existsSync(out + s) ? readFileSync(out + s, "utf-8") : "");
  return { shared, argv: read(".argv"), stdin: read(".stdin"), header: read(".header") };
}

// [LOCK] [HOOK-KEEPS-PROMPT-AND-SECRET-OFF-ARGV]
describe("the Claude Code hook keeps the prompt and the shared secret off the command line", () => {
  it("prompt: body on standard input, secret in a header file, neither in curl's arguments", () => {
    const prompt = "please check the invoice totals 4711";
    const r = fire("UserPromptSubmit", { prompt, session_id: "s1", cwd: "/tmp/x" });
    expect(r.argv).not.toContain(prompt);
    expect(r.argv).not.toContain(r.shared);
    expect(r.argv).toContain("--data-binary");
    expect(r.stdin).toContain('"events":[');
    expect(r.stdin).toContain(prompt);
    expect(r.header.trim()).toBe(`X-OpsContext-Secret: ${r.shared}`);
  });

  it("tool call: the command preview travels in the body only", () => {
    const command = "ls -la /var/www/app_crowlr";
    const r = fire("PostToolUse", { tool_name: "Bash", tool_input: { command }, session_id: "s1", cwd: "/tmp/x" });
    expect(r.argv).not.toContain(command);
    expect(r.stdin).toContain(command);
  });
});

// [LOCK] [BUILD-HASH-COVERS-EVERY-MODULE]
describe("buildHashOf", () => {
  it("changes when any module next to the entry changes, not only the entry", () => {
    const dist = join(dir, "dist");
    mkdirSync(dist);
    writeFileSync(join(dist, "index.js"), "import './audit.js';\n");
    writeFileSync(join(dist, "audit.js"), "export const v = 1;\n");
    const before = buildHashOf(join(dist, "index.js"));
    expect(buildHashOf(join(dist, "index.js"))).toBe(before);
    writeFileSync(join(dist, "audit.js"), "export const v = 2;\n");
    expect(buildHashOf(join(dist, "index.js"))).not.toBe(before);
  });
});
