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

// [LOCK] [HOOK-TOLERATES-EVERY-RESULT-SHAPE]. E2E_REVIEW_2026-09 C1-3: an MCP result is a list of
// content blocks; `.tool_response.is_error` on a list is a jq error, the script exited 0 with nothing
// sent, and no MCP tool call reached the audit log in 24 days of use.
describe("the hook records a tool call whatever shape its result has", () => {
  it("an MCP result, a list of content blocks, is recorded without an error field", () => {
    const r = fire("PostToolUse", {
      tool_name: "mcp__contextengine__list_sessions", tool_input: {},
      tool_response: [{ type: "text", text: "3 sessions" }], session_id: "s1", cwd: "/tmp/x",
    });
    expect(r.stdin).toContain('"tool":"mcp__contextengine__list_sessions"');
    expect(r.stdin).not.toContain('"error"');
  });

  it("a plain string result is recorded", () => {
    const r = fire("PostToolUse", { tool_name: "mcp__x__y", tool_input: { q: 1 }, tool_response: "plain text", session_id: "s1", cwd: "/tmp/x" });
    expect(r.stdin).toContain('"tool":"mcp__x__y"');
    expect(r.stdin).toContain('"args_preview":"{\\"q\\":1}"');
  });

  it("an object result that reports an error carries the error text", () => {
    const r = fire("PostToolUse", {
      tool_name: "mcp__x__y", tool_input: {},
      tool_response: { is_error: true, content: [{ type: "text", text: "boom" }] }, session_id: "s1", cwd: "/tmp/x",
    });
    expect(r.stdin).toContain('"error":"');
    expect(r.stdin).toContain("boom");
  });

  it("an Edit whose result names an error carries it, a Bash result stays as before", () => {
    const edit = fire("PostToolUse", { tool_name: "Edit", tool_input: { file_path: "/f" }, tool_response: { error: "old_string not found" }, session_id: "s1", cwd: "/tmp/x" });
    expect(edit.stdin).toContain('"error":"old_string not found"');
    const bash = fire("PostToolUse", { tool_name: "Bash", tool_input: { command: "ls" }, tool_response: { stdout: "a", stderr: "", interrupted: false }, session_id: "s1", cwd: "/tmp/x" });
    expect(bash.stdin).toContain('"tool":"Bash"');
    expect(bash.stdin).toContain('"args_preview":"ls"');
    expect(bash.stdin).not.toContain('"error"');
  });

  it("a string tool_input and a null result still yield a record", () => {
    const r = fire("PostToolUse", { tool_name: "X", tool_input: "a string input", tool_response: null, session_id: "s1", cwd: "/tmp/x" });
    expect(r.stdin).toContain('"tool":"X"');
    expect(r.stdin).toContain('"args_preview":"a string input"');
  });
});

// [LOCK] [DOUBLED-IS-THE-SAME-INPUT-TWICE] (src/fleet-health.ts). E2E_REVIEW_2026-09 C6-6: 28 "doubled"
// hook events were 28 distinct Edits on one file; the record kept only the file path, so they looked
// identical. The size of the whole tool input tells two edits apart, and keeps no content.
describe("two different Edits on one file are two different records", () => {
  it("the record carries the size of the tool input", () => {
    const a = fire("PostToolUse", { tool_name: "Edit", tool_input: { file_path: "/f", old_string: "a", new_string: "b" }, tool_response: {}, session_id: "s1", cwd: "/x" });
    const b = fire("PostToolUse", { tool_name: "Edit", tool_input: { file_path: "/f", old_string: "a much longer text", new_string: "b" }, tool_response: {}, session_id: "s1", cwd: "/x" });
    const chars = (s: string) => Number(/"input_chars":(\d+)/.exec(s)?.[1] ?? -1);
    expect(chars(a.stdin)).toBeGreaterThan(0);
    expect(chars(b.stdin)).toBeGreaterThan(chars(a.stdin));
    expect(a.stdin).not.toContain("old_string");
  });
});
