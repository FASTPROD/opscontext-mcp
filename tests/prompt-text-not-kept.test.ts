import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { prepareCapturedPayload } from "../src/http-server.js";
import { runHeuristics } from "../src/detector.js";
import type { AuditRecord } from "../src/audit.js";

let home: string;
let saved: { home?: string; keep?: string };
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-prompt-text-"));
  saved = { home: process.env.CONTEXTENGINE_HOME, keep: process.env.OPSCONTEXT_KEEP_PROMPT_TEXT };
  process.env.CONTEXTENGINE_HOME = home;
  delete process.env.OPSCONTEXT_KEEP_PROMPT_TEXT;
});
afterEach(() => {
  if (saved.home === undefined) delete process.env.CONTEXTENGINE_HOME; else process.env.CONTEXTENGINE_HOME = saved.home;
  if (saved.keep === undefined) delete process.env.OPSCONTEXT_KEEP_PROMPT_TEXT; else process.env.OPSCONTEXT_KEEP_PROMPT_TEXT = saved.keep;
  rmSync(home, { recursive: true, force: true });
});

// [LOCK] [PROMPT-TEXT-IS-NOT-KEPT]
describe("prompt text is not kept", () => {
  it("a prompt keeps its length and a fingerprint, never its words", () => {
    const out = prepareCapturedPayload({ surface: "claude-code", text: "check the invoice totals", char_count: 24, session: "s1" }, "vscode.prompt_submit");
    expect(out.text).toBeUndefined();
    expect(JSON.stringify(out)).not.toContain("invoice");
    expect(out.char_count).toBe(24);
    expect(out.text_fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(out.session).toBe("s1");
  });

  it("the same words give the same fingerprint, other words another", () => {
    const fp = (t: string) => prepareCapturedPayload({ text: t }, "browser.prompt").text_fingerprint;
    expect(fp("go on")).toBe(fp("go on"));
    expect(fp("go on")).not.toBe(fp("go on please"));
  });

  it("the fingerprint key stays on the machine, readable by its owner only", () => {
    prepareCapturedPayload({ text: "x" }, "vscode.prompt_submit");
    expect(statSync(join(home, "keys", "fingerprint.key")).mode & 0o777).toBe(0o600);
  });

  it("commands keep their text, redacted: they are the record of what an agent did", () => {
    const out = prepareCapturedPayload({ tool: "Bash", args_preview: "ls /var/www" }, "vscode.tool_call");
    expect(out.args_preview).toBe("ls /var/www");
  });

  it("OPSCONTEXT_KEEP_PROMPT_TEXT=1 keeps the redacted text", () => {
    process.env.OPSCONTEXT_KEEP_PROMPT_TEXT = "1";
    expect(prepareCapturedPayload({ text: "list files" }, "vscode.prompt_submit").text).toBe("list files");
  });
});

describe("the detectors on fingerprint-only prompts", () => {
  const at = (s: number) => new Date(Date.UTC(2026, 8, 25, 10, 0, s)).toISOString();
  const prompt = (text: string, s: number): AuditRecord => ({
    ts: at(s), event: "vscode.prompt_submit", actor: "claude-code",
    payload: prepareCapturedPayload({ surface: "claude-code", text, session: "s1" }, "vscode.prompt_submit"),
    prev_hash: "", hash: "",
  });

  it("still flag a prompt repeated word for word", () => {
    const events = [prompt("fix the login", 0), prompt("fix the login", 30), prompt("fix the login", 60)];
    const kinds = runHeuristics(events, { now: Date.parse(at(90)) }).map((s) => s.kind);
    expect(kinds).toContain("loop");
  });

  it("do not call every session drifted for lack of words", () => {
    const events = ["a", "b", "c", "d", "e"].map((t, i) => prompt(`topic ${t} ${i}`, i * 60));
    const kinds = runHeuristics(events, { now: Date.parse(at(400)) }).map((s) => s.kind);
    expect(kinds).not.toContain("drift");
    expect(kinds).not.toContain("loop");
  });
});
