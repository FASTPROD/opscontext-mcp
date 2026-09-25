import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, readdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  appendAudit,
  verifyChain,
  rotateAuditLog,
  scrubAuditLog,
  acknowledgeRedaction,
  readAuditLog,
  listSegments,
  resetCacheForTest,
} from "../src/audit.js";
import { redactPayload } from "../src/secret-shapes.js";

let tempHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(join(tmpdir(), "ce-scrub-test-"));
  originalHome = process.env.CONTEXTENGINE_HOME;
  process.env.CONTEXTENGINE_HOME = tempHome;
  resetCacheForTest();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.CONTEXTENGINE_HOME;
  else process.env.CONTEXTENGINE_HOME = originalHome;
  resetCacheForTest();
  rmSync(tempHome, { recursive: true, force: true });
});

// Assembled at run time so the file holds nothing the commit scanner blocks. Not real.
const STRIPE = ["sk", "live", "Q1w2E3r4T5y6U7i8O9p0A1s2"].join("_");
const PW = "Zq7" + "Kx9" + "Wm2" + "Vp4";
const allText = () =>
  [...listSegments().map((f) => join(tempHome, "audit-archive", f)), join(tempHome, "audit.log")]
    .map((p) => readFileSync(p, "utf-8"))
    .join("\n");

/** 2,300 records: capture events carrying the two fake secrets, then a rotation, then more. */
function seedWithSecrets(): void {
  for (let i = 0; i < 2300; i++) {
    if (i === 10) appendAudit("vscode.prompt_submit", { surface: "claude-code", text: `use ${STRIPE} for the test` }, "claude-code");
    else if (i === 20) appendAudit("vscode.tool_call", { surface: "claude-code", tool: "Bash", args_preview: `sshpass -p '${PW}' ssh admin@host.example.test` }, "claude-code");
    else appendAudit("learning.save", { i });
  }
  expect(rotateAuditLog({ maxRecords: 2000 }).rotated).toBe(true); // the first 300 go to a segment
  appendAudit("vscode.tool_call", { surface: "claude-code", tool: "Bash", args_preview: `psql postgresql://fc_user:${PW}@db.example.test/fc_db` }, "claude-code");
  appendAudit("vscode.prompt_submit", { surface: "claude-code", text: "nothing secret here" }, "claude-code");
}

const scrub = (apply: boolean, reason = "test scrub") => scrubAuditLog({ apply, reason, redact: redactPayload });

// [LOCK] [SCRUB-IS-ACKNOWLEDGED-REDACTION]
describe("scrubAuditLog", () => {
  it("a dry run counts what it would redact and writes nothing", () => {
    seedWithSecrets();
    const before = allText();
    const r = scrub(false);
    expect(r.applied).toBe(false);
    expect(r.redactedRecords).toBe(3);
    expect(r.counts).toEqual({ stripe_key: 1, sshpass_password: 1, url_password: 1 });
    expect(allText()).toBe(before);
  });

  it("removes the secrets from the archive and the live log, and the chain still verifies", () => {
    seedWithSecrets();
    expect(allText()).toContain(STRIPE);
    const r = scrub(true);
    expect(r.applied).toBe(true);
    expect(r.redactedRecords).toBe(3);
    const text = allText();
    expect(text).not.toContain(STRIPE);
    expect(text).not.toContain(PW);
    expect(text).toContain("postgresql://fc_user:[REDACTED:url_password]@db.example.test/fc_db");
    const v = verifyChain();
    expect(v.ok).toBe(true);
    expect(v.tamperedIndices).toEqual([]);
    expect(v.redactedIndices).toHaveLength(3);
  });

  it("changes no other line, byte for byte", () => {
    seedWithSecrets();
    const before = allText().trimEnd().split("\n");
    scrub(true);
    // The acknowledgements are appended after the old last line; compare what was there before.
    const after = allText().split("\n").slice(0, before.length);
    const changed = before.filter((line, i) => line !== after[i]);
    expect(changed).toHaveLength(3);
    expect(changed.every((l) => l.includes(STRIPE) || l.includes(PW))).toBe(true);
  });

  it("running it again changes nothing", () => {
    seedWithSecrets();
    scrub(true);
    const again = scrub(true, "second run");
    expect(again.redactedRecords).toBe(0);
    expect(again.acknowledgements).toEqual([]);
    expect(verifyChain().ok).toBe(true);
  });

  it("re-scrubbing a record that was already redacted by hand keeps it acknowledged", () => {
    seedWithSecrets();
    // The 2026-08-20 shape: someone edits one secret by hand, then acknowledges it.
    const seg = join(tempHome, "audit-archive", listSegments()[0]);
    const lines = readFileSync(seg, "utf-8").split("\n");
    const i = lines.findIndex((l) => l.includes("sshpass"));
    const r = JSON.parse(lines[i]);
    r.payload.args_preview = r.payload.args_preview.replace("admin@", "someone@");
    lines[i] = JSON.stringify(r);
    writeFileSync(seg, lines.join("\n"));
    const idx = readAuditLog().findIndex((x) => x.hash === r.hash);
    expect(acknowledgeRedaction([idx], "hand edit").acknowledged).toEqual([idx]);
    expect(verifyChain().ok).toBe(true);
    scrub(true);
    const v = verifyChain();
    expect(v.ok).toBe(true);
    expect(allText()).not.toContain(PW);
  });

  it("requires a reason to apply, and waits for a running rotation", () => {
    seedWithSecrets();
    expect(scrubAuditLog({ apply: true, redact: redactPayload }).refusedReason).toMatch(/reason is required/);
    writeFileSync(join(tempHome, "audit.rotate.lock"), "1\n");
    expect(scrub(true).refusedReason).toMatch(/rotation is in progress/);
    expect(allText()).toContain(STRIPE);
  });

  it("leaves no temporary file behind", () => {
    seedWithSecrets();
    scrub(true);
    const leftovers = [...readdirSync(tempHome), ...readdirSync(join(tempHome, "audit-archive"))].filter((f) => f.includes(".scrub.tmp"));
    expect(leftovers).toEqual([]);
  });
});
