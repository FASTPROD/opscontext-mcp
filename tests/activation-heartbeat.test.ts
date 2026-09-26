// [LOCK] [LICENSE-IS-CHECKED-DAILY]: E2E_REVIEW_2026-09 A4-2. Throwaway HOME (src/test-setup.ts),
// a licence signed with a test key installed in-process, and fetch replaced: no network.
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { canonicalPayload, __setLicensePublicKeyForTesting } from "../src/license-sig.js";
import { heartbeat, gateCheck, gateCheckFresh } from "../src/activation.js";

const LICENSE_FILE = join(homedir(), ".contextengine", "license.json");
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const machineId = createHash("sha256")
  .update([process.platform, process.arch, homedir().split("/").slice(0, 3).join("/"), process.env.USER || process.env.USERNAME || "unknown"].join("|"))
  .digest("hex")
  .slice(0, 16);
const DAY = 86_400_000;

function writeLicense(extra: Record<string, unknown> = {}) {
  const base = { key: "CE-TEST-HB", email: "t@example.invalid", plan: "pro", machineId, expiresAt: new Date(Date.now() + 300 * DAY).toISOString(), deltaVersion: "0" };
  const signature = sign(null, Buffer.from(canonicalPayload(base)), privateKey).toString("base64");
  mkdirSync(join(homedir(), ".contextengine"), { recursive: true });
  writeFileSync(LICENSE_FILE, JSON.stringify({ ...base, signature, activatedAt: new Date().toISOString(), lastHeartbeat: new Date(Date.now() - 2 * DAY).toISOString(), ...extra }));
}
const license = () => JSON.parse(readFileSync(LICENSE_FILE, "utf8"));
const reply = (status: number, body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));

beforeAll(() => {
  expect(homedir()).toMatch(/ce-test-home-/);
  __setLicensePublicKeyForTesting(publicKey.export({ type: "spki", format: "pem" }).toString());
});
afterAll(() => __setLicensePublicKeyForTesting(null));
afterEach(() => vi.unstubAllGlobals());

describe("heartbeat", () => {
  it("a valid answer refreshes the check and clears any offline mark", async () => {
    writeLicense({ offlineSince: new Date(Date.now() - 3 * DAY).toISOString() });
    const f = reply(200, { valid: true });
    vi.stubGlobal("fetch", f);
    expect(await heartbeat()).toBe("valid");
    expect(f).toHaveBeenCalledOnce();
    expect(Date.now() - Date.parse(license().lastHeartbeat)).toBeLessThan(10_000);
    expect(license().offlineSince).toBeUndefined();
    expect(gateCheck("score_project")).toBeNull();
  });

  it("a first refusal warns; refusals lasting past 3 days cancel; a success in between clears them", async () => {
    writeLicense();
    vi.stubGlobal("fetch", reply(403, { valid: false, error: "Invalid license" }));
    expect(await heartbeat()).toBe("refused");
    expect(license().refusedSince.reason).toBe("Invalid license");
    expect(license().revoked).toBeUndefined();
    expect(gateCheck("score_project")).toBeNull(); // grace: a server-side mistake cannot cut Pro at once

    writeLicense({ refusedSince: { at: new Date(Date.now() - 4 * DAY).toISOString(), reason: "Invalid license" } });
    expect(await heartbeat()).toBe("revoked");
    expect(license().revoked.reason).toBe("Invalid license");
    expect(gateCheck("score_project")).toMatch(/requires a ContextEngine Pro license/);

    writeLicense({ refusedSince: { at: new Date(Date.now() - 2 * DAY).toISOString(), reason: "x" } });
    vi.stubGlobal("fetch", reply(200, { valid: true }));
    expect(await heartbeat()).toBe("valid");
    expect(license().refusedSince).toBeUndefined();
  });

  it("no answer, a 429, a 500 or a 403 that is not the server's never cancel; they start the grace", async () => {
    for (const f of [vi.fn(async () => { throw new Error("offline"); }), reply(429, {}), reply(500, { valid: false }), reply(403, "<html>proxy</html>")]) {
      writeLicense();
      vi.stubGlobal("fetch", f);
      expect(await heartbeat()).toBe("unreachable");
      expect(license().revoked).toBeUndefined();
      expect(license().offlineSince).toBeTruthy();
      expect(gateCheck("score_project")).toBeNull();
    }
  });

  it("past 7 days without reaching the server, the gate refuses; the first failure starts the clock", async () => {
    writeLicense({ lastHeartbeat: "2000-01-01T00:00:00.000Z" });
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    expect(await gateCheckFresh("score_project")).toBeNull(); // an upgrade on a bad-network day
    writeLicense({ offlineSince: new Date(Date.now() - 8 * DAY).toISOString() });
    expect(await gateCheckFresh("score_project")).toMatch(/has not been reachable for 8 days/);
  });

  it("after a failure the next call within the hour does not wait on the network again", async () => {
    writeLicense();
    const f = vi.fn(async () => { throw new Error("offline"); });
    vi.stubGlobal("fetch", f);
    expect(await heartbeat()).toBe("unreachable");
    expect(await heartbeat()).toBe("fresh");
    expect(f).toHaveBeenCalledOnce();
  });

  it("checks at most once a day, and treats a check scheduled too far out as due", async () => {
    writeLicense({ nextCheck: new Date(Date.now() + 23 * 3_600_000).toISOString() });
    const f = reply(200, { valid: true });
    vi.stubGlobal("fetch", f);
    expect(await heartbeat()).toBe("fresh");
    expect(f).not.toHaveBeenCalled();
    writeLicense({ nextCheck: new Date(Date.now() + 365 * DAY).toISOString() });
    expect(await heartbeat()).toBe("valid");
    expect(f).toHaveBeenCalledOnce();
  });

  it("the Pro gate runs the check when it is due; a free tool never does", async () => {
    writeLicense();
    const f = reply(200, { valid: true });
    vi.stubGlobal("fetch", f);
    expect(await gateCheckFresh("search_context")).toBeNull();
    expect(f).not.toHaveBeenCalled();
    expect(await gateCheckFresh("run_audit")).toBeNull();
    expect(f).toHaveBeenCalledOnce();
    const sent = JSON.parse((f.mock.calls[0] as unknown as [string, { body: string }])[1].body);
    expect(Object.keys(sent).sort()).toEqual(["deltaVersion", "key", "machineId"]); // [ACTIVATION-PAYLOAD-NO-USAGE-DATA]
  });
});
