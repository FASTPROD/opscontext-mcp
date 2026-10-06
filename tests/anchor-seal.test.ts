// The SealHour backend of the hourly job, against a stand-in service on this machine.
// [LOCK] [NOT-SEALED-IS-NEVER-CALLED-SEALED] (src/anchor-seal.ts)
// [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY] [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY] (src/anchor-service.ts)
// [LOCK] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES] [LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE] (src/anchor-bundle.ts)
// [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] [LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD] (src/anchor.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { appendAudit } from "../src/audit.js";
import { anchorTick, anchorHealth, anchorTickDue, newConfig, writeConfig, readState, listCheckpoints, type AnchorConfig, type StoredCheckpoint } from "../src/anchor.js";
import { canonBytes, digestOf } from "../src/anchor-protocol.js";
import { findOpenssl } from "../src/anchor-tsa.js";
import { ensurePilotToken, readPilotToken } from "../src/anchor-service.js";
import { BUNDLE_NAME } from "../src/anchor-bundle.js";
import { exportEvidence, formatVerify, verifyAnchors } from "../src/anchor-verify.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";
import { startFakeSealHour, type FakeSealHour } from "./helpers/fake-sealhour.js";

const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;

let tsa: FakeTsa;
let svc: FakeSealHour;
let keys: string;
let home: string;
let work: string;
const saved: Record<string, string | undefined> = {};

beforeAll(async () => {
  if (!haveOpenssl) return;
  keys = mkdtempSync(join(tmpdir(), "ce-seal-keys-"));
  tsa = await startFakeTsa(keys, "seal");
});
afterAll(async () => {
  if (!haveOpenssl) return;
  await tsa.close().catch(() => undefined);
  rmSync(keys, { recursive: true, force: true });
});
beforeEach(async () => {
  for (const k of ["CONTEXTENGINE_HOME", "CONTEXTENGINE_SEALHOUR_TEST", "CONTEXTENGINE_ANCHOR_TEST_PROVIDERS", "CONTEXTENGINE_WORKSPACES"]) saved[k] = process.env[k];
  home = mkdtempSync(join(tmpdir(), "ce-seal-home-"));
  work = mkdtempSync(join(tmpdir(), "ce-seal-ws-"));
  process.env.CONTEXTENGINE_HOME = home;
  process.env.CONTEXTENGINE_WORKSPACES = work;
  if (!haveOpenssl) return;
  svc = await startFakeSealHour(keys, tsa);
  process.env.CONTEXTENGINE_SEALHOUR_TEST = svc.env();
  process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS = JSON.stringify([tsa.entry()]);
  tsa.requests.length = 0;
});
afterEach(async () => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  if (haveOpenssl) await svc.close().catch(() => undefined);
  rmSync(home, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
});

/** A fixed clock: the hour, then minutes into it. */
const at = (hour: string, minute = 30, second = 0) => new Date(`${hour}:${String(minute).padStart(2, "0")}:${String(second).padStart(2, "0")}Z`);
const H1 = "2026-10-06T14";
const H2 = "2026-10-06T15";
const H3 = "2026-10-06T16";
const H4 = "2026-10-06T17";

/** The owner's yes to the service, with a pilot code (this test home has no licence). */
function enable(o: Partial<AnchorConfig> = {}): AnchorConfig {
  const cfg = { ...newConfig({ code: false, providers: ["sealhour"], now: at(H1, 0), rand: () => 10 * 60, backend: "sealhour", credential: "pilot" }), ...o };
  writeConfig(cfg);
  ensurePilotToken();
  return cfg;
}
/** One run of the hourly job at `now`; the service's clock is the same. */
function tick(now: Date, extra: { force?: boolean } = {}) {
  svc.clock = () => now;
  return anchorTick({ now: () => now, timeoutMs: 2000, clientVersion: "test", sleep: async () => undefined, ...extra });
}
const line = (now: Date) => anchorHealth(now).line;
const sealOf = (c: StoredCheckpoint) => c.meta.seal!;
const grow = (n = 1) => { for (let i = 0; i < n; i++) appendAudit("learning.save", { n: Math.random() }); };
const logLength = () => readFileSync(join(home, "audit.log"), "utf8").length;
function everyFile(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) out.push(...everyFile(join(dir, e.name)));
    else out.push(join(dir, e.name));
  }
  return out;
}

describe.skipIf(!haveOpenssl)("no yes to the service, nothing goes to it", () => {
  it("a machine that said yes to interim mode keeps stamping with the free services and never calls the service", async () => {
    grow(2);
    writeConfig(newConfig({ code: false, providers: [tsa.id], now: at(H1, 0), rand: () => 600 }));
    const r = await tick(at(H1, 30));
    expect(r.action).toBe("checkpoint");
    expect(r.stamped).toEqual([`Test TSA ${tsa.id}`]);
    expect(svc.requests.length).toBe(0);
    expect(line(at(H1, 31))).toMatch(/^SealHour interim: on/);
  });

  it("a configuration moved to the service without the owner's yes to it is off", async () => {
    grow(2);
    const interim = newConfig({ code: false, providers: [tsa.id], now: at(H1, 0), rand: () => 600 });
    writeConfig({ ...interim, backend: "sealhour" }); // the consent still names the interim backend
    expect((await tick(at(H1, 30))).action).toBe("off");
    expect(anchorTickDue(at(H1, 30))).toBe(false);
    expect(svc.requests.length + tsa.requests.length).toBe(0);
    expect(listCheckpoints().length).toBe(0);
  });
});

describe.skipIf(!haveOpenssl)("one checkpoint, from made to sealed", () => {
  it("sends the checkpoint and the credential and nothing else, keeps the receipt, then the proof, and says each state as it is", async () => {
    grow(3);
    enable();
    const before = logLength();
    const r = await tick(at(H1, 30));
    expect(r.action).toBe("checkpoint");
    expect(r.received).toEqual([1]);
    expect(r.detail).toMatch(/checkpoint 1 \(3 record\(s\)\) received by SealHour TEST stand-in .*receipt ok; its hour 2026-10-06T15Z is sealed at 15:02Z/);

    // What left: one request, the canonical checkpoint, the pilot code in Authorization.
    expect(svc.requests.length).toBe(1);
    const [c] = listCheckpoints();
    const sent = svc.requests[0];
    expect(sent.method).toBe("POST");
    expect(sent.path).toBe("/v1/checkpoints");
    expect(sent.body.equals(canonBytes(c.checkpoint))).toBe(true);
    expect(sent.headers.authorization).toBe(`Bearer ${readPilotToken()}`);
    expect(Object.keys(sent.headers).sort()).toEqual(["accept", "authorization", "connection", "content-length", "content-type", "host", "user-agent"]);
    expect(sent.headers["user-agent"]).toBe("opscontext-anchor");

    // Received is not sealed.
    expect(sealOf(c).state).toBe("received");
    expect(existsSync(join(c.dir, "receipt.json"))).toBe(true);
    expect(existsSync(join(c.dir, "proof"))).toBe(false);
    const l1 = line(at(H1, 31));
    expect(l1).toMatch(/SealHour TEST stand-in \(127\.0\.0\.1:\d+, not the SealHour service\): on \(chain only\), no seal yet, 1 checkpoint received \(receipt ok\), next seal at 15:02Z/);
    expect(anchorHealth(at(H1, 31)).problem).toBeNull();
    expect(readState().next_due).toBe("2026-10-06T15:02:45.000Z"); // the proof is asked 45 s after the cut-off

    // Before the cut-off nothing is asked; after it, a hour not sealed yet stays "received".
    await tick(at(H1, 50));
    expect(svc.requests.length).toBe(1);
    await tick(at(H2, 3));
    expect(svc.requests.length).toBe(2);
    expect(svc.requests[1].method).toBe("GET");
    expect(svc.requests[1].path).toBe(`/v1/proofs/${digestOf(c.checkpoint)}`);
    expect(svc.requests[1].headers.authorization).toBeUndefined(); // the digest is the capability
    expect(sealOf(listCheckpoints()[0])).toMatchObject({ state: "received", waiting: "hour not sealed yet" });
    expect(line(at(H2, 4))).not.toMatch(/last seal/);

    // The hour is sealed: the proof is fetched, checked, kept under the contract's names only.
    await svc.seal("2026-10-06T15Z", { ots: "pending" });
    const r3 = await tick(at(H2, 6));
    expect(r3.sealed).toEqual([1]);
    const [s] = listCheckpoints();
    expect(sealOf(s)).toMatchObject({ state: "sealed", hour: "2026-10-06T15Z", bitcoin: "pending", error: null });
    expect(sealOf(s).stamp).toMatchObject({ name: "Test stamp service (not a real time stamp)", checked: true });
    const proof = join(s.dir, "proof");
    const names = everyFile(proof).map((f) => f.slice(proof.length + 1)).sort();
    expect(names).toEqual(["LISEZMOI.txt", "README.txt", "certs/test-ca.pem", "checkpoint.json", `keys/${svc.keyId}.pub`, "leaf.json", "path.json", "receipt.json", "root.bin", "root.bin.ots", "root.test.tsr", "stamps.json"]);
    expect(names.every((n) => BUNDLE_NAME.test(n))).toBe(true);
    const sealedAt = new Date(sealOf(s).stamp!.time!);
    expect(line(new Date(sealedAt.getTime() + 12 * 60_000))).toMatch(/: on \(chain only\), last seal 12 min ago, receipt ok, nothing new since, next checkpoint after \d\d:\d\dZ/);

    // The job never wrote to the audit log. [LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD]
    expect(logLength()).toBe(before);

    // verify: everything checked here; export: the proof as served, a folder SealHour's checker can read.
    const v = verifyAnchors();
    expect(v.holds).toBe(true);
    const text = formatVerify(v);
    expect(text).toMatch(/\[OK\] receipt signed by SealHour TEST stand-in .* key test-receipts-1: received 2026-10-06 14:30:00Z for the hour 2026-10-06T15Z/);
    expect(text).toMatch(/\[OK\] included in the hour 2026-10-06T15Z \(one of 1 fingerprints\)/);
    expect(text).toMatch(/\[OK\] hour stamped by Test stamp service/);
    expect(text).toMatch(/\[\?\?\] Bitcoin: the Bitcoin attestation is still pending/);
    expect(text).toMatch(/1 of 1 checkpoint\(s\) hold; 1 sealed, their hour's stamp checked/);
    const out = join(home, "export");
    const e = exportEvidence({ from: "2026-10-06", to: "2026-10-06", out });
    expect(e).toMatchObject({ count: 1, sealed: 1, pendingBitcoin: 1 });
    expect(everyFile(join(out, "checkpoints", s.name)).map((f) => f.split(`${s.name}/`)[1]).sort()).toEqual(names);
    expect(readFileSync(join(out, "README.txt"), "utf8")).toMatch(/python3 sealhour_verify\.py checkpoints\//);
    const mjs = (...a: string[]) => spawnSync(process.execPath, [join(out, "verify.mjs"), out, ...a], { encoding: "utf8", env: { ...process.env, OPENSSL: ssl!.path } });
    // The export's checker knows SealHour's key and certificates, never a stand-in's.
    const strict = mjs();
    expect(strict.stdout).toMatch(/\[\?\?\] receipt signed by key test-receipts-1, which this checker does not know/);
    expect(strict.stdout).toMatch(/\[\?\?\] hour stamped by Test stamp service .* under a certificate this checker does not know/);
    expect(strict.stdout).not.toMatch(/\[NO\]/);
    const trusting = mjs("--trust-folder");
    expect(trusting.stdout).toMatch(/\[OK\] receipt signed by SealHour key test-receipts-1/);
    expect(trusting.stdout).toMatch(/\[OK\] included in the hour 2026-10-06T15Z/);
    expect(trusting.stdout).toMatch(/\[OK\] hour stamped by Test stamp service/);
    expect(trusting.stdout).toMatch(/Result: 1 checkpoint\(s\), the rule holds\./);
    expect(trusting.status).toBe(0);
  });

  it("the pilot code is in one file, readable by the owner alone, and nowhere else", async () => {
    grow(2);
    const copy = mkdtempSync(join(tmpdir(), "ce-seal-copy-"));
    try {
      enable({ copy_dir: copy });
      const r1 = await tick(at(H1, 30));
      await svc.seal("2026-10-06T15Z");
      const r2 = await tick(at(H2, 6));
      const token = readPilotToken()!;
      expect(statSync(join(home, "anchors", "pilot-token")).mode & 0o777).toBe(0o600);
      const out = join(home, "export");
      exportEvidence({ from: "2026-10-06", to: "2026-10-06", out });
      const holders = [...everyFile(home), ...everyFile(copy)].filter((f) => readFileSync(f).includes(token));
      expect(holders).toEqual([join(home, "anchors", "pilot-token")]);
      expect(`${r1.detail} ${r2.detail} ${line(at(H2, 7))} ${formatVerify(verifyAnchors())}`).not.toContain(token);
      // The copy holds the receipt and the proof, never what names repositories.
      const copied = everyFile(copy).map((f) => f.split("/checkpoints/")[1]).filter(Boolean).map((f) => f.split("/").slice(1).join("/")).sort();
      expect(copied).toContain("receipt.json");
      expect(copied).toContain("proof/root.test.tsr");
      expect(copied).toContain("proof/path.json");
      expect(copied).not.toContain("meta.json");
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!haveOpenssl)("a receipt counts only when it passes the contract's rules under the pinned key", () => {
  for (const how of ["wrong-key", "other-digest", "other-customer", "wrong-hour"] as const) {
    it(`an answer that is a receipt in shape but ${how} is not stored, and the checkpoint stays queued`, async () => {
      grow(2);
      enable();
      svc.nextPost.push(how);
      const r = await tick(at(H1, 30));
      const [c] = listCheckpoints();
      expect(sealOf(c).state).toBe("queued");
      expect(existsSync(join(c.dir, "receipt.json"))).toBe(false);
      expect(r.detail).toMatch(/not sent yet: .*not a receipt this version of OpsContext may keep.*\(queued\)/);
      const h = anchorHealth(at(H1, 31));
      expect(h.problem).toMatch(/^not sealed yet: .*not a receipt this version of OpsContext may keep.*\(1 checkpoint queued\)$/);
      // Held for hours, then sent again: the service answers the receipt it kept.
      await tick(at(H1, 40));
      expect(svc.posts().length).toBe(1);
      await tick(at("2026-10-06T21", 0));
      expect(svc.posts().length).toBe(2);
      expect(sealOf(listCheckpoints()[0]).state).toBe("received");
    });
  }

  it("a receipt under a key id this version does not know says so", async () => {
    grow(2);
    enable();
    svc.nextPost.push({ status: 201, body: { version: 1, kind: "receipt", checkpoint_digest: "ab".repeat(32), customer: "cd".repeat(32), received_at: "2026-10-06T14:30:00Z", hour: "2026-10-06T15Z", key_id: "sealhour-2031-01", signature: `${"A".repeat(86)}==` } });
    await tick(at(H1, 30));
    expect(anchorHealth(at(H1, 31)).problem).toMatch(/signed under a key this version of OpsContext does not know \(sealhour-2031-01\): update OpsContext/);
  });
});

describe.skipIf(!haveOpenssl)("what the service answers, and what the client does (contract section 5.1)", () => {
  it("503 without a wait: queued, said, retried with a backoff, then received", async () => {
    grow(2);
    enable();
    svc.nextPost.push({ status: 503, body: { error: "the licence could not be checked just now; try again later" }, headers: { "Retry-After": "300" } });
    const r = await tick(at(H1, 30));
    expect(r.detail).toMatch(/checkpoint 1 \(2 record\(s\)\) made, not sent yet: .* answered: the licence could not be checked just now; try again later \(queued\)/);
    expect(anchorHealth(at(H1, 31)).problem).toMatch(/^not sealed yet: SealHour TEST stand-in .* answered: the licence could not be checked just now; try again later \(1 checkpoint queued\)$/);
    expect(readState().hold?.until).toBe("2026-10-06T14:35:00.000Z"); // the service said 300 s
    expect(readState().next_due).toBe("2026-10-06T14:35:00.000Z");
    await tick(at(H1, 33));
    expect(svc.posts().length).toBe(1);
    await tick(at(H1, 36));
    expect(svc.posts().length).toBe(2);
    expect(sealOf(listCheckpoints()[0]).state).toBe("received");
    expect(readState().hold).toBeNull();
    expect(anchorHealth(at(H1, 37)).problem).toBeNull();
  });

  it("503 with Retry-After: 1 (the hour is being sealed) is sent again in the same run", async () => {
    grow(2);
    enable();
    svc.nextPost.push({ status: 503, body: { error: "the hour is being sealed; try again in a second" }, headers: { "Retry-After": "1" } });
    const r = await tick(at(H1, 30));
    expect(svc.posts().length).toBe(2);
    expect(r.received).toEqual([1]);
  });

  it("the service away: checkpoints keep being made, wait in order, and all go once it is back", async () => {
    grow(2);
    enable();
    const url = svc.url;
    await svc.close();
    const r1 = await tick(at(H1, 30));
    expect(r1.detail).toMatch(/not sent yet: SealHour TEST stand-in .* did not answer \(connection refused\) \(queued\)/);
    grow(1);
    await tick(at(H2, 30));
    grow(1);
    await tick(at(H3, 30));
    expect(listCheckpoints().map((c) => sealOf(c).state)).toEqual(["queued", "queued", "queued"]);
    expect(anchorHealth(at(H3, 31)).problem).toMatch(/^not sealed yet: SealHour TEST stand-in .* did not answer \(connection refused\) \(3 checkpoints queued\)$/);
    // Back, on the same address.
    svc = await startFakeSealHour(keys, tsa);
    process.env.CONTEXTENGINE_SEALHOUR_TEST = JSON.stringify({ ...JSON.parse(svc.env()) });
    expect(url).not.toBe(""); // (a new port: the stand-in's address is read at each run)
    grow(1);
    const r4 = await tick(at(H4, 30));
    expect(r4.received).toEqual([1, 2, 3, 4]);
    const all = listCheckpoints();
    expect(svc.posts().map((p) => p.digest)).toEqual(all.map((c) => digestOf(c.checkpoint))); // oldest first
    expect(new Set(all.map((c) => sealOf(c).hour))).toEqual(new Set(["2026-10-06T18Z"])); // one hour, one stamp
    expect(sealOf(all[0]).first_try).toBe(false);
    expect(sealOf(all[3]).first_try).toBe(true);
  });

  it("401 and 403: the service's line word for word, the queue held a day", async () => {
    grow(2);
    enable();
    svc.pilotOver = true;
    await tick(at(H1, 30));
    const h = anchorHealth(at(H1, 31));
    expect(h.problem).toBe("not sealed yet: SealHour TEST stand-in (" + new URL(svc.url).host + ", not the SealHour service) answered: the SealHour pilot has ended; SealHour is included in OpsContext Team and Enterprise (1 checkpoint queued)");
    grow(1);
    await tick(at(H2, 30));
    await tick(at(H3, 30));
    expect(svc.posts().length).toBe(1); // not asked again within the day
    expect(listCheckpoints().length).toBe(2);
    svc.pilotOver = false;
    await tick(at("2026-10-07T14", 31));
    expect(svc.posts().length).toBe(3);
    expect(listCheckpoints().map((c) => sealOf(c).state)).toEqual(["received", "received"]);
  });

  it("by hand (--now) the queue is sent whatever the hold", async () => {
    grow(2);
    enable();
    svc.nextPost.push({ status: 401, body: { error: "the licence server does not know this licence key" } });
    await tick(at(H1, 30));
    expect(readState().hold?.until).toBe("2026-10-07T14:30:00.000Z");
    const r = await tick(at(H1, 32), { force: true });
    expect(r.received).toEqual([1]);
  });

  it("400 and 409 are the checkpoint's own: kept, said, never sent again, and dated by the next sealed one", async () => {
    grow(2);
    enable();
    svc.nextPost.push({ status: 400, body: { error: "not a checkpoint of protocol version 1: version is not 1" } });
    await tick(at(H1, 30));
    const [c1] = listCheckpoints();
    expect(sealOf(c1)).toMatchObject({ state: "refused", error: expect.stringMatching(/refused this checkpoint \(400\): not a checkpoint of protocol version 1: version is not 1/) });
    expect(readState().hold ?? null).toBeNull();
    expect(anchorHealth(at(H1, 31)).problem).toMatch(/checkpoint #1 has no seal of its own \(.*version is not 1\); the next sealed checkpoint dates it/);
    grow(1);
    svc.nextPost.push({ status: 409, body: { error: "this checkpoint was already received from another customer" } });
    await tick(at(H2, 30));
    grow(1);
    await tick(at(H3, 30));
    expect(svc.posts().length).toBe(3); // one each: the refused ones were never sent again
    await svc.seal("2026-10-06T17Z");
    await tick(at(H4, 5));
    const all = listCheckpoints();
    expect(all.map((c) => sealOf(c).state)).toEqual(["refused", "refused", "sealed"]);
    expect(all[0].meta.covered_by).toMatchObject({ seq: 3 });
    expect(all[1].meta.covered_by).toMatchObject({ seq: 3 });
    expect(anchorHealth(at(H4, 6)).problem).toBeNull();
    const v = verifyAnchors();
    expect(v.holds).toBe(true);
    expect(formatVerify(v)).toMatch(/no checked stamp of its own: dated through the chain by #3's seal of .*, a later date/);
  });
});

describe.skipIf(!haveOpenssl)("the proof is kept only when it holds", () => {
  async function received(): Promise<void> {
    grow(2);
    enable();
    await tick(at(H1, 30));
  }

  it("a missed hour (410): no proof of its own, not asked again, dated by the next checkpoint's seal", async () => {
    await received();
    svc.missed.add("2026-10-06T15Z");
    await tick(at(H2, 5));
    expect(sealOf(listCheckpoints()[0])).toMatchObject({ state: "missed", proof_next_at: null });
    expect(sealOf(listCheckpoints()[0]).error).toMatch(/missed the hour 2026-10-06T15Z: hour 2026-10-06T15Z was not sealed and never will be/);
    const gets = svc.requests.filter((r) => r.method === "GET").length;
    await tick(at(H2, 20));
    expect(svc.requests.filter((r) => r.method === "GET").length).toBe(gets);
    grow(1);
    await tick(at(H2, 30));
    await svc.seal("2026-10-06T16Z");
    await tick(at(H3, 5));
    const all = listCheckpoints();
    expect(all[0].meta.covered_by).toMatchObject({ seq: 2 });
    expect(formatVerify(verifyAnchors())).toMatch(/not sealed: .*missed the hour 2026-10-06T15Z/);
  });

  it("a bundle carrying a name outside the contract's list is refused whole: nothing is written", async () => {
    await received();
    await svc.seal("2026-10-06T15Z");
    svc.mangle = (files) => { files["../../../escaped.txt"] = Buffer.from("x"); };
    await tick(at(H2, 5));
    const [c] = listCheckpoints();
    expect(sealOf(c).state).toBe("received");
    expect(sealOf(c).error).toMatch(/was not kept: the bundle carries a file name outside the protocol/);
    expect(existsSync(join(c.dir, "proof"))).toBe(false);
    expect(everyFile(home).filter((f) => f.includes("escaped"))).toEqual([]);
    expect(existsSync(join(home, "..", "escaped.txt"))).toBe(false);
    for (const bad of ["/etc/x", "keys/../x.pub", "certs/.hidden", "record/leaf.json", "root.bin.exe", "a\\b"]) expect(BUNDLE_NAME.test(bad), bad).toBe(false);
  });

  for (const [what, mangle, why] of [
    ["a path that does not lead to the hour's root", (f: Record<string, Buffer>) => { const p = JSON.parse(f["path.json"].toString()); p.root = "ab".repeat(32); f["path.json"] = Buffer.from(JSON.stringify(p)); }, /inclusion path does not lead/],
    ["another hour's root", (f: Record<string, Buffer>) => { f["root.bin"] = Buffer.alloc(32, 7); }, /inclusion path does not lead/],
    ["another checkpoint", (f: Record<string, Buffer>) => { const c = JSON.parse(f["checkpoint.json"].toString()); c.records.count += 1; f["checkpoint.json"] = Buffer.from(JSON.stringify(c)); }, /not the checkpoint this proof seals|another checkpoint/],
    ["a receipt changed after it was signed", (f: Record<string, Buffer>) => { const r = JSON.parse(f["receipt.json"].toString()); r.received_at = "2026-10-06T14:29:59Z"; f["receipt.json"] = Buffer.from(JSON.stringify(r)); }, /receipt: .*signature does not verify/],
    ["a stamp of another fingerprint", (f: Record<string, Buffer>) => { const b = Buffer.from(f["root.test.tsr"]); const i = b.indexOf(f["root.bin"]); b[i] ^= 1; f["root.test.tsr"] = b; }, /another fingerprint|not a time stamp|does not verify|Verif/i],
  ] as const) {
    it(`a proof with ${what} is not kept, and the checkpoint is not called sealed`, async () => {
      await received();
      await svc.seal("2026-10-06T15Z");
      svc.mangle = mangle as (f: Record<string, Buffer>) => void;
      await tick(at(H2, 5));
      const [c] = listCheckpoints();
      expect(sealOf(c).state).toBe("received");
      expect(sealOf(c).error).toMatch(why);
      expect(existsSync(join(c.dir, "proof"))).toBe(false);
      expect(line(at(H2, 6))).not.toMatch(/last seal/);
      // The honest proof, later, is kept.
      svc.mangle = null;
      await tick(at(H2, 20));
      expect(sealOf(listCheckpoints()[0]).state).toBe("sealed");
    });
  }

  it("a stamp under a certificate this version does not know: included, and said as not checked, never as checked", async () => {
    process.env.CONTEXTENGINE_SEALHOUR_TEST = svc.env({ anchors: false });
    await received();
    await svc.seal("2026-10-06T15Z");
    await tick(at(H2, 5));
    const [c] = listCheckpoints();
    expect(sealOf(c).state).toBe("sealed");
    expect(sealOf(c).stamp).toMatchObject({ checked: false });
    // (the stand-in's stamp carries the real clock's time, so the line is read a few minutes after it)
    expect(line(new Date(Date.parse(sealOf(c).stamp!.time!) + 9 * 60_000))).toMatch(/last seal 9 min ago \(its official stamp could not be checked on this machine\), receipt ok/);
    expect(formatVerify(verifyAnchors())).toMatch(/\[\?\?\] hour's stamp, Test stamp service .* under a certificate this version of OpsContext does not know/);
  });

  it("an hour still not sealed long after its cut-off is a problem, in words", async () => {
    await received();
    await tick(at(H2, 5));
    expect(anchorHealth(at(H2, 30)).problem).toBeNull();
    expect(anchorHealth(at(H3, 30)).problem).toMatch(/^not sealed yet: the hour 2026-10-06T15Z is still not sealed at SealHour TEST stand-in .* \(hour not sealed yet\)$/);
  });

  it("a pending Bitcoin attestation is fetched again hours later, and a worse proof never replaces the one kept", async () => {
    await received();
    await svc.seal("2026-10-06T15Z", { ots: "pending" });
    await tick(at(H2, 5));
    expect(sealOf(listCheckpoints()[0]).bitcoin).toBe("pending");
    const gets = () => svc.requests.filter((r) => r.method === "GET").length;
    const n = gets();
    await tick(at(H3, 30));
    expect(gets()).toBe(n); // not within 3 hours
    // A proof without its stamp comes back: the one kept stays.
    svc.hours.get("2026-10-06T15Z")!.ots = "complete";
    svc.mangle = (f) => { delete f["root.test.tsr"]; };
    await tick(at("2026-10-06T18", 30));
    expect(gets()).toBe(n + 1);
    expect(sealOf(listCheckpoints()[0])).toMatchObject({ state: "sealed", bitcoin: "pending" });
    expect(existsSync(join(listCheckpoints()[0].dir, "proof", "root.test.tsr"))).toBe(true);
    // The complete one, later, replaces it.
    svc.mangle = null;
    await tick(at("2026-10-06T22", 30));
    expect(sealOf(listCheckpoints()[0])).toMatchObject({ state: "sealed", bitcoin: "complete", proof_next_at: null });
    expect(readFileSync(join(listCheckpoints()[0].dir, "proof", "root.bin.ots"), "utf8")).toBe("fake attestation, complete");
  });
});

describe.skipIf(!haveOpenssl)("the credential is the one the owner said yes to", () => {
  it("a yes given with the licence key, and no licence on the machine: nothing is sent, and the line says why", async () => {
    grow(2);
    enable({ consent: { at: at(H1, 0).toISOString(), screen: 2, backend: "sealhour", providers: ["sealhour"], credential: "licence" } });
    const r = await tick(at(H1, 30));
    expect(svc.requests.length).toBe(0); // the pilot code on disk is not used: the owner did not say yes to it
    expect(r.detail).toMatch(/not sent yet: no OpsContext licence on this machine \(contextengine anchor enable asks again\) \(queued\)/);
    expect(anchorHealth(at(H1, 31)).problem).toBe("not sealed yet: no OpsContext licence on this machine (contextengine anchor enable asks again) (1 checkpoint queued)");
  });

  it("moving from interim mode: what the free services stamped is never sent, and the first seal dates what they had not stamped", async () => {
    grow(2);
    writeConfig(newConfig({ code: false, providers: [tsa.id], now: at(H1, 0), rand: () => 600 }));
    await tick(at(H1, 30)); // #1, stamped directly
    grow(1);
    tsa.mode = "http503";
    await tick(at(H2, 30)); // #2, not stamped
    tsa.mode = "ok";
    enable(); // the owner's yes to the service
    grow(1);
    await tick(at(H3, 30)); // #3, sent
    expect(svc.posts().length).toBe(1);
    expect(svc.posts()[0].digest).toBe(digestOf(listCheckpoints()[2].checkpoint));
    expect(tsa.requests.length).toBe(2); // the free service is no longer asked, for #2 either
    await svc.seal("2026-10-06T17Z");
    await tick(at(H4, 5));
    const all = listCheckpoints();
    expect(all[1].meta.covered_by).toMatchObject({ seq: 3 });
    const v = verifyAnchors();
    expect(v.holds).toBe(true);
    expect(v.summary).toMatch(/3 of 3 checkpoint\(s\) hold; 1 sealed, their hour's stamp checked; 1 stamped and checked, 1 dated through a later stamp/);
  });
});
