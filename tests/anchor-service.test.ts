// The SealHour client's network and bundle halves, on their own.
// [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY] [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY] (src/anchor-service.ts)
// [LOCK] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES] [LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE] (src/anchor-bundle.ts)
//
// The last block reads, in place, what the SealHour service itself produced (a receipt its server
// signed and the first proof of its real chain): the folder named by SEALHOUR_VECTORS_DIR, set by
// scripts/test-sealhour-fixture.sh. Those files name the official stamp provider, so they are never
// copied into this repository; without the variable the block shows as skipped, never passed.
import { describe, it, expect, afterEach } from "vitest";
import http from "http";
import type { AddressInfo } from "net";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { generateKeyPairSync } from "crypto";
import { makeCheckpoint, ZERO } from "../src/anchor-protocol.js";
import { activeService, getProof, postCheckpoint, publicKeyHex, receiptRefusals, RECEIPT_KEYS, STAMP_ANCHORS, type Service } from "../src/anchor-service.js";
import { bundleFiles, checkBundle, writeBundle, BUNDLE_NAME } from "../src/anchor-bundle.js";
import { verifyMjs } from "../src/anchor-checker.js";
import { findOpenssl } from "../src/anchor-tsa.js";

const servers: http.Server[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const s of servers.splice(0)) await new Promise<void>((done) => { s.closeAllConnections(); s.close(() => done()); });
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A stand-in that answers every request with what `handler` writes. */
async function standIn(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void): Promise<Service> {
  const server = http.createServer((req, res) => { req.resume(); req.on("end", () => handler(req, res)); });
  servers.push(server);
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, keys: [], anchors: [], test: true };
}
const cp = makeCheckpoint({ from_hash: ZERO, count: 1, head_hash: "a".repeat(64), records_root: "b".repeat(64) }, { created_at: "2026-10-06T14:30:00Z", prev: ZERO, clientVersion: "test" });
const DIGEST = "c".repeat(64);
const b64 = (s: string) => Buffer.from(s).toString("base64");

describe("answers from the network are read as bytes that may be anything", () => {
  it("a body shorter than announced is a cut connection, never a short answer", async () => {
    const svc = await standIn((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "5000" });
      res.write('{"version":1,"kind":"bundle"');
      res.socket?.destroy();
    });
    const r = await getProof(svc, DIGEST);
    expect(r).toMatchObject({ kind: "later", status: null });
    expect((r as { line: string }).line).toMatch(/did not answer \((the answer was cut short|the connection was cut)\)/);
  });

  it("a redirect is never followed: the credential goes to the service's address and nowhere else", async () => {
    let elsewhere = 0;
    const other = await standIn((_req, res) => { elsewhere++; res.writeHead(200); res.end("{}"); });
    const svc = await standIn((_req, res) => { res.writeHead(307, { Location: `${other.url}/v1/checkpoints` }); res.end(); });
    const r = await postCheckpoint(svc, cp, `pilot-${"1".repeat(64)}`);
    expect(r).toMatchObject({ kind: "later", status: 307 });
    expect(elsewhere).toBe(0);
  });

  it("an error page, a proxy's answer and an empty body are not receipts and not proofs", async () => {
    for (const body of ["<html>502 Bad Gateway</html>", "", "[]", "null", '"receipt"', "{}"]) {
      const svc = await standIn((_req, res) => { res.writeHead(200, { "Content-Type": "text/html" }); res.end(body); });
      expect((await postCheckpoint(svc, cp, `pilot-${"1".repeat(64)}`)).kind, body).toBe("bad-receipt");
      const p = await getProof(svc, DIGEST);
      if (p.kind === "bundle") expect(() => bundleFiles(p.bundle), body).toThrow(/not a SealHour bundle of protocol version 1/);
      else expect(p.kind, body).toBe("later");
    }
  });

  it("the service's error line is shown word for word, without control characters and without its length", async () => {
    const svc = await standIn((_req, res) => { res.writeHead(403, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: `this licence expired on 2026-09-30\u001b[31m\n${"x".repeat(500)}` })); });
    const r = await postCheckpoint(svc, cp, `pilot-${"1".repeat(64)}`);
    expect(r).toMatchObject({ kind: "refused", status: 403, retry: "daily" });
    const line = (r as { line: string }).line;
    expect(line.startsWith("this licence expired on 2026-09-30 [31m xxx")).toBe(true);
    expect(line.length).toBeLessThanOrEqual(200);
  });

  it("a proof is asked by a digest and nothing else", async () => {
    const svc = await standIn((_req, res) => { res.writeHead(404); res.end("{}"); });
    for (const bad of ["", "../receipts", "C".repeat(64), "c".repeat(63), `${"c".repeat(64)}?x=1`]) await expect(getProof(svc, bad)).rejects.toThrow(/64-hex/);
  });
});

describe("a bundle's names are the contract's fixed list", () => {
  const good = { "leaf.json": b64("{}"), "certs/ca_1.pem": b64("x"), "keys/sealhour-2026-10.pub": b64("x"), "root.some-profile.tsr": b64("x"), "root.bin.ots": b64("x") };
  const env = (files: Record<string, unknown>) => ({ version: 1, kind: "bundle", checkpoint_digest: DIGEST, files });

  it("takes the names of section 7.1", () => {
    expect([...bundleFiles(env(good)).keys()].sort()).toEqual(Object.keys(good).sort());
  });

  it("refuses the whole bundle for one name outside the list, before anything is written", () => {
    for (const name of ["../x", "/etc/passwd", "keys/../../x.pub", "certs/../x", "certs/.x", "certs/a/b", "record/leaf.json", "code/files.txt", "seal.json", "root.BIN", "keys/UPPER.pub", "leaf.json ", "", "certs/", "root..tsr", "C:\\x", "README.txt\u0000.sh"]) {
      expect(() => bundleFiles(env({ ...good, [name]: b64("x") })), JSON.stringify(name)).toThrow(/outside the protocol/);
      expect(BUNDLE_NAME.test(name), JSON.stringify(name)).toBe(false);
    }
  });

  it("refuses what is not a version 1 bundle, and a file that is not base64", () => {
    for (const bad of [null, [], "x", {}, { ...env(good), version: 2 }, { ...env(good), kind: "receipt" }, { ...env(good), checkpoint_digest: "C".repeat(64) }, { ...env(good), extra: 1 }, env({}), { ...env(good), files: [] }]) {
      expect(() => bundleFiles(bad)).toThrow(/not a SealHour bundle of protocol version 1/);
    }
    expect(() => bundleFiles(env({ "leaf.json": "not base64!" }))).toThrow(/leaf\.json is not base64/);
    expect(() => bundleFiles(env({ "leaf.json": 12 }))).toThrow(/not base64/);
  });

  it("writeBundle refuses a name the list does not hold, even handed to it directly, and replaces a folder whole", () => {
    const base = mkdtempSync(join(tmpdir(), "ce-bundle-"));
    dirs.push(base);
    const dir = join(base, "proof");
    expect(() => writeBundle(new Map([["../escaped.txt", Buffer.from("x")]]), dir)).toThrow(/refused to write/);
    expect(existsSync(join(base, "escaped.txt"))).toBe(false);
    writeBundle(new Map([["leaf.json", Buffer.from("1")], ["root.bin.ots", Buffer.from("old")]]), dir);
    writeBundle(new Map([["leaf.json", Buffer.from("2")], ["certs/a.pem", Buffer.from("c")]]), dir);
    expect(readFileSync(join(dir, "leaf.json"), "utf8")).toBe("2");
    expect(existsSync(join(dir, "root.bin.ots"))).toBe(false); // nothing of the old proof is left beside the new one
    expect(readFileSync(join(dir, "certs", "a.pem"), "utf8")).toBe("c");
  });
});

describe("what is pinned", () => {
  it("the receipt key is the one SealHour publishes, and the export's checker knows the same key and certificates", () => {
    expect(RECEIPT_KEYS.map((k) => k.id)).toEqual(["sealhour-2026-10"]);
    expect(publicKeyHex(RECEIPT_KEYS[0].pem)).toBe("7538476ce95a13f958815b2af78457277b788a22680a695cbe2c4aecc1524104");
    expect(STAMP_ANCHORS.length).toBe(5);
    expect(STAMP_ANCHORS.every((a) => /^[0-9a-f]{64}$/.test(a))).toBe(true);
    const mjs = verifyMjs({ keys: Object.fromEntries(RECEIPT_KEYS.map((k) => [k.id, publicKeyHex(k.pem)])), anchors: STAMP_ANCHORS });
    expect(mjs).toContain('const KNOWN_KEYS = {"sealhour-2026-10":"7538476ce95a13f958815b2af78457277b788a22680a695cbe2c4aecc1524104"};');
    for (const a of STAMP_ANCHORS) expect(mjs).toContain(a);
    expect(mjs).not.toContain("/*PINS*/");
  });

  it("no environment variable replaces the pinned key for the real service", () => {
    const pair = generateKeyPairSync("ed25519");
    const dir = mkdtempSync(join(tmpdir(), "ce-pin-"));
    dirs.push(dir);
    writeFileSync(join(dir, "k.pub"), pair.publicKey.export({ type: "spki", format: "pem" }));
    const keep = process.env.CONTEXTENGINE_SEALHOUR_TEST;
    try {
      process.env.CONTEXTENGINE_SEALHOUR_TEST = JSON.stringify({ url: "https://api.sealhour.com", keys: [{ id: "sealhour-2026-10", file: join(dir, "k.pub") }], anchors: [] });
      expect(() => activeService()).toThrow(/test service refused: https:\/\/api\.sealhour\.com is not this machine/);
    } finally {
      if (keep === undefined) delete process.env.CONTEXTENGINE_SEALHOUR_TEST;
      else process.env.CONTEXTENGINE_SEALHOUR_TEST = keep;
    }
  });
});

const VEC = process.env.SEALHOUR_VECTORS_DIR ?? "";
const haveVectors = !!VEC && existsSync(join(VEC, "first-official-proof-2026-10-03.json"));
const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;
const REAL: Service = { url: "https://api.sealhour.com", keys: RECEIPT_KEYS, anchors: STAMP_ANCHORS, test: false };

describe.skipIf(!haveVectors)("what the SealHour service itself produced, read in place (SEALHOUR_VECTORS_DIR)", () => {
  it("a receipt signed by the server verifies under the pinned key, and under no change of a field", () => {
    const r = JSON.parse(readFileSync(join(VEC, "service-receipt-2026-10-02.json"), "utf8")) as Record<string, string>;
    expect(receiptRefusals(REAL, r, { digest: r.checkpoint_digest, customer: r.customer })).toEqual([]);
    expect(receiptRefusals(REAL, r, { digest: "ab".repeat(32) })).toEqual(["checkpoint_digest is not this checkpoint's"]);
    expect(receiptRefusals(REAL, r, { digest: r.checkpoint_digest, customer: "ab".repeat(32) })).toEqual(["customer is not this client's"]);
    for (const [k, v] of [["received_at", "2026-10-02T09:13:52Z"], ["hour", "2026-10-02T11Z"], ["customer", "ab".repeat(32)], ["key_id", "sealhour-2026-11"]] as const) {
      expect(receiptRefusals(REAL, { ...r, [k]: v }, { digest: r.checkpoint_digest }).length, k).toBeGreaterThan(0);
    }
  });

  it.skipIf(!haveOpenssl)("the first proof of the real chain holds: receipt, path, and the official stamp under a pinned certificate", () => {
    const bundle = JSON.parse(readFileSync(join(VEC, "first-official-proof-2026-10-03.json"), "utf8")) as { checkpoint_digest: string; files: Record<string, string> };
    const base = mkdtempSync(join(tmpdir(), "ce-real-proof-"));
    dirs.push(base);
    const files = bundleFiles(bundle);
    expect(files.size).toBe(12);
    writeBundle(files, join(base, "proof"));
    const c = checkBundle(join(base, "proof"), REAL, { digest: bundle.checkpoint_digest });
    expect(c).toMatchObject({ included: true, holds: true, hour: "2026-10-03T17Z", receivedAt: "2026-10-03T16:34:53Z", stampedAt: "2026-10-03T17:02:00Z" });
    expect(c.stamps.map((s) => s.mark)).toEqual(["OK"]);
    expect(c.bitcoin).toMatchObject({ state: "complete", block: 969756 });
    // Under another list of certificates the same stamp is shown, and does not count as a date.
    const blind = checkBundle(join(base, "proof"), { ...REAL, anchors: [] }, { digest: bundle.checkpoint_digest });
    expect(blind.stamps.map((s) => s.mark)).toEqual(["??"]);
    expect(blind.stampedAt).toBeNull();
    expect(blind.included).toBe(true);
    // One number changed in the checkpoint: the proof no longer holds.
    const cp2 = JSON.parse(files.get("checkpoint.json")!.toString("utf8"));
    cp2.records.count += 1;
    writeBundle(new Map([...files, ["checkpoint.json", Buffer.from(JSON.stringify(cp2))]]), join(base, "changed"));
    expect(checkBundle(join(base, "changed"), REAL)).toMatchObject({ included: false, holds: false });
  });
});
