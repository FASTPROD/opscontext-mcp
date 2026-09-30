// The interim backend's time stamp client. [LOCK] [ONLY-THE-DIGEST-LEAVES]
// [LOCK] [A-STAMP-IS-CHECKED-BEFORE-IT-COUNTS] (src/anchor-tsa.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { buildTsq, parseTsr, checkStamp, stampDigest, activeProviders, caFileFor, findOpenssl, PROVIDERS, type Provider } from "../src/anchor-tsa.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";

const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const REAL = join(process.cwd(), "tests/fixtures/anchor-real-stamps");
const REAL_DIGEST = "8ae6b8a72075113dc6024f5d7ece1b3df484747b1997e241355b8318c3265012";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ce-anchor-tsa-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe("the request: one digest, nothing else", () => {
  it("is exactly version 1, the SHA-256 imprint, the nonce, certReq", () => {
    const d = sha("checkpoint");
    const nonce = Buffer.from("0102030405060708", "hex");
    const tsq = buildTsq(d, nonce);
    const expected = Buffer.from(
      "3043" + "020101" + "3031" + "300d06096086480165030402010500" + "0420" + d + "02080102030405060708" + "0101ff",
      "hex",
    );
    expect(tsq.toString("hex")).toBe(expected.toString("hex"));
    // A nonce whose first bit is set gets a leading zero (a positive INTEGER); leading zeros go.
    expect(buildTsq(d, Buffer.from("8000000000000001", "hex")).toString("hex")).toContain("0209008000000000000001");
    expect(buildTsq(d, Buffer.from("0000000000000501", "hex")).toString("hex")).toContain("02020501");
  });

  it.skipIf(!haveOpenssl)("OpenSSL reads it as a time stamp query for that digest", () => {
    const d = sha("checkpoint");
    const f = join(dir, "q.tsq");
    writeFileSync(f, buildTsq(d, Buffer.from("1122334455667788", "hex")));
    const text = execFileSync(ssl!.path, ["ts", "-query", "-in", f, "-text"], { encoding: "utf8" });
    expect(text).toMatch(/Hash Algorithm: sha256/);
    const parsed = execFileSync(ssl!.path, ["asn1parse", "-inform", "DER", "-in", f], { encoding: "utf8" });
    expect(parsed).toContain(`OCTET STRING      [HEX DUMP]:${d.toUpperCase()}`);
    expect(text).toMatch(/Certificate required: yes/);
    expect(text).toMatch(/Nonce: 0x1122334455667788/);
    expect(text).toMatch(/Extensions:\s*$/m);
  });

  it("refuses anything that is not a 64-hex digest", () => {
    expect(() => buildTsq("ABC", Buffer.alloc(8))).toThrow();
    expect(() => buildTsq(sha("x").toUpperCase(), Buffer.alloc(8))).toThrow();
  });

  it("a test stand-in can only be on this machine", () => {
    const ca = join(dir, "ca.pem");
    writeFileSync(ca, "x");
    const set = (url: string) => { process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS = JSON.stringify([{ id: "t", url, caFile: ca }]); };
    try {
      set("http://127.0.0.1:9/tsr");
      expect(activeProviders()[0].url).toBe("http://127.0.0.1:9/tsr");
      for (const bad of ["https://freetsa.org/tsr", "http://10.0.0.1/tsr", "http://127.0.0.1.example.com/tsr", "https://127.0.0.1/tsr"]) {
        set(bad);
        expect(() => activeProviders(), bad).toThrow(/not this machine/);
      }
    } finally {
      delete process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS;
    }
    expect(activeProviders().map((p) => p.id)).toEqual(["freetsa", "digicert"]);
  });
});

describe.skipIf(!haveOpenssl)("two real stamps, checked offline against the pinned roots", () => {
  for (const id of ["freetsa", "digicert"]) {
    it(`${id}: granted, our imprint and nonce, verified at its own time`, () => {
      const tsr = join(REAL, `${id}.tsr`);
      const info = parseTsr(readFileSync(tsr));
      expect(info.status).toBe(0);
      expect(info.imprintSha256).toBe(REAL_DIGEST);
      expect(info.time).toMatch(/^2026-09-30T18:41:3[78]/);
      const p = PROVIDERS.find((x) => x.id === id)!;
      const ok = checkStamp({ tsr, queryFile: join(REAL, "q.tsq"), caFile: caFileFor(p, dir), time: info.time });
      expect(ok).toEqual({ ok: true, detail: "signature and chain verified by OpenSSL against the pinned root" });
    });
  }

  it("the other provider's root does not verify it, and a changed byte does not either", () => {
    const tsr = join(REAL, "freetsa.tsr");
    const wrongRoot = caFileFor(PROVIDERS.find((x) => x.id === "digicert")!, dir);
    expect(checkStamp({ tsr, digestHex: REAL_DIGEST, caFile: wrongRoot, time: "2026-09-30T18:41:37Z" }).ok).toBe(false);
    const bytes = readFileSync(tsr);
    bytes[bytes.length - 20] ^= 0xff; // inside the signature
    const bad = join(dir, "bad.tsr");
    writeFileSync(bad, bytes);
    const root = caFileFor(PROVIDERS.find((x) => x.id === "freetsa")!, dir);
    expect(checkStamp({ tsr: bad, digestHex: REAL_DIGEST, caFile: root, time: "2026-09-30T18:41:37Z" }).ok).toBe(false);
    expect(checkStamp({ tsr, digestHex: sha("another digest"), caFile: root, time: "2026-09-30T18:41:37Z" }).ok).toBe(false);
  });
});

describe.skipIf(!haveOpenssl)("stamping through a throwaway provider on 127.0.0.1", () => {
  let tsa: FakeTsa;
  let home: string;
  let provider: Provider;
  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "ce-anchor-fake-"));
    tsa = await startFakeTsa(home, "one");
    provider = { id: tsa.id, name: "Test TSA", url: tsa.url, caPem: readFileSync(tsa.caFile, "utf8") };
  });
  afterAll(async () => {
    await tsa.close().catch(() => undefined);
    rmSync(home, { recursive: true, force: true });
  });
  beforeEach(() => { tsa.mode = "ok"; tsa.requests.length = 0; });

  it("a granted stamp is kept with its request and checked; the provider received the digest and nothing else", async () => {
    const d = sha("a checkpoint");
    const r = await stampDigest(d, provider, dir, { certsDir: join(dir, "certs") });
    expect(r).toMatchObject({ ok: true, checked: true, error: null });
    expect(Math.abs(Date.parse(r.time!) - Date.now())).toBeLessThan(60_000);
    expect(existsSync(join(dir, `checkpoint.${tsa.id}.tsr`))).toBe(true);
    expect(existsSync(join(dir, `checkpoint.${tsa.id}.tsq`))).toBe(true);
    expect(tsa.requests.length).toBe(1);
    const sent = tsa.requests[0];
    // The body is exactly the request built for that digest (only its random nonce is unknown here).
    const q = readFileSync(join(dir, `checkpoint.${tsa.id}.tsq`));
    expect(sent.body.equals(q)).toBe(true);
    expect(sent.body.length).toBeLessThanOrEqual(70); // 69, or 70 when the nonce needs a leading zero
    expect(sent.body.toString("hex")).toContain("0420" + d);
    expect(Object.keys(sent.headers).sort()).toEqual(["connection", "content-length", "content-type", "host", "user-agent"]);
    expect(sent.headers["user-agent"]).toBe("opscontext-anchor");
  });

  const failures: Array<[string, FakeTsa["mode"], RegExp]> = [
    ["an HTTP error", "http503", /HTTP 503/],
    ["a cut connection", "cut", /cut|socket hang up/],
    ["an answer that is not a stamp", "garbage", /not a time stamp/],
    ["a stamp for another request", "other-request", /not for this request/],
  ];
  for (const [what, mode, msg] of failures) {
    it(`${what} is a failed stamp, and nothing is kept as one`, async () => {
      tsa.mode = mode;
      const r = await stampDigest(sha(what), provider, dir, { certsDir: join(dir, "certs") });
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(msg);
      expect(existsSync(join(dir, `checkpoint.${tsa.id}.tsr`))).toBe(false);
    });
  }

  it("a provider that never answers is given up after the timeout", async () => {
    tsa.mode = "hang";
    const t0 = Date.now();
    const r = await stampDigest(sha("slow"), provider, dir, { certsDir: join(dir, "certs"), timeoutMs: 400 });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no answer within/);
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("a provider that is down: connection refused", async () => {
    const other = await startFakeTsa(home, "two");
    const p: Provider = { id: other.id, name: "down", url: other.url, caPem: readFileSync(other.caFile, "utf8") };
    await other.close();
    const r = await stampDigest(sha("down"), p, dir, { certsDir: join(dir, "certs") });
    expect(r).toMatchObject({ ok: false, error: "connection refused" });
  });

  it("a stamp signed under another root is refused and not kept", async () => {
    const wrong: Provider = { ...provider, caPem: PROVIDERS[0].caPem };
    const r = await stampDigest(sha("wrong root"), wrong, dir, { certsDir: join(dir, "certs-wrong") });
    expect(r.ok).toBe(false);
    expect(r.checked).toBe(false);
    expect(r.error).toMatch(/does not verify against the pinned root/);
    expect(existsSync(join(dir, `checkpoint.${tsa.id}.tsr`))).toBe(false);
  });
});
