// SealHour protocol v1, the client's bytes. [LOCK] [SEALHOUR-PROTOCOL-V1-BYTES] (src/anchor-protocol.ts)
//
// Two kinds of test. The first kind is self-contained and runs everywhere. The second reads the
// protocol's fixture in place, from the folder named by SEALHOUR_FIXTURE_DIR (the contract's owner keeps
// it; it is never copied into this repository, whose tests are published). Without that variable those
// tests are reported as skipped, never as passed. scripts/test-sealhour-fixture.sh sets it.
import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { createHash, generateKeyPairSync, sign } from "crypto";
import {
  canon,
  mth,
  MerkleStream,
  auditPath,
  rootFromPath,
  leafHash,
  recordsRoot,
  codeRoot,
  sortCodeLeaves,
  digestOf,
  checkpointProblems,
  customerOf,
  hourOf,
  receiptProblems,
  ZERO,
  type CodeLeaf,
} from "../src/anchor-protocol.js";

const hex = (b: Buffer) => b.toString("hex");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

describe("canonical JSON (contract section 1)", () => {
  it("sorts keys at every level, writes no whitespace, keeps UTF-8 as itself", () => {
    expect(canon({ b: 1, a: { d: [3, { z: true, y: null }], c: "é" } })).toBe('{"a":{"c":"é","d":[3,{"y":null,"z":true}]},"b":1}');
    expect(canon("line\nbreak\u0001 😀")).toBe('"line\\nbreak\\u0001 😀"');
    expect(canon('quote " and \\ backslash')).toBe('"quote \\" and \\\\ backslash"');
  });

  it("refuses what the rule cannot write, instead of writing something else", () => {
    for (const bad of [4.5, -1, NaN, Infinity, 2 ** 53, undefined, "\uD800", { a: undefined }, new Date(0), 10n, () => 1]) {
      expect(() => canon(bad as unknown), String(bad)).toThrow();
    }
  });

  it("gives the bytes Python's json.dumps gives (the service's side)", () => {
    const values = [
      { version: 1, kind: "checkpoint", nested: { "é": "café-app", a: [0, 9007199254740991] } },
      { ctl: "\u0000\u0007\b\f\n\r\t\u001f\u007f", sep: "  ", astral: "𝄞😀", quote: '"\\' },
      [{ z: 1, Z: 2, _: 3, "10": 4, "9": 5 }],
    ];
    let py: string;
    try {
      py = execFileSync("python3", ["-c", [
        "import json,sys",
        "for v in json.loads(sys.stdin.read()):",
        "    sys.stdout.write(json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\\n')",
      ].join("\n")], { input: JSON.stringify(values), encoding: "utf8" });
    } catch {
      console.warn("python3 not available: the cross-language check did not run");
      return;
    }
    expect(py.trimEnd().split("\n")).toEqual(values.map(canon));
  });
});

describe("the tree (RFC 6962, contract section 1)", () => {
  const leaves = (n: number) => Array.from({ length: n }, (_, i) => leafHash({ kind: "record", hash: sha(`r${i}`) }));

  it("the streaming root equals the recursive one for every size up to 130", () => {
    for (let n = 1; n <= 130; n++) {
      const l = leaves(n);
      const s = new MerkleStream();
      for (const x of l) s.push(x);
      expect(hex(s.root()), `n=${n}`).toBe(hex(mth(l)));
      expect(s.size).toBe(n);
    }
  });

  it("every audit path climbs back to the root, and a path of the wrong length is refused", () => {
    for (let n = 1; n <= 20; n++) {
      const l = leaves(n);
      const root = hex(mth(l));
      for (let m = 0; m < n; m++) expect(hex(rootFromPath(m, n, l[m], auditPath(m, l)))).toBe(root);
    }
    const l = leaves(5);
    expect(() => rootFromPath(0, 5, l[0], auditPath(0, l).slice(1))).toThrow(/too short/);
    expect(() => rootFromPath(0, 1, l[0], [l[1]])).toThrow(/too long/);
  });

  it("an empty tree is refused", () => {
    expect(() => mth([])).toThrow();
    expect(() => new MerkleStream().root()).toThrow();
  });
});

const good = () => ({
  version: 1,
  kind: "checkpoint",
  created_at: "2026-10-03T14:37:11Z",
  records: { from_hash: ZERO, count: 412, head_hash: sha("h"), records_root: sha("r") },
  code: { repos: 39, code_root: sha("c") },
  prev_checkpoint_digest: ZERO,
  client: { name: "opscontext", version: "2.18.0" },
});

describe("the checkpoint's shape (contract section 2.1)", () => {
  it("accepts a well-formed checkpoint, with or without code", () => {
    expect(checkpointProblems(good())).toEqual([]);
    const { code: _code, ...noCode } = good();
    expect(checkpointProblems(noCode)).toEqual([]);
  });

  const broken: Record<string, (c: ReturnType<typeof good>) => void> = {
    "an extra key": (c) => Object.assign(c, { note: "x" }),
    "a count of 0": (c) => { c.records.count = 0; },
    "a count of 4.5": (c) => { c.records.count = 4.5; },
    "version true": (c) => Object.assign(c, { version: true }),
    "uppercase hex": (c) => { c.prev_checkpoint_digest = c.prev_checkpoint_digest.toUpperCase().replace(/0/g, "A"); },
    "code null": (c) => Object.assign(c, { code: null }),
    "a client version of 33 characters": (c) => { c.client.version = "x".repeat(33); },
    "created_at with milliseconds": (c) => { c.created_at = "2026-10-03T14:37:11.000Z"; },
    "a missing key": (c) => { delete (c as Partial<typeof c>).prev_checkpoint_digest; },
    "an extra key inside records": (c) => Object.assign(c.records, { seq: 1 }),
  };
  for (const [what, change] of Object.entries(broken)) {
    it(`refuses ${what}`, () => {
      const c = good();
      change(c);
      expect(checkpointProblems(c)).not.toEqual([]);
    });
  }

  it("refuses a body over 4096 bytes", () => {
    expect(checkpointProblems(good(), 4097)).not.toEqual([]);
  });

  it("the digest is taken over the canonical form, whatever the key order", () => {
    const c = good();
    const reversed = Object.fromEntries(Object.entries(c).reverse());
    expect(digestOf(reversed)).toBe(digestOf(c));
    expect(digestOf(JSON.parse(JSON.stringify(c, null, 7)))).toBe(digestOf(c));
  });
});

describe("customer and hour (contract sections 3.1 and 4)", () => {
  it("customer is SHA-256 of the credential", () => {
    expect(customerOf("CE-1234-5678-9ABC-DEF0")).toBe(sha("CE-1234-5678-9ABC-DEF0"));
  });

  it("a receipt's hour is the first minute-2 cut-off after it arrived", () => {
    expect(hourOf("2026-10-03T14:02:12Z")).toBe("2026-10-03T15Z");
    expect(hourOf("2026-10-03T14:02:00Z")).toBe("2026-10-03T15Z");
    expect(hourOf("2026-10-03T14:01:59Z")).toBe("2026-10-03T14Z");
    expect(hourOf("2026-12-31T23:59:59Z")).toBe("2027-01-01T00Z");
    expect(() => hourOf("2026-10-03T14:02:12.000Z")).toThrow();
  });
});

describe("the receipt check (contract section 6)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const digest = sha("checkpoint");
  const customer = customerOf("pilot-" + "ab".repeat(32));
  const signed = (body: Record<string, unknown>) => ({ ...body, signature: sign(null, Buffer.from(canon(body), "utf8"), privateKey).toString("base64") });
  const body = () => ({ version: 1, kind: "receipt", checkpoint_digest: digest, customer, received_at: "2026-10-03T14:37:12Z", hour: "2026-10-03T15Z", key_id: "sealhour-2026-10" });

  it("accepts a receipt signed over its canonical JSON", () => {
    expect(receiptProblems(signed(body()), { publicKeyPem: pem, digest, customer })).toEqual([]);
  });

  it("refuses another digest, another customer, a wrong hour, a path as key name, a changed field", () => {
    expect(receiptProblems(signed(body()), { publicKeyPem: pem, digest: sha("other"), customer })).toContain("checkpoint_digest is not this checkpoint's");
    expect(receiptProblems(signed(body()), { publicKeyPem: pem, digest, customer: sha("x") })).toContain("customer is not this client's");
    expect(receiptProblems(signed({ ...body(), hour: "2026-10-03T16Z" }), { publicKeyPem: pem })).toContain("hour is not the cut-off of received_at");
    expect(receiptProblems(signed({ ...body(), key_id: "../keys/x" }), { publicKeyPem: pem })).toContain("key_id is not 1 to 64 of [a-z0-9-]");
    const r = signed(body());
    expect(receiptProblems({ ...r, received_at: "2026-10-03T14:37:59Z" }, { publicKeyPem: pem })).toContain("signature does not verify under the pinned key");
  });
});

// ---------- the fixture, read in place ----------

const FIX = process.env.SEALHOUR_FIXTURE_DIR ?? "";
const haveFixture = FIX !== "" && existsSync(join(FIX, "clients"));
const fx = (p: string) => join(FIX, p);
const fxJson = <T = Record<string, unknown>>(p: string): T => JSON.parse(readFileSync(fx(p), "utf8")) as T;

/** The credentials and pseudonyms of the fixture's README table, read at run time. */
function readmeCustomers(): Array<{ credential: string; customer: string }> {
  const text = readFileSync(fx("README.md"), "utf8");
  const ticks = (row: RegExp) => [...(text.match(row)?.[0] ?? "").matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  const creds = ticks(/^\| Credential \|.*$/m);
  const custs = ticks(/^\| `customer` \(SHA-256 of the credential\) \|.*$/m).filter((v) => /^[0-9a-f]{64}$/.test(v));
  return creds.map((credential, i) => ({ credential, customer: custs[i] }));
}

/** The window of a checkpoint in a one-file log: the `count` records after `from_hash`. */
function windowOf(log: string, from: string, count: number): string[] {
  const hashes = readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => (JSON.parse(l) as { hash: string }).hash);
  const start = from === ZERO ? 0 : hashes.indexOf(from) + 1;
  return hashes.slice(start, start + count);
}

describe.skipIf(!haveFixture)("the SealHour protocol v1 fixture, read in place (SEALHOUR_FIXTURE_DIR)", () => {
  const pairs = [
    ["customer-a", 1],
    ["customer-a", 2],
    ["customer-b", 1],
  ] as const;

  it("customer = SHA-256 of each credential of the fixture's README, and every receipt carries it", () => {
    const table = readmeCustomers();
    expect(table.length).toBe(2);
    for (const { credential, customer } of table) expect(customerOf(credential)).toBe(customer);
    expect(fxJson("clients/customer-a/receipt-1.json").customer).toBe(table[0].customer);
    expect(fxJson("clients/customer-a/receipt-2.json").customer).toBe(table[0].customer);
    expect(fxJson("clients/customer-b/receipt-1.json").customer).toBe(table[1].customer);
  });

  for (const [who, n] of pairs) {
    it(`${who} checkpoint ${n}: the shape holds, the digest is the receipt's, the window gives records_root`, () => {
      const cp = fxJson<Record<string, unknown> & { records: { from_hash: string; count: number; head_hash: string; records_root: string } }>(`clients/${who}/checkpoint-${n}.json`);
      const rc = fxJson(`clients/${who}/receipt-${n}.json`);
      expect(checkpointProblems(cp, Buffer.byteLength(canon(cp)))).toEqual([]);
      expect(digestOf(cp)).toBe(rc.checkpoint_digest);
      const win = windowOf(fx(`clients/${who}/audit.jsonl`), cp.records.from_hash, cp.records.count);
      expect(win.length).toBe(cp.records.count);
      expect(win[win.length - 1]).toBe(cp.records.head_hash);
      expect(recordsRoot(win)).toBe(cp.records.records_root);
    });

    it(`${who} receipt ${n}: signed over the canonical JSON, under the fixture key`, () => {
      const rc = fxJson(`clients/${who}/receipt-${n}.json`);
      const key = readFileSync(fx(`keys/${String(rc.key_id)}.pub`));
      const cp = fxJson(`clients/${who}/checkpoint-${n}.json`);
      expect(receiptProblems(rc, { publicKeyPem: key, digest: digestOf(cp) })).toEqual([]);
    });
  }

  it("customer A's second checkpoint chains to the first, and its code root is the leaves' root", () => {
    const a1 = fxJson("clients/customer-a/checkpoint-1.json");
    const a2 = fxJson<{ prev_checkpoint_digest: string; code: { repos: number; code_root: string } }>("clients/customer-a/checkpoint-2.json");
    expect(a2.prev_checkpoint_digest).toBe(digestOf(a1));
    const leaves = fxJson<CodeLeaf[]>("clients/customer-a/code-leaves-2.json");
    expect(sortCodeLeaves(leaves)).toEqual(leaves); // the stored order is the checkpoint order
    expect(leaves.some((l) => /[^\x00-\x7f]/.test(l.repo))).toBe(true); // a name that is not ASCII
    expect(a2.code.repos).toBe(leaves.length);
    expect(codeRoot(leaves)).toBe(a2.code.code_root);
  });

  it("the side-branch record of customer A is inside its window, covered by its own leaf", () => {
    const recs = readFileSync(fx("clients/customer-a/audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { hash: string; prev_hash: string });
    const prevs = new Set(recs.map((r) => r.prev_hash));
    const tips = recs.filter((r) => !prevs.has(r.hash));
    expect(tips.length).toBe(2); // the head and the dead branch
    const a2 = fxJson<{ records: { from_hash: string; count: number } }>("clients/customer-a/checkpoint-2.json");
    const win = windowOf(fx("clients/customer-a/audit.jsonl"), a2.records.from_hash, a2.records.count);
    for (const t of tips) expect(win).toContain(t.hash);
  });
});
