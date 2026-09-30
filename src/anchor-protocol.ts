// SealHour protocol version 1, the client's half of the contract (COMPR-TSA docs/SEALHOUR_PROTOCOL.md,
// fixed 2026-09-30): the hashing rule (section 1), the checkpoint's shape and digest (section 2), the
// customer pseudonym (section 4) and the receipt check (section 6). Pure functions, no file and no network.
//
// [LOCKED] [SEALHOUR-PROTOCOL-V1-BYTES] - 2026-09-30
// [NEVER] change canon(), leafHash(), nodeHash(), mth(), MerkleStream, auditPath(), rootFromPath() or
//         digestOf(), and never "tidy" the key order, the escaping or the integer rule of canon().
// WHY: these are the bytes of protocol version 1, shared with the SealHour service (Python, COMPR-TSA
//      trial/sealhour.py canon() and mth()) and with every verifier a customer or an auditor runs. A
//      checkpoint digest, a receipt signature and every stamp hang on them: one byte of difference and
//      every proof made before the change stops verifying, silently, on the other side.
// FIX: a new rule is protocol version 2 (a new section in the contract, a new fixture, both code bases
//      changed together), never an edit here. The fixture test (tests/anchor-protocol.test.ts) and the
//      Python cross-check pin these bytes.
import { createHash, createPublicKey, verify as cryptoVerify } from "crypto";

export const PROTOCOL_VERSION = 1;
/** OpsContext's genesis value: no record before, no checkpoint before. */
export const ZERO = "0".repeat(64);
export const TREE_RULE = "RFC 6962 SHA-256; leaf = SHA-256(0x00 || canonical JSON), node = SHA-256(0x01 || left || right)";
/** Largest body SealHour accepts (section 2.1). */
export const MAX_CHECKPOINT_BYTES = 4096;

const HEX64 = /^[0-9a-f]{64}$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Canonical JSON (section 1): keys sorted by code point (UTF-8 byte order), no whitespace, strings
 * escaped as JSON requires and no more, integers 0 to 2^53 - 1 only. Within these limits it is RFC 8785
 * and Python's json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False). Anything
 * outside them throws: a value this rule cannot write must never be hashed as something else.
 */
export function canon(v: unknown): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error(`canonical JSON takes integers 0 to 2^53 - 1 only, not ${v}`);
    return String(v);
  }
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Error("canonical JSON takes valid Unicode only (a lone surrogate)");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
    return `{${keys.map((k) => {
      if (o[k] === undefined) throw new Error(`canonical JSON has no undefined (key ${k})`);
      return `${canon(k)}:${canon(o[k])}`;
    }).join(",")}}`;
  }
  throw new Error(`canonical JSON cannot write a ${typeof v}`);
}

export function canonBytes(v: unknown): Buffer {
  return Buffer.from(canon(v), "utf8");
}

export function sha256(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);

export function leafHash(obj: unknown): Buffer {
  return sha256(LEAF, canonBytes(obj));
}

export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE, left, right);
}

/** Largest power of two strictly below n (n >= 2). */
export function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** RFC 6962 Merkle tree hash. A tree has at least one leaf. */
export function mth(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) throw new Error("a Merkle tree needs at least one leaf");
  if (hashes.length === 1) return hashes[0];
  const k = splitPoint(hashes.length);
  return nodeHash(mth(hashes.slice(0, k)), mth(hashes.slice(k)));
}

/**
 * The same root as mth(), one leaf at a time, in O(log n) memory: the complete subtrees of the
 * binary decomposition of n, merged from the right at the end. A window can hold the whole history
 * (5 million records on the author's machine), which must never sit in one array.
 */
export class MerkleStream {
  private stack: Array<{ size: number; hash: Buffer }> = [];
  private n = 0;

  push(leaf: Buffer): void {
    let node = { size: 1, hash: leaf };
    while (this.stack.length > 0 && this.stack[this.stack.length - 1].size === node.size) {
      const left = this.stack.pop()!;
      node = { size: left.size * 2, hash: nodeHash(left.hash, node.hash) };
    }
    this.stack.push(node);
    this.n++;
  }

  get size(): number {
    return this.n;
  }

  root(): Buffer {
    if (this.n === 0) throw new Error("a Merkle tree needs at least one leaf");
    let acc = this.stack[this.stack.length - 1].hash;
    for (let i = this.stack.length - 2; i >= 0; i--) acc = nodeHash(this.stack[i].hash, acc);
    return acc;
  }
}

/** RFC 6962 audit path of leaf m: the siblings from the bottom of the tree to the top. */
export function auditPath(m: number, hashes: Buffer[]): Buffer[] {
  if (hashes.length === 1) return [];
  const k = splitPoint(hashes.length);
  if (m < k) return [...auditPath(m, hashes.slice(0, k)), mth(hashes.slice(k))];
  return [...auditPath(m - k, hashes.slice(k)), mth(hashes.slice(0, k))];
}

/** The root a leaf and its audit path give; throws on a path too long or too short for m and n. */
export function rootFromPath(m: number, n: number, leaf: Buffer, path: Buffer[]): Buffer {
  if (n === 1) {
    if (path.length) throw new Error("path too long");
    return leaf;
  }
  if (!path.length) throw new Error("path too short");
  const k = splitPoint(n);
  const rest = path.slice(0, -1);
  const sibling = path[path.length - 1];
  return m < k ? nodeHash(rootFromPath(m, k, leaf, rest), sibling) : nodeHash(sibling, rootFromPath(m - k, n - k, leaf, rest));
}

/**
 * The leaf of one audit record (section 2.2): its hash field only, so a redaction breaks no proof.
 * A 64-hex hash needs no escaping, so its canonical JSON is written directly (the history holds
 * millions of records); anything else goes through canon(). The test pins the two paths together.
 */
export function recordLeaf(hash: string): Buffer {
  if (HEX64.test(hash)) return sha256(LEAF, Buffer.from(`{"hash":"${hash}","kind":"record"}`, "utf8"));
  return leafHash({ kind: "record", hash });
}

export function recordsRoot(hashes: string[]): string {
  return mth(hashes.map(recordLeaf)).toString("hex");
}

/** One repository's code leaf (section 2.3), the trial's git leaf unchanged. */
export interface CodeLeaf {
  kind: "git";
  repo: string;
  commit: string;
  files: number;
  files_sha256: string;
}

/** The code leaves in checkpoint order: by repo (UTF-8 byte order), then commit. */
export function sortCodeLeaves(leaves: CodeLeaf[]): CodeLeaf[] {
  return [...leaves].sort((a, b) =>
    Buffer.compare(Buffer.from(a.repo, "utf8"), Buffer.from(b.repo, "utf8")) || (a.commit < b.commit ? -1 : a.commit > b.commit ? 1 : 0),
  );
}

export function codeRoot(leaves: CodeLeaf[]): string {
  return mth(leaves.map(leafHash)).toString("hex");
}

export interface Checkpoint {
  version: 1;
  kind: "checkpoint";
  created_at: string;
  records: { from_hash: string; count: number; head_hash: string; records_root: string };
  code?: { repos: number; code_root: string };
  prev_checkpoint_digest: string;
  client: { name: "opscontext"; version: string };
}

/** A checkpoint from its window and the rest of section 2.1; `code` only when the owner said yes. */
export function makeCheckpoint(
  w: { from_hash: string; count: number; head_hash: string; records_root: string },
  o: { created_at: string; prev: string; clientVersion: string; code?: { repos: number; code_root: string } },
): Checkpoint {
  const cp: Checkpoint = {
    version: 1,
    kind: "checkpoint",
    created_at: o.created_at,
    records: { from_hash: w.from_hash, count: w.count, head_hash: w.head_hash, records_root: w.records_root },
    prev_checkpoint_digest: o.prev,
    client: { name: "opscontext", version: o.clientVersion },
  };
  if (o.code) cp.code = { repos: o.code.repos, code_root: o.code.code_root };
  return cp;
}

/** checkpoint_digest (section 2.4): SHA-256 of the canonical JSON of the whole checkpoint, hex. */
export function digestOf(obj: unknown): string {
  return sha256(canonBytes(obj)).toString("hex");
}

const isHex64 = (v: unknown): v is string => typeof v === "string" && HEX64.test(v);
const isCount = (v: unknown): boolean => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
const hasExactly = (o: unknown, keys: string[]): o is Record<string, unknown> =>
  typeof o === "object" && o !== null && !Array.isArray(o) &&
  Object.keys(o).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));

/**
 * Why SealHour would answer 400 to this checkpoint (section 2.1, the trial's checkpoint_problems());
 * empty when it is fine. The client checks its own checkpoints with it and never keeps one that fails.
 * A JSON text with a count written 4.0 parses to 4 in JavaScript: that textual case is the server's.
 */
export function checkpointProblems(cp: unknown, size = 0): string[] {
  const top = ["client", "created_at", "kind", "prev_checkpoint_digest", "records", "version"];
  if (typeof cp !== "object" || cp === null || Array.isArray(cp)) return ["keys are not exactly those of protocol version 1"];
  const o = cp as Record<string, unknown>;
  if (Object.keys(o).filter((k) => k !== "code").sort().join() !== top.join()) return ["keys are not exactly those of protocol version 1"];
  const rec = o.records as Record<string, unknown>;
  const code = "code" in o ? o.code : { repos: 1, code_root: ZERO };
  const client = o.client as Record<string, unknown>;
  const rules: Array<[boolean, string]> = [
    [size <= MAX_CHECKPOINT_BYTES, `larger than ${MAX_CHECKPOINT_BYTES} bytes`],
    [o.version === 1, "version is not 1"],
    [o.kind === "checkpoint", "kind is not checkpoint"],
    [typeof o.created_at === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(o.created_at), "created_at is not YYYY-MM-DDTHH:MM:SSZ"],
    [hasExactly(rec, ["from_hash", "count", "head_hash", "records_root"]) && isCount(rec.count) &&
      isHex64(rec.from_hash) && isHex64(rec.head_hash) && isHex64(rec.records_root),
    "records is not from_hash, count (1 or more), head_hash, records_root"],
    [hasExactly(code, ["repos", "code_root"]) && isCount((code as Record<string, unknown>).repos) && isHex64((code as Record<string, unknown>).code_root),
      "code is not repos (1 or more), code_root"],
    [isHex64(o.prev_checkpoint_digest), "prev_checkpoint_digest is not 64 lowercase hex"],
    [hasExactly(client, ["name", "version"]) && client.name === "opscontext" && typeof client.version === "string" &&
      /^[ -~]{1,32}$/.test(client.version), "client is not name opscontext, version of 1 to 32 ASCII"],
  ];
  return rules.filter(([ok]) => !ok).map(([, why]) => why);
}

/** created_at: UTC to the second, `YYYY-MM-DDTHH:MM:SSZ`. */
export function isoSecond(d: Date): string {
  return d.toISOString().slice(0, 19) + "Z";
}

/**
 * The customer's pseudonym (section 4): SHA-256 of the credential it presents (licence key or pilot
 * token), hex. [LOCK] [CUSTOMER_IS_NOT_THE_ROW_ID] (COMPR-TSA): never the licence server's row number.
 */
export function customerOf(credential: string): string {
  return sha256(Buffer.from(credential, "utf8")).toString("hex");
}

/** The hour a receipt names (section 3.1): the first minute-2 cut-off after `received_at`. */
export function hourOf(receivedAt: string): string {
  const t = Date.parse(receivedAt);
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(receivedAt) || Number.isNaN(t)) throw new Error(`not a UTC time to the second: ${receivedAt}`);
  return new Date(t + 58 * 60_000).toISOString().slice(0, 13) + "Z";
}

export const RECEIPT_KEYS = ["checkpoint_digest", "customer", "hour", "key_id", "kind", "received_at", "version"];

/**
 * Every rule of section 6 for a receipt, given the pinned public key (PEM, SubjectPublicKeyInfo):
 * exact keys, a valid Ed25519 signature over the canonical JSON without `signature`, and, when given,
 * the client's own digest and customer. Empty when the receipt holds. Used by the SealHour backend
 * (step 3); pinned now by the fixture.
 */
export function receiptProblems(
  receipt: unknown,
  opts: { publicKeyPem: string | Buffer; digest?: string; customer?: string },
): string[] {
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return ["not an object"];
  const { signature, ...body } = receipt as Record<string, unknown>;
  const out: string[] = [];
  if (!hasExactly(body, RECEIPT_KEYS)) out.push("keys are not exactly those of a version 1 receipt");
  if (body.version !== 1 || body.kind !== "receipt") out.push("not a version 1 receipt");
  if (typeof body.key_id !== "string" || !/^[a-z0-9-]{1,64}$/.test(body.key_id)) out.push("key_id is not 1 to 64 of [a-z0-9-]");
  if (typeof signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) out.push("signature is not 64 bytes in base64");
  else {
    let good = false;
    try {
      good = cryptoVerify(null, canonBytes(body), createPublicKey(opts.publicKeyPem), Buffer.from(signature, "base64"));
    } catch {
      good = false;
    }
    if (!good) out.push("signature does not verify under the pinned key");
  }
  if (!isHex64(body.checkpoint_digest) || (opts.digest !== undefined && body.checkpoint_digest !== opts.digest)) out.push("checkpoint_digest is not this checkpoint's");
  if (!isHex64(body.customer) || (opts.customer !== undefined && body.customer !== opts.customer)) out.push("customer is not this client's");
  let hour: string | null = null;
  try { hour = hourOf(String(body.received_at)); } catch { out.push("received_at is not a UTC time to the second"); }
  if (hour !== null && body.hour !== hour) out.push("hour is not the cut-off of received_at");
  return out;
}
