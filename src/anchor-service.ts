// The SealHour backend's network half (COMPR-TSA docs/SEALHOUR_PROTOCOL.md sections 4 to 6; plan
// docs/SEALHOUR_INTEGRATION_PLAN.md section 6, step 3): the checkpoint goes to the SealHour service with
// the owner's credential, a signed receipt comes back, and once the hour is sealed its proof bundle is
// fetched. With the interim backend (src/anchor-tsa.ts) this is the only module of the SealHour client
// that opens a network connection.
//
// [LOCKED] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY] - 2026-10-05
// [NEVER] send the SealHour service anything but the checkpoint of contract section 2 (canonical JSON)
//         and the credential in the Authorization header of that one request; never send the credential
//         with a GET of a receipt or a proof (the digest is the capability there), to another host, or
//         after a redirect; never write it into a checkpoint folder, a report, an error line, the audit
//         log or the copy off the machine; and never let a test hook point the client at a host that is
//         not this machine.
// WHY: the enable screen promises the owner exactly that (contract section 10, correction 7): a few
//      fingerprints, two numbers and a time, with the licence key, and nothing else. The licence key is
//      the customer's credential: whoever reads it can activate the product. The code leaves name
//      repositories and stay here (section 2.3). A header added "for debugging", a redirect followed or
//      an override pointing at another server would break the promise silently: the seal would still
//      verify.
// FIX: one function builds each request; the body is canon(checkpoint) and nothing else; no redirect is
//      followed (Node's http never does); the service's address is one constant, replaced only by a
//      loopback stand-in for tests, which every status line then names as a test. A test captures what
//      the service receives and compares it byte for byte (tests/anchor-service.test.ts).
//
// [LOCKED] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY] - 2026-10-05
// [NEVER] store an answer as a receipt, or call a checkpoint received, before receiptProblems() passed
//         under a key pinned in this file for the receipt's key_id; never take the key from the answer,
//         from a proof bundle's keys/ folder, from ~/.contextengine or from an environment variable.
// WHY: a receipt is SealHour's signed word that it holds the checkpoint off this machine (workplan 2,
//      correction 1). An answer is only bytes from the network: an error page, a proxy's answer, another
//      customer's receipt or one signed by any key at all would all parse. A key read from the same
//      place as the receipt proves nothing (the free checker's LOCK ANCHOR_IN_THE_FOLDER_IS_NOT_TRUST).
// FIX: RECEIPT_KEYS below, pinned as the licence public key is (src/license-sig.ts); a receipt under
//      any other key id is an error, reported and never stored. A new SealHour key ships as a new entry
//      in a new version of OpsContext; old entries stay as long as receipts signed with them are kept.
import http from "http";
import https from "https";
import { createHash, createPublicKey, randomBytes, X509Certificate } from "crypto";
import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, writeSync, constants } from "fs";
import { join } from "path";
import { homedir } from "os";
import { canonBytes, customerOf, digestOf, receiptProblems, type Checkpoint } from "./anchor-protocol.js";

/** The SealHour service (contract section 5). Every path below it starts with /v1/. */
export const SEALHOUR_URL = "https://api.sealhour.com";

export interface ReceiptKey {
  /** The receipt's key_id. */
  id: string;
  /** PEM, SubjectPublicKeyInfo (Ed25519). */
  pem: string;
}

/**
 * The keys SealHour signs receipts with. `sealhour-2026-10` was made on the SealHour server on
 * 2026-10-02; its 32 bytes are 7538476ce95a13f958815b2af78457277b788a22680a695cbe2c4aecc1524104, the
 * file published at https://sealhour.com/keys/sealhour-2026-10.pub (read on 2026-10-05: these bytes).
 * [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY]
 */
export const RECEIPT_KEYS: readonly ReceiptKey[] = [
  {
    id: "sealhour-2026-10",
    pem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAdThHbOlaE/lYgVsq94RXJ3t4iiJoCmlcvixK7MFSQQQ=
-----END PUBLIC KEY-----
`,
  },
];

/**
 * The certificates an official stamp of a sealed hour must be made under: SHA-256 of each certificate
 * (DER). They are the certificates of the official European provider's time stamp services, as the EU
 * trusted list of its country names them (read on 2026-10-02); the list, and how it was read, live with
 * the SealHour service (COMPR-TSA service/sealhour_verify.py, KNOWN_ANCHORS: the free checker pins the
 * same five). A proof bundle carries the certificate itself; it counts only when its fingerprint is here.
 * [LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE] in src/anchor-bundle.ts
 */
export const STAMP_ANCHORS: readonly string[] = [
  "9a2451da060f0577b30df516ff6ee277406b3911d15bfc1a9cafc31c349ed864", // valid 2017-05-18 to 2028-05-18
  "063d3908bccdc014ce5f2341c87a2157ffa5bc94d8860c8f934426197249790c", // valid 2017-06-05 to 2028-06-05
  "f340d93532ff69d90607a491f4039fa3d083e528d8f8631867c25a231b14d2ce", // valid 2019-08-05 to 2030-08-05
  "47f67cf54bd65d728ef171222e6ba0b76b7c83ba1e18863586ccf3f72b03babc", // valid 2019-08-05 to 2030-08-05
  "c587f9039588dabf969a897a41db8cd4c97b9f847afec547b7fa9eaeb066f29a", // valid 2023-09-15 to 2034-09-15
];

export interface Service {
  url: string;
  keys: readonly ReceiptKey[];
  /** SHA-256 fingerprints (hex) of the certificates a stamp may be made under. */
  anchors: readonly string[];
  /** A stand-in on this machine, for tests: never called SealHour in a status line. */
  test: boolean;
}

/** SHA-256 fingerprints (hex, of the DER) of every certificate in a PEM file; throws when one does not parse. */
export function certFingerprints(pem: string | Buffer): string[] {
  const text = typeof pem === "string" ? pem : pem.toString("latin1");
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((b) => createHash("sha256").update(new X509Certificate(b).raw).digest("hex"));
}

/** The 32 bytes of an Ed25519 public key (PEM), hex: what https://sealhour.com/keys/ shows for it. */
export function publicKeyHex(pem: string | Buffer): string {
  return createPublicKey(pem).export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
}

/**
 * The service in use: the pinned one, or, for tests only, a stand-in on this machine given as JSON in
 * CONTEXTENGINE_SEALHOUR_TEST ({url, keys: [{id, file}], anchors: [certificate files]}). A stand-in
 * whose address is not on the loopback is refused, and it replaces the keys and certificates whole: a
 * receipt of the real service never verifies in test mode, nor a test one outside it.
 * [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY]
 */
export function activeService(): Service {
  const raw = process.env.CONTEXTENGINE_SEALHOUR_TEST;
  if (!raw) return { url: SEALHOUR_URL, keys: RECEIPT_KEYS, anchors: STAMP_ANCHORS, test: false };
  let o: { url?: unknown; keys?: unknown; anchors?: unknown };
  try {
    o = JSON.parse(raw);
  } catch {
    throw new Error("CONTEXTENGINE_SEALHOUR_TEST is not JSON");
  }
  const url = new URL(String(o.url));
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error(`test service refused: ${url.origin} is not this machine`);
  }
  const keys = (Array.isArray(o.keys) ? o.keys : []).map((k: { id?: unknown; file?: unknown }) => {
    const id = String(k.id);
    if (!/^[a-z0-9-]{1,64}$/.test(id)) throw new Error(`test key id refused: ${id}`);
    return { id, pem: readFileSync(String(k.file), "utf8") };
  });
  const anchors = (Array.isArray(o.anchors) ? o.anchors : []).flatMap((f: unknown) => certFingerprints(readFileSync(String(f))));
  return { url: url.origin, keys, anchors, test: true };
}

/** How a status line names the service in use: "SealHour", or what it really is in a test. */
export const serviceName = (s: Service): string => (s.test ? `SealHour TEST stand-in (${new URL(s.url).host}, not the SealHour service)` : "SealHour");

// ---------- the credential (contract section 4) ----------

export const LICENCE_KEY = /^CE-[0-9A-F]{4}(-[0-9A-F]{4}){3}$/;
export const PILOT_TOKEN = /^pilot-[0-9a-f]{64}$/;

function ceHome(): string {
  return process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine");
}
const pilotTokenPath = () => join(ceHome(), "anchors", "pilot-token");

/** The pilot token kept with the anchors, or null. Never shown: callers pass it to postCheckpoint() only. */
export function readPilotToken(): string | null {
  try {
    const t = readFileSync(pilotTokenPath(), "utf8").trim();
    return PILOT_TOKEN.test(t) ? t : null;
  } catch {
    return null;
  }
}

/** Make the pilot token once (32 random bytes), readable by the owner alone; an existing one is kept. */
export function ensurePilotToken(): void {
  if (readPilotToken()) return;
  mkdirSync(join(ceHome(), "anchors"), { recursive: true, mode: 0o700 });
  const path = pilotTokenPath();
  const fd = openSync(path, constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY, 0o600);
  try { writeSync(fd, `pilot-${randomBytes(32).toString("hex")}\n`); } finally { closeSync(fd); }
  chmodSync(path, 0o600);
}

export const hasPilotToken = (): boolean => readPilotToken() !== null;

// ---------- the requests ----------

export interface Answer {
  status: number;
  /** Seconds, from Retry-After, when the service gave a whole number. */
  retryAfterS: number | null;
  /** The body parsed as JSON; null when it is not JSON. */
  body: unknown;
}

const MAX_ANSWER_BYTES = 24 * 1024 * 1024; // a proof bundle is a few kilobytes; the free checker stops at 16 MB of files

/**
 * One request to the service; the answer whatever its status, or a plain-words error when none came.
 * Node's default agent, so an owner behind a proxy can route it with NODE_USE_ENV_PROXY=1, and the
 * connection is kept between the few requests of one run. Never follows a redirect.
 * [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY]
 */
function call(service: Service, method: "GET" | "POST", path: string, o: { credential?: string; body?: Buffer; timeoutMs?: number }): Promise<Answer> {
  const u = new URL(path, service.url);
  const mod = u.protocol === "https:" ? https : http;
  const timeoutMs = o.timeoutMs ?? 20_000;
  const headers: Record<string, string | number> = { "User-Agent": "opscontext-anchor", Accept: "application/json" };
  if (o.body) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = o.body.length;
  }
  if (o.credential) headers.Authorization = `Bearer ${o.credential}`;
  return new Promise((resolve, reject) => {
    const req = mod.request(u, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_ANSWER_BYTES) req.destroy(new Error("the answer is larger than a proof can be"));
        else chunks.push(c);
      });
      res.on("error", () => reject(new Error("the answer was cut short")));
      res.on("close", () => { if (!res.complete) reject(new Error("the answer was cut short")); });
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        // A body shorter than announced is a cut connection, never a short answer (measured on
        // 2026-10-04 from a filtered network: reads above 16 KB came back cut, with the code 200).
        const announced = Number(res.headers["content-length"]);
        if (Number.isInteger(announced) && announced !== raw.length) {
          reject(new Error("the answer was cut short"));
          return;
        }
        let body: unknown = null;
        try { body = JSON.parse(raw.toString("utf8")); } catch { body = null; }
        const ra = String(res.headers["retry-after"] ?? "");
        resolve({ status: res.statusCode ?? 0, retryAfterS: /^\d{1,6}$/.test(ra) ? Number(ra) : null, body });
      });
    });
    const timer = setTimeout(() => req.destroy(new Error(`no answer within ${Math.round(timeoutMs / 1000)} s`)), timeoutMs);
    req.on("close", () => clearTimeout(timer));
    req.on("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      if (e.code === "ECONNREFUSED") reject(new Error("connection refused"));
      else if (e.code === "ENOTFOUND" || e.code === "EAI_AGAIN") reject(new Error("its address could not be found (no network?)"));
      else if (e.code === "ECONNRESET" || e.code === "EPIPE") reject(new Error("the connection was cut"));
      else reject(new Error(String(e.message || e.code || "no answer").slice(0, 120)));
    });
    req.end(o.body);
  });
}

/** The service's own line, as the contract promises it ({"error": "<one line in English>"}), made safe to print. */
function errorLine(a: Answer): string {
  const line = a.body && typeof a.body === "object" && typeof (a.body as { error?: unknown }).error === "string" ? (a.body as { error: string }).error : "";
  const clean = line.replace(/[^\x20-\x7e]/g, " ").trim().slice(0, 200);
  return clean || `HTTP ${a.status}`;
}

export type Receipt = Record<string, unknown> & { checkpoint_digest: string; customer: string; received_at: string; hour: string; key_id: string; signature: string };

export type PostOutcome =
  /** 201 or 200, and the receipt passed every rule of section 6 under a pinned key. */
  | { kind: "receipt"; receipt: Receipt; created: boolean }
  /** 201 or 200, but what came is not a receipt this client may keep. */
  | { kind: "bad-receipt"; problems: string[] }
  /** 400 and 409: never retried. 401 and 403: retried once a day. `line` is the service's, word for word. */
  | { kind: "refused"; status: number; line: string; retry: "never" | "daily" }
  /** 429, 5xx, or no answer: queued, retried with backoff (`waitS` when the service said how long). */
  | { kind: "later"; status: number | null; line: string; waitS: number | null };

/** The pinned key for a receipt's key_id, or null. */
export function receiptKey(service: Service, keyId: unknown): ReceiptKey | null {
  return service.keys.find((k) => k.id === keyId) ?? null;
}

/**
 * Why this is not a receipt for this checkpoint and this credential that the client may keep; empty when
 * it is. Every rule of section 6. [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY]
 */
export function receiptRefusals(service: Service, receipt: unknown, o: { digest: string; customer?: string }): string[] {
  const keyId = receipt && typeof receipt === "object" ? (receipt as { key_id?: unknown }).key_id : undefined;
  const key = receiptKey(service, keyId);
  if (!key) {
    const shown = typeof keyId === "string" && /^[a-z0-9-]{1,64}$/.test(keyId) ? keyId : "(unreadable)";
    return [`signed under a key this version of OpsContext does not know (${shown}): update OpsContext, or compare with https://sealhour.com/keys/`];
  }
  return receiptProblems(receipt, { publicKeyPem: key.pem, digest: o.digest, customer: o.customer });
}

/**
 * POST /v1/checkpoints (section 5.1). The body is the canonical JSON of the checkpoint, nothing else.
 * Never throws. [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY]
 */
export async function postCheckpoint(service: Service, cp: Checkpoint, credential: string, o: { timeoutMs?: number } = {}): Promise<PostOutcome> {
  let a: Answer;
  try {
    a = await call(service, "POST", "/v1/checkpoints", { credential, body: canonBytes(cp), timeoutMs: o.timeoutMs });
  } catch (e) {
    return { kind: "later", status: null, line: `${serviceName(service)} did not answer (${(e as Error).message})`, waitS: null };
  }
  if (a.status === 201 || a.status === 200) {
    const problems = receiptRefusals(service, a.body, { digest: digestOf(cp), customer: customerOf(credential) });
    if (problems.length > 0) return { kind: "bad-receipt", problems };
    return { kind: "receipt", receipt: a.body as Receipt, created: a.status === 201 };
  }
  const line = errorLine(a);
  if (a.status === 400 || a.status === 409) return { kind: "refused", status: a.status, line, retry: "never" };
  if (a.status === 401 || a.status === 403) return { kind: "refused", status: a.status, line, retry: "daily" };
  return { kind: "later", status: a.status, line, waitS: a.retryAfterS };
}

export type ProofOutcome =
  /** 200: the bundle as served ({version, kind, checkpoint_digest, files}); src/anchor-bundle.ts reads it. */
  | { kind: "bundle"; bundle: unknown }
  /** 202: the hour is not sealed yet, or its official stamp has not come yet. Ask again later. */
  | { kind: "pending"; hour: string | null; why: string }
  /** 410: the hour was missed. This checkpoint will never have a proof of its own (section 2.4). */
  | { kind: "missed"; line: string }
  /** 404: the service does not know this digest. */
  | { kind: "unknown"; line: string }
  | { kind: "later"; status: number | null; line: string; waitS: number | null };

/** GET /v1/proofs/<digest> (section 5.3), without a credential: the digest is the capability. Never throws. */
export async function getProof(service: Service, digest: string, o: { timeoutMs?: number } = {}): Promise<ProofOutcome> {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("a proof is asked by a 64-hex checkpoint digest");
  let a: Answer;
  try {
    a = await call(service, "GET", `/v1/proofs/${digest}`, { timeoutMs: o.timeoutMs });
  } catch (e) {
    return { kind: "later", status: null, line: `${serviceName(service)} did not answer (${(e as Error).message})`, waitS: null };
  }
  if (a.status === 200) return a.body && typeof a.body === "object" ? { kind: "bundle", bundle: a.body } : { kind: "later", status: 200, line: "the answer is not a proof bundle", waitS: null };
  if (a.status === 202) {
    const b = (a.body ?? {}) as { hour?: unknown; why?: unknown };
    const hour = typeof b.hour === "string" && /^\d{4}-\d\d-\d\dT\d\dZ$/.test(b.hour) ? b.hour : null;
    const why = typeof b.why === "string" ? b.why.replace(/[^\x20-\x7e]/g, " ").trim().slice(0, 120) : "";
    return { kind: "pending", hour, why: why || "not ready yet" };
  }
  if (a.status === 410) return { kind: "missed", line: errorLine(a) };
  if (a.status === 404) return { kind: "unknown", line: errorLine(a) };
  return { kind: "later", status: a.status, line: errorLine(a), waitS: a.retryAfterS };
}
