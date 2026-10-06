// A proof bundle as the SealHour service serves it (COMPR-TSA docs/SEALHOUR_PROTOCOL.md sections 5.3, 7.1
// and 7.2): read from the answer, written under the contract's fixed names only, and checked here before
// an hour is ever called sealed. Pure of network: the bytes come from src/anchor-service.ts.
//
// [LOCKED] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES] - 2026-10-05
// [NEVER] write a file under the name a bundle gives it without matching the whole name against
//         BUNDLE_NAME first, and never write a bundle anywhere but a folder this code made for it.
// WHY: a bundle is an answer from the network. A name like "../../.ssh/authorized_keys" or
//      "/etc/cron.d/x" taken as it stands writes outside the folder (contract section 5.3; the free
//      checker's LOCK BUNDLE_NAMES_ARE_A_FIXED_LIST is the same rule on the other side).
// FIX: the fixed names of section 7.1, with <key_id> and <profile> from [a-z0-9-] and certificates from
//      [A-Za-z0-9._-] not starting with a dot: no "..", no leading "/", one folder deep at most. A bundle
//      carrying any other name is refused whole, before a byte is written. record/ and code/ never come
//      from SealHour.
//
// [LOCKED] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE] - 2026-10-05
// [NEVER] call an hour stamped because its stamp verifies against a certificate the bundle carries, and
//         never call a checkpoint sealed before its inclusion path gives the bundle's root, its receipt
//         holds under a pinned key and names that hour, and the bundle's checkpoint is this machine's own.
// WHY: anyone can make a certificate authority, a time stamp server with its clock set back and a
//      signing key: such a bundle verifies against its own certs/ and keys/ (the contract's fixture is
//      exactly that, on purpose). [VERIFY-TRUSTS-ONLY-PINNED-ROOTS] already says it for the interim
//      stamps. And a status line that rounds "received" or "a proof came" up to "sealed" is the silent
//      failure the product exists to catch ([NOT-STAMPED-IS-NEVER-CALLED-STAMPED]).
// FIX: every certificate of the stamp's CA file must have its SHA-256 in the service's pinned list
//      (src/anchor-service.ts STAMP_ANCHORS, the list the free checker pins); otherwise the stamp is
//      shown with the fingerprint and marked ??, never OK. OpenSSL checks the stamp over root.bin at the
//      stamp's own time. A check that cannot run is ??, a check that fails is NO, and only a bundle with
//      no NO in its checkpoint, path and receipt lines is kept as this checkpoint's proof.
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "fs";
import { basename, dirname, join } from "path";
import { digestOf, leafHash, rootFromPath } from "./anchor-protocol.js";
import { checkStamp, parseTsr } from "./anchor-tsa.js";
import { certFingerprints, publicKeyHex, receiptKey, receiptRefusals, serviceName, type Service } from "./anchor-service.js";

/** The whole of a name a bundle may carry (section 7.1). [LOCK] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES] */
export const BUNDLE_NAME = /^(?:README\.txt|LISEZMOI\.txt|checkpoint\.json|receipt\.json|leaf\.json|path\.json|stamps\.json|root\.bin|root\.bin\.ots|root\.[a-z0-9-]+\.tsr|keys\/[a-z0-9-]{1,64}\.pub|certs\/[A-Za-z0-9_-][A-Za-z0-9._-]*)$/;
/** Every file of a bundle together, at most (the free checker's limit; a real bundle is a few kilobytes). */
const BUNDLE_MOST = 16 * 1024 * 1024;

const isHex64 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const printable = (v: unknown, most = 100): string => String(v ?? "").replace(/[^\x20-\x7e]/g, " ").trim().slice(0, most);

/**
 * The files of a served bundle as name to bytes; throws, in plain words, on anything that is not a
 * version 1 bundle whose every name is one of the contract's. Nothing is written.
 */
export function bundleFiles(bundle: unknown): Map<string, Buffer> {
  const b = bundle as { version?: unknown; kind?: unknown; checkpoint_digest?: unknown; files?: unknown };
  if (typeof b !== "object" || b === null || Array.isArray(b) || Object.keys(b).sort().join() !== "checkpoint_digest,files,kind,version" ||
    b.version !== 1 || b.kind !== "bundle" || !isHex64(b.checkpoint_digest) ||
    typeof b.files !== "object" || b.files === null || Array.isArray(b.files) || Object.keys(b.files).length === 0) {
    throw new Error("not a SealHour bundle of protocol version 1");
  }
  const out = new Map<string, Buffer>();
  let total = 0;
  for (const [name, text] of Object.entries(b.files as Record<string, unknown>)) {
    if (!BUNDLE_NAME.test(name)) throw new Error(`the bundle carries a file name outside the protocol: ${JSON.stringify(name).slice(0, 80)}`);
    if (typeof text !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new Error(`${name} is not base64`);
    const data = Buffer.from(text, "base64");
    total += data.length;
    if (total > BUNDLE_MOST) throw new Error("the bundle is too large");
    out.set(name, data);
  }
  return out;
}

/**
 * Write a bundle's files as the folder `dir`, replacing a proof already there in one move: the files go
 * to a new folder beside it first. Only names bundleFiles() let through reach this function.
 */
export function writeBundle(files: Map<string, Buffer>, dir: string): void {
  const tmp = join(dirname(dir), `.tmp-${basename(dir)}-${process.pid}`);
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  for (const [name, data] of files) {
    if (!BUNDLE_NAME.test(name)) throw new Error(`refused to write ${JSON.stringify(name).slice(0, 80)}`); // [LOCK] twice on purpose
    const to = join(tmp, name);
    mkdirSync(dirname(to), { recursive: true });
    writeFileSync(to, data);
  }
  const old = `${tmp}.old`;
  rmSync(old, { recursive: true, force: true });
  if (existsSync(dir)) renameSync(dir, old);
  renameSync(tmp, dir);
  rmSync(old, { recursive: true, force: true });
}

/** The files of a proof folder on disk (one folder deep), under the contract's names only. */
export function readBundleDir(dir: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isFile()) {
      if (BUNDLE_NAME.test(e.name)) out.set(e.name, readFileSync(join(dir, e.name)));
    } else if (e.isDirectory() && (e.name === "keys" || e.name === "certs")) {
      for (const f of readdirSync(join(dir, e.name))) {
        const name = `${e.name}/${f}`;
        if (BUNDLE_NAME.test(name)) out.set(name, readFileSync(join(dir, e.name, f)));
      }
    }
  }
  return out;
}

/** OK passed, NO failed, ?? could not be checked here (never a pass). */
export type BundleMark = "OK" | "NO" | "??";

export interface BundleStamp {
  profile: string;
  /** As the bundle's stamps.json names the provider. */
  name: string;
  mark: BundleMark;
  /** The stamp's own time (from the stamp, not from stamps.json). */
  time: string | null;
  late: boolean;
  detail: string;
}

export interface BundleCheck {
  checkpoint: { mark: BundleMark; detail: string };
  path: { mark: BundleMark; detail: string };
  receipt: { mark: BundleMark; detail: string };
  stamps: BundleStamp[];
  /** What the bundle says of its Bitcoin attestation; this code does not check it (the free checker does). */
  bitcoin: { state: "complete" | "pending" | "none"; block: number | null; detail: string };
  hour: string | null;
  /** The receipt's received_at, when the receipt holds. */
  receivedAt: string | null;
  /** Checkpoint, path and receipt all OK: this checkpoint is inside this hour's root, on SealHour's signed word. */
  included: boolean;
  /** Included, and the earliest stamp that verified under a pinned certificate. */
  stampedAt: string | null;
  /** Nothing says NO. */
  holds: boolean;
}

function json(files: Map<string, Buffer>, name: string): Record<string, unknown> {
  const raw = files.get(name);
  if (!raw) throw new Error(`${name} is missing`);
  const v: unknown = JSON.parse(raw.toString("utf8"));
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`${name} is not a JSON object`);
  return v as Record<string, unknown>;
}

/**
 * Every check of contract section 7.2 that a served bundle allows (1, 3, 4 and 6; 5, the window, is
 * `anchor verify`'s own; 7, Bitcoin, is reported as the bundle states it). `dir` is where the bundle's
 * files are on disk (OpenSSL reads the stamp and the certificates there). `digest`, when given, is the
 * checkpoint this proof must be about; `customer`, the pseudonym its receipt must carry.
 * [LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE]
 */
export function checkBundle(dir: string, service: Service, o: { digest?: string; customer?: string } = {}): BundleCheck {
  const files = readBundleDir(dir);
  const who = serviceName(service);
  const out: BundleCheck = {
    checkpoint: { mark: "NO", detail: "" }, path: { mark: "NO", detail: "" }, receipt: { mark: "NO", detail: "" },
    stamps: [], bitcoin: { state: "none", block: null, detail: "no Bitcoin attestation in this proof" },
    hour: null, receivedAt: null, included: false, stampedAt: null, holds: false,
  };

  // 1. The checkpoint the proof is about.
  let leaf: Record<string, unknown> = {};
  let digest = "";
  try {
    leaf = json(files, "leaf.json");
    digest = digestOf(json(files, "checkpoint.json"));
    if (leaf.kind !== "checkpoint" || !isHex64(leaf.digest) || !isHex64(leaf.customer) || Object.keys(leaf).length !== 3) out.checkpoint = { mark: "NO", detail: "leaf.json is not a checkpoint leaf of protocol version 1" };
    else if (digest !== leaf.digest) out.checkpoint = { mark: "NO", detail: "checkpoint.json is not the checkpoint this proof seals (another digest)" };
    else if (o.digest !== undefined && digest !== o.digest) out.checkpoint = { mark: "NO", detail: "this proof is about another checkpoint" };
    else out.checkpoint = { mark: "OK", detail: `the proof is about this checkpoint, digest ${digest}` };
  } catch (e) {
    out.checkpoint = { mark: "NO", detail: `checkpoint.json or leaf.json missing or unreadable (${printable((e as Error).message)})` };
  }

  // 3. The inclusion path: leaf.json and path.json give root.bin.
  const root = files.get("root.bin") ?? Buffer.alloc(0);
  let pathHour: string | null = null;
  try {
    const p = json(files, "path.json");
    const lh = leafHash(leaf);
    const i = p.index, n = p.size, sib = p.siblings;
    const fits = Number.isSafeInteger(i) && Number.isSafeInteger(n) && (i as number) >= 0 && (n as number) >= 1 && (i as number) < (n as number) &&
      Array.isArray(sib) && sib.length <= 64 && sib.every(isHex64);
    if (root.length !== 32) out.path = { mark: "NO", detail: "root.bin is missing or is not 32 bytes" };
    else if (!fits) out.path = { mark: "NO", detail: "path.json does not describe a place in a tree" };
    else {
      let climbed: Buffer | null = null;
      try { climbed = rootFromPath(i as number, n as number, lh, (sib as string[]).map((s) => Buffer.from(s, "hex"))); } catch { climbed = null; }
      const good = climbed !== null && climbed.equals(root) && lh.toString("hex") === p.leaf_hash && root.toString("hex") === p.root;
      pathHour = typeof p.hour === "string" && /^\d{4}-\d\d-\d\dT\d\dZ$/.test(p.hour) ? p.hour : null;
      if (!good) out.path = { mark: "NO", detail: "the inclusion path does not lead from this checkpoint to the hour's root" };
      else if (!pathHour) out.path = { mark: "NO", detail: "path.json does not name its hour" };
      else out.path = { mark: "OK", detail: `included in the hour ${pathHour} (one of ${n} fingerprints), hour root ${root.toString("hex")}` };
    }
  } catch (e) {
    out.path = { mark: "NO", detail: `path.json missing or unreadable (${printable((e as Error).message)})` };
  }

  // 4. The receipt: SealHour's signed word, under a pinned key, for this customer and this hour.
  try {
    const r = json(files, "receipt.json");
    const problems = receiptRefusals(service, r, { digest: isHex64(leaf.digest) ? leaf.digest : digest, customer: o.customer });
    const key = receiptKey(service, r.key_id);
    const carried = key ? files.get(`keys/${key.id}.pub`) : undefined;
    let carriedHex: string | null = null;
    try { carriedHex = carried ? publicKeyHex(carried) : null; } catch { carriedHex = null; }
    if (problems.length > 0) out.receipt = { mark: key ? "NO" : "??", detail: `receipt: ${problems.join("; ")}` };
    else if (r.customer !== leaf.customer) out.receipt = { mark: "NO", detail: "the receipt is for another customer than the sealed leaf" };
    else if (pathHour !== null && r.hour !== pathHour) out.receipt = { mark: "NO", detail: `the receipt names the hour ${printable(r.hour, 20)}, the path the hour ${pathHour}` };
    else if (carried && carriedHex !== publicKeyHex(key!.pem)) out.receipt = { mark: "NO", detail: `the proof carries another key under the name ${key!.id} than the one ${who} publishes` };
    else {
      out.receipt = { mark: "OK", detail: `receipt signed by ${who} key ${key!.id}: received ${String(r.received_at).replace("T", " ")} for the hour ${String(r.hour)}` };
      out.receivedAt = String(r.received_at);
      out.hour = String(r.hour);
    }
  } catch (e) {
    out.receipt = { mark: "NO", detail: `receipt.json missing or unreadable (${printable((e as Error).message)})` };
  }

  // 6. Each stamp of the hour's root, under a pinned certificate.
  let stampsJson: Record<string, unknown> = {};
  try { stampsJson = files.has("stamps.json") ? json(files, "stamps.json") : {}; } catch { stampsJson = {}; }
  const tsa = stampsJson.tsa && typeof stampsJson.tsa === "object" && !Array.isArray(stampsJson.tsa) ? (stampsJson.tsa as Record<string, unknown>) : {};
  for (const [profile, raw] of Object.entries(tsa)) {
    const s = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    const name = printable(s.name, 80) || profile.slice(0, 40);
    const line = (mark: BundleMark, detail: string, time: string | null = null): BundleStamp => ({ profile, name, mark, time, late: s.late === true, detail });
    if (!/^[a-z0-9-]+$/.test(profile)) { out.stamps.push(line("NO", "stamps.json names a time stamp outside the protocol")); continue; }
    const tsrName = `root.${profile}.tsr`;
    if (!files.has(tsrName)) { out.stamps.push(line("??", `no time stamp from ${name} in this proof${s.ok === false ? " (the service says it did not get one)" : ""}`)); continue; }
    let time: string | null = null;
    try {
      const info = parseTsr(files.get(tsrName)!);
      time = info.time;
      if (root.length !== 32 || info.imprintSha256 !== root.toString("hex")) { out.stamps.push(line("NO", "this stamp is for another fingerprint than the hour's root", time)); continue; }
    } catch (e) {
      out.stamps.push(line("NO", `not a time stamp (${printable((e as Error).message)})`));
      continue;
    }
    const caName = typeof s.ca_file === "string" ? `certs/${basename(s.ca_file)}` : "";
    const untrustedName = typeof s.untrusted === "string" ? `certs/${basename(s.untrusted)}` : "";
    if (!caName || !BUNDLE_NAME.test(caName) || !files.has(caName) || (untrustedName && (!BUNDLE_NAME.test(untrustedName) || !files.has(untrustedName)))) {
      out.stamps.push(line("??", `the proof does not carry the certificate of ${name}'s stamp`, time));
      continue;
    }
    let prints: string[] = [];
    try { prints = certFingerprints(files.get(caName)!); } catch { prints = []; }
    const unknown = prints.find((p) => !service.anchors.includes(p));
    if (prints.length === 0 || unknown) {
      out.stamps.push(line("??", `stamped at ${time ?? "an unread time"} under a certificate this version of OpsContext does not know (${caName}${unknown ? `, SHA-256 ${unknown}` : ""}): the free checker at sealhour.com may know it; it does not count as a date here`, time));
      continue;
    }
    const r = checkStamp({
      tsr: join(dir, tsrName), caFile: join(dir, caName), digestHex: root.toString("hex"), time,
      untrusted: untrustedName ? join(dir, untrustedName) : undefined, partialChain: s.partial_chain === true,
    });
    out.stamps.push(line(r.ok === true ? "OK" : r.ok === false ? "NO" : "??", r.ok === true ? "signature and chain verified by OpenSSL under a pinned certificate" : r.detail, time));
  }

  // 7. Bitcoin, as the bundle states it.
  const ots = stampsJson.ots && typeof stampsJson.ots === "object" ? (stampsJson.ots as Record<string, unknown>) : {};
  if (files.has("root.bin.ots")) {
    const block = Number.isSafeInteger(ots.bitcoin_block) ? (ots.bitcoin_block as number) : null;
    out.bitcoin = ots.ok === true && block !== null
      ? { state: "complete", block, detail: `the proof carries its Bitcoin attestation (block ${block}, as ${who} states it); not checked by this command: the free checker does it` }
      : { state: "pending", block: null, detail: "the Bitcoin attestation is still pending (it comes hours after the seal); fetch the proof again later: contextengine anchor export-evidence --refresh" };
  }

  out.included = out.checkpoint.mark === "OK" && out.path.mark === "OK" && out.receipt.mark === "OK";
  const dated = out.stamps.filter((s) => s.mark === "OK" && s.time).map((s) => s.time!).sort();
  out.stampedAt = out.included ? dated[0] ?? null : null;
  out.holds = ![out.checkpoint.mark, out.path.mark, out.receipt.mark, ...out.stamps.map((s) => s.mark)].includes("NO");
  return out;
}
