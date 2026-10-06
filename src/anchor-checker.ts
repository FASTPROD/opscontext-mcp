// The standalone checker written into every `anchor export-evidence` folder: plain Node, no dependency,
// needs only Node 18 and OpenSSL 3. The same rules as src/anchor-protocol.ts ([LOCK]
// [SEALHOUR-PROTOCOL-V1-BYTES]), the contract's fixture check.mjs and, for a proof SealHour served,
// src/anchor-bundle.ts ([LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE]): a receipt counts only
// under a key it knows, a stamp only under a certificate it knows, both written into it when the folder
// is exported; anything else is shown with its fingerprint and marked ??. `--trust-folder` takes what
// the folder carries as genuine, for test folders, as SealHour's own free checker does.

/** verify.mjs, knowing these receipt keys (key id to the 32 bytes of the public key, hex) and these certificates (SHA-256, hex). */
export function verifyMjs(pins: { keys: Record<string, string>; anchors: readonly string[] }): string {
  return CHECKER.replace("/*PINS*/", `const KNOWN_KEYS = ${JSON.stringify(pins.keys)};\nconst KNOWN_ANCHORS = ${JSON.stringify([...pins.anchors])};`);
}

// No template literal and no backtick inside: String.raw keeps every backslash as it is written.
const CHECKER = String.raw`// verify.mjs: checks a folder of OpsContext checkpoints, their time stamps and their SealHour proofs,
// offline, without OpsContext and without SealHour.
//   node verify.mjs <folder> [<audit log, one JSON record per line>] [--trust-folder]
// The rules are those of SealHour protocol version 1: canonical JSON (keys sorted, no spaces, UTF-8,
// integers only), SHA-256, RFC 6962 tree with leaf = SHA-256(0x00 || JSON) and node = SHA-256(0x01 || l || r).
// A receipt counts only under a SealHour key this file knows, a stamp of a sealed hour only under a
// certificate this file knows; --trust-folder takes those the folder carries as genuine (test folders).
import { createHash, createPublicKey, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { spawnSync } from "node:child_process";

/*PINS*/
const ZERO = "0".repeat(64);
const HEX = /^[0-9a-f]{64}$/;
const argv = process.argv.slice(2);
const trustFolder = argv.includes("--trust-folder");
const [dir = ".", log] = argv.filter((a) => a !== "--trust-folder");
function canon(v) {
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (v !== null && typeof v === "object")
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  if (typeof v === "number" && !Number.isSafeInteger(v)) throw new Error("not an integer: " + v);
  return JSON.stringify(v);
}
const sha = (...b) => createHash("sha256").update(Buffer.concat(b)).digest();
const leaf = (o) => sha(Buffer.from([0]), Buffer.from(canon(o), "utf8"));
const node = (l, r) => sha(Buffer.from([1]), l, r);
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (h) => (h.length === 1 ? h[0] : node(mth(h.slice(0, split(h.length))), mth(h.slice(split(h.length)))));
function climb(i, n, lh, sib) {
  if (n === 1) { if (sib.length) throw new Error("path too long"); return lh; }
  if (!sib.length) throw new Error("path too short");
  const k = split(n), rest = sib.slice(0, -1), s = sib[sib.length - 1];
  return i < k ? node(climb(i, k, lh, rest), s) : node(s, climb(i - k, n - k, lh, rest));
}
const hourOf = (t) => new Date(Date.parse(t) + 58 * 60000).toISOString().slice(0, 13) + "Z";
const ssl = process.env.OPENSSL || "openssl";
/** The time a stamp carries, as openssl reads it (ISO, UTC), or null. */
function stampTime(tsr) {
  const p = spawnSync(ssl, ["ts", "-reply", "-in", tsr, "-text"], { encoding: "utf8" });
  const m = p.error ? null : /^Time stamp: (\w{3}) +(\d+) (\d\d:\d\d:\d\d)(?:\.\d+)? (\d{4}) GMT$/m.exec(p.stdout || "");
  if (!m) return null;
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].indexOf(m[1]) + 1;
  return mon ? m[4] + "-" + String(mon).padStart(2, "0") + "-" + m[2].padStart(2, "0") + "T" + m[3] + "Z" : null;
}
const hashes = log
  ? readFileSync(log, "utf8").split("\n").map((l) => { try { const r = JSON.parse(l); return HEX.test(r && r.hash) ? r.hash : null; } catch { return null; } }).filter(Boolean)
  : null;

const blocks = [];
let out = null;
const say = (ok, text) => { out.push("  [" + (ok === true ? "OK" : ok === false ? "NO" : "??") + "] " + text); return ok; };
let prev = null;
let fails = 0;
let pending = []; // checkpoints with no checked stamp of their own, since the last one with one

/** A folder that holds leaf.json: a proof as SealHour served it. The stamp's time when one verified under a known certificate. */
function checkSealed(d, digest) {
  let first = null;
  try {
    const lf = JSON.parse(readFileSync(join(d, "leaf.json"), "utf8"));
    const p = JSON.parse(readFileSync(join(d, "path.json"), "utf8"));
    const root = readFileSync(join(d, "root.bin"));
    if (say(lf.kind === "checkpoint" && lf.digest === digest, "this folder is SealHour's proof of this checkpoint") === false) fails++;
    const lh = leaf(lf);
    let top = null;
    try {
      const fits = Number.isSafeInteger(p.index) && Number.isSafeInteger(p.size) && p.index >= 0 && p.index < p.size && Array.isArray(p.siblings) && p.siblings.length <= 64 && p.siblings.every((x) => HEX.test(x));
      top = fits ? climb(p.index, p.size, lh, p.siblings.map((x) => Buffer.from(x, "hex"))) : null;
    } catch { top = null; }
    const inHour = top !== null && root.length === 32 && top.equals(root) && lh.toString("hex") === p.leaf_hash && root.toString("hex") === p.root;
    if (say(inHour, "included in the hour " + p.hour + " (one of " + p.size + " fingerprints), hour root " + root.toString("hex")) === false) fails++;

    const r = JSON.parse(readFileSync(join(d, "receipt.json"), "utf8"));
    const { signature, ...body } = r;
    let sig = false, keyHex = "";
    if (typeof r.key_id === "string" && /^[a-z0-9-]{1,64}$/.test(r.key_id) && existsSync(join(d, "keys", r.key_id + ".pub"))) {
      try {
        const key = createPublicKey(readFileSync(join(d, "keys", r.key_id + ".pub")));
        keyHex = key.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
        sig = /^[A-Za-z0-9+/]{86}==$/.test(String(signature)) && cryptoVerify(null, Buffer.from(canon(body), "utf8"), key, Buffer.from(signature, "base64"));
      } catch { sig = false; }
    }
    const fields = Object.keys(body).sort().join() === "checkpoint_digest,customer,hour,key_id,kind,received_at,version" && r.version === 1 && r.kind === "receipt" &&
      r.checkpoint_digest === digest && r.customer === lf.customer && r.hour === p.hour && hourOf(r.received_at) === r.hour;
    const knownKey = trustFolder || (keyHex !== "" && KNOWN_KEYS[r.key_id] === keyHex);
    const rOk = sig && fields ? (knownKey ? true : null) : false;
    const rText = rOk === null
      ? "receipt signed by key " + r.key_id + ", which this checker does not know (public key " + keyHex + "): compare it with https://sealhour.com/keys/"
      : "receipt signed by SealHour key " + r.key_id + ": received " + r.received_at + " for the hour " + r.hour;
    if (say(rOk, rText) === false) fails++;

    const st = existsSync(join(d, "stamps.json")) ? JSON.parse(readFileSync(join(d, "stamps.json"), "utf8")) : {};
    for (const [prof, s] of Object.entries(st.tsa || {})) {
      const name = String((s && s.name) || prof).replace(/[^\x20-\x7e]/g, " ").slice(0, 80);
      if (!/^[a-z0-9-]+$/.test(prof)) { say(false, "stamps.json names a time stamp outside the protocol"); fails++; continue; }
      const tsr = join(d, "root." + prof + ".tsr");
      if (!existsSync(tsr)) { say(null, "no time stamp from " + name + " in this folder"); continue; }
      const ca = join(d, "certs", basename(String(s.ca_file || "")));
      const time = stampTime(tsr);
      const args = ["ts", "-verify", "-digest", root.toString("hex"), "-in", tsr, "-CAfile", ca];
      if (s.untrusted) args.push("-untrusted", join(d, "certs", basename(String(s.untrusted))));
      if (s.partial_chain) args.push("-partial_chain");
      if (time) args.push("-attime", String(Math.floor(Date.parse(time) / 1000)));
      const q = spawnSync(ssl, args, { encoding: "utf8" });
      const ok = q.error ? null : q.status === 0 && /Verification: OK/.test(q.stdout);
      let prints = [];
      try {
        prints = (readFileSync(ca, "latin1").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || []).map((b) => createHash("sha256").update(new X509Certificate(b).raw).digest("hex"));
      } catch { prints = []; }
      const knownCert = trustFolder || (prints.length > 0 && prints.every((x) => KNOWN_ANCHORS.includes(x)));
      const mark = ok === true ? (knownCert ? true : null) : ok;
      if (mark === true && (!first || (time && time < first))) first = time || "a stamp without a time";
      const tail = q.error ? ": openssl not found" : ok === true && !knownCert ? ", but under a certificate this checker does not know (SHA-256 " + (prints[0] || "unreadable") + "): it does not count as a date here" : "";
      if (say(mark, "hour stamped by " + name + (time ? " at " + time : "") + tail) === false) fails++;
    }
    const ots = st.ots || {};
    const btc = existsSync(join(d, "root.bin.ots")) ? (ots.ok === true ? "the proof names block " + ots.bitcoin_block : "the attestation is still pending") : "no attestation in this folder";
    say(null, "Bitcoin: " + btc + "; not checked here: SealHour's free checker does it (python3 sealhour_verify.py " + d + ")");
  } catch (e) {
    say(false, "not a proof folder, or a file in it is unreadable (" + String(e && e.message).slice(0, 120) + ")");
    fails++;
  }
  return first;
}

const names = readdirSync(join(dir, "checkpoints")).filter((n) => /^\d{6}-[0-9a-f]{12}$/.test(n)).sort();
for (const n of names) {
  const d = join(dir, "checkpoints", n);
  out = [n];
  blocks.push(out);
  const cp = JSON.parse(readFileSync(join(d, "checkpoint.json"), "utf8"));
  const digest = sha(Buffer.from(canon(cp), "utf8")).toString("hex");
  if (say(n.endsWith(digest.slice(0, 12)), "checkpoint digest " + digest) === false) fails++;
  const chain = prev === null
    ? (cp.prev_checkpoint_digest === ZERO ? true : null)
    : cp.prev_checkpoint_digest === prev.digest && cp.records.from_hash === prev.head;
  if (say(chain, prev === null ? (chain ? "first of the chain" : "the checkpoint before it is not in this folder") : "chains to the one before it") === false) fails++;
  if (chain !== true) pending = []; // a broken or unknown link: nothing later dates what came before it
  if (hashes) {
    const r = cp.records;
    let ok = false;
    const starts = r.from_hash === ZERO ? [0] : hashes.map((h, i) => (h === r.from_hash ? i + 1 : -1)).filter((i) => i > 0);
    for (const s of starts) {
      const w = hashes.slice(s, s + r.count);
      if (w.length === r.count && w[w.length - 1] === r.head_hash && mth(w.map((h) => leaf({ kind: "record", hash: h }))).toString("hex") === r.records_root) ok = true;
    }
    if (say(ok, "records_root recomputed from the log (" + r.count + " records)") === false) fails++;
  }
  let first = null;
  if (existsSync(join(d, "leaf.json"))) {
    first = checkSealed(d, digest);
  } else {
    const stamps = existsSync(join(d, "stamps.json")) ? JSON.parse(readFileSync(join(d, "stamps.json"), "utf8")) : {};
    for (const f of readdirSync(d).filter((x) => /^checkpoint\.[a-z0-9-]+\.tsr$/.test(x)).sort()) {
      const id = f.split(".")[1];
      const s = stamps[id] || {};
      const ca = join(dir, s.ca_file || "certs/" + id + "-ca.pem");
      const args = ["ts", "-verify", "-digest", digest, "-in", join(d, f), "-CAfile", ca];
      if (s.time) args.push("-attime", String(Math.floor(Date.parse(s.time) / 1000)));
      const p = spawnSync(ssl, args, { encoding: "utf8" });
      const ok = p.error ? null : p.status === 0 && /Verification: OK/.test(p.stdout);
      if (ok && (!first || (s.time && s.time < first))) first = s.time || "a stamp without a time";
      if (say(ok, "stamp " + (s.name || id) + (s.time ? " " + s.time : "") + (p.error ? ": openssl not found" : "")) === false) fails++;
    }
  }
  if (first) {
    for (const b of pending) b.push("  [OK] no checked stamp of its own: dated through the chain by " + n + " (" + first + "), a later date");
    pending = [];
  } else {
    pending.push(out);
  }
  prev = { digest, head: cp.records.head_hash };
}
for (const b of pending) b.push("  not stamped by a service this folder can check");
console.log(dir);
for (const b of blocks) for (const l of b) console.log(l);
const holds = names.length > 0 && fails === 0;
console.log("Result: " + names.length + " checkpoint(s), " + (holds ? "the rule holds" : "the rule does NOT hold") + (pending.length ? ", " + pending.length + " not stamped" : "") + ".");
process.exit(holds ? 0 : 1);
`;
