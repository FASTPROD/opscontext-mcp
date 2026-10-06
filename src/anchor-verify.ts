// `contextengine anchor verify` and `anchor export-evidence` (COMPR-TSA docs/SEALHOUR_PROTOCOL.md sections 2
// and 7; workplan 2 Chantier 1, corrections 2 to 4): every checkpoint of this machine recomputed from its
// own history, every stamp checked against the provider's pinned root, every SealHour receipt and proof
// checked under the pinned key and certificates (src/anchor-bundle.ts), and the clock offset measured.
//
// [LOCKED] [VERIFY-TRUSTS-ONLY-PINNED-ROOTS] - 2026-09-30
// [NEVER] check a stamp against a certificate read from ~/.contextengine (anchors/certs/ is a convenience
//         copy), and never let a check that could not run pass as a check that passed.
// WHY: whoever can rewrite the audit log can rewrite anchors/ too, including a CA file: a stamp checked
//      against a root on that disk proves nothing. And a missing openssl reading as "OK" would turn the
//      one outside witness into an unchecked claim ([EXEC-FAILURE-IS-NOT-EMPTY]).
// FIX: the roots come from the code (src/anchor-tsa.ts PROVIDERS, or a loopback test stand-in), written
//      to a private temp folder for OpenSSL. Every check prints OK, NO or ??; NO fails the verification,
//      ?? is said and never counted as a pass.
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { tmpdir } from "os";
import { verifyMjs } from "./anchor-checker.js";
import { checkWindows, type WindowCheck } from "./anchor-window.js";
import { canonBytes, checkpointProblems, codeRoot, digestOf, ZERO, type CodeLeaf } from "./anchor-protocol.js";
import { activeProviders, checkStamp, findOpenssl, parseTsr, PROVIDERS, type Provider } from "./anchor-tsa.js";
import { backendOf, listCheckpoints, type StoredCheckpoint } from "./anchor.js";
import { activeService, receiptKey, receiptRefusals, serviceName, RECEIPT_KEYS, STAMP_ANCHORS, publicKeyHex, type Service } from "./anchor-service.js";
import { BUNDLE_NAME, checkBundle, readBundleDir } from "./anchor-bundle.js";
import { cutoffOf, proofDir, readReceipt } from "./anchor-seal.js";

/** A clock jump: two stamped checkpoints whose offsets differ by more than this. */
export const CLOCK_JUMP_S = 300;
/** A stamp this long after created_at, without a first-try mark, is counted as late (not a clock reading). */
const LATE_S = 600;

/** OK passed, NO failed, ?? could not be checked here, -- nothing to check (that service did not stamp it). */
export type Mark = "OK" | "NO" | "??" | "--";

export interface StampLine {
  provider: string;
  name: string;
  mark: Mark;
  time: string | null;
  late: boolean;
  detail: string;
}

export interface CheckpointLine {
  seq: number;
  name: string;
  created_at: string;
  count: number;
  repos: number | null;
  digest: string;
  shape: { mark: Mark; detail: string };
  chain: { mark: Mark; detail: string };
  window: { mark: Mark; detail: string };
  code: { mark: Mark; detail: string } | null;
  stamps: StampLine[];
  /** SealHour: the receipt, the place in the sealed hour, the hour's stamp, Bitcoin; empty for an interim checkpoint. */
  seal: Array<{ mark: Mark; text: string }>;
  /** Earliest first-try stamp time minus created_at, seconds (SealHour: its receipt's time minus created_at). */
  offsetS: number | null;
  flags: string[];
  /** Nothing in it says NO. */
  holds: boolean;
  /** At least one stamp verified (OK), or exists and could not be checked here (??). */
  stamped: boolean;
  stampChecked: boolean;
  /** No checked stamp of its own, but a later checkpoint with one names it through an unbroken chain:
   *  dated by that stamp, a later date. */
  coveredBy: { seq: number; time: string | null } | null;
}

export interface VerifyReport {
  lines: CheckpointLine[];
  unlocked: boolean;
  restored: Array<{ segment: string; at: string | null }>;
  clock: string;
  holds: boolean;
  unstamped: number;
  summary: string;
}

/** The pinned root of a provider id, from the code (or a loopback test stand-in); null if unknown. */
function pinnedRoot(id: string): Provider | null {
  const fromCode = PROVIDERS.find((p) => p.id === id);
  if (fromCode) return fromCode;
  try {
    return activeProviders().find((p) => p.id === id) ?? null;
  } catch {
    return null;
  }
}

function checkStampsOf(c: StoredCheckpoint, digest: string, rootsDir: string): StampLine[] {
  const out: StampLine[] = [];
  const files = readdirSync(c.dir).filter((f) => /^checkpoint\.[a-z0-9-]+\.tsr$/.test(f));
  const ids = new Set([...files.map((f) => f.split(".")[1]), ...Object.keys(c.stamps)]);
  for (const id of [...ids].sort()) {
    const entry = c.stamps[id];
    const name = entry?.name ?? pinnedRoot(id)?.name ?? id;
    const tsr = join(c.dir, `checkpoint.${id}.tsr`);
    if (!existsSync(tsr)) {
      out.push({ provider: id, name, mark: "--", time: null, late: false, detail: `no stamp from this service${entry?.error ? ` (${entry.error}, ${entry.tried_at.slice(11, 16)}Z)` : ""}` });
      continue;
    }
    let time: string | null = null;
    try {
      const info = parseTsr(readFileSync(tsr));
      time = info.time;
      if (info.imprintSha256 !== digest) {
        out.push({ provider: id, name, mark: "NO", time, late: false, detail: "this stamp is for another fingerprint" });
        continue;
      }
    } catch (e) {
      out.push({ provider: id, name, mark: "NO", time: null, late: false, detail: `not a time stamp (${(e as Error).message})` });
      continue;
    }
    const p = pinnedRoot(id);
    if (!p) {
      out.push({ provider: id, name, mark: "??", time, late: false, detail: "no pinned root for this service in this version of OpsContext" });
      continue;
    }
    const caFile = join(rootsDir, `${p.id}-ca.pem`);
    if (!existsSync(caFile)) writeFileSync(caFile, p.caPem);
    const r = checkStamp({ tsr, caFile, digestHex: digest, time });
    const late = entry ? !entry.first_try : time !== null && Date.parse(time) - Date.parse(c.checkpoint.created_at) > LATE_S * 1000;
    out.push({ provider: id, name, mark: r.ok === true ? "OK" : r.ok === false ? "NO" : "??", time, late, detail: r.detail });
  }
  return out;
}

/**
 * What SealHour says of one checkpoint, checked here: its receipt under the pinned key, its place in
 * the sealed hour, the hour's stamp under a pinned certificate, Bitcoin as the proof states it.
 * [LOCK] [A-SEAL-COUNTS-ONLY-UNDER-A-PINNED-CERTIFICATE] (src/anchor-bundle.ts)
 */
function sealLinesOf(c: StoredCheckpoint, digest: string, service: Service): { lines: Array<{ mark: Mark; text: string }>; included: boolean; stampedAt: string | null; receivedFirstTry: string | null } {
  const who = serviceName(service);
  const seal = c.meta.seal;
  const out: Array<{ mark: Mark; text: string }> = [];
  const customer = seal?.customer ?? undefined;
  if (existsSync(proofDir(c))) {
    const chk = checkBundle(proofDir(c), service, { digest, customer });
    if (chk.checkpoint.mark !== "OK") out.push({ mark: chk.checkpoint.mark, text: `proof: ${chk.checkpoint.detail}` });
    out.push({ mark: chk.receipt.mark, text: chk.receipt.detail });
    out.push({ mark: chk.path.mark, text: chk.path.detail });
    for (const s of chk.stamps) {
      const at = s.time ? ` ${s.time.slice(0, 19).replace("T", " ")}Z` : "";
      out.push({ mark: s.mark, text: s.mark === "OK" ? `hour stamped by ${s.name}:${at}${s.late ? " (asked late, after its hour)" : ""}` : `hour's stamp, ${s.name}:${at} ${s.detail}` });
    }
    if (chk.stamps.length === 0) out.push({ mark: "??", text: "the proof carries no time stamp of the hour yet" });
    out.push({ mark: chk.bitcoin.state === "none" ? "--" : "??", text: `Bitcoin: ${chk.bitcoin.detail}` });
    return { lines: out, included: chk.included, stampedAt: chk.stampedAt, receivedFirstTry: chk.included && seal?.first_try ? chk.receivedAt : null };
  }
  const receipt = readReceipt(c);
  if (receipt) {
    const problems = receiptRefusals(service, receipt, { digest, customer });
    const r = receipt as { key_id?: unknown; received_at?: unknown; hour?: unknown };
    if (problems.length > 0) out.push({ mark: receiptKey(service, r.key_id) ? "NO" : "??", text: `receipt: ${problems.join("; ")}` });
    else out.push({ mark: "OK", text: `receipt signed by ${who} key ${String(r.key_id)}: received ${String(r.received_at).replace("T", " ")} for the hour ${String(r.hour)}` });
    const first = problems.length === 0 && seal?.first_try ? String(r.received_at) : null;
    if (seal?.state === "missed") out.push({ mark: "--", text: `not sealed: ${seal.error ?? `${who} missed its hour`}` });
    else {
      const at = typeof r.hour === "string" && /^\d{4}-\d\d-\d\dT\d\dZ$/.test(r.hour) ? cutoffOf(r.hour).toISOString().slice(0, 16).replace("T", " ") + "Z" : "the next minute 2";
      out.push({ mark: "--", text: `not sealed yet: its hour is sealed at ${at}${seal?.error ? ` (${seal.error})` : seal?.waiting ? ` (${who}: ${seal.waiting})` : ""}; the proof is fetched by the hourly job` });
    }
    return { lines: out, included: false, stampedAt: null, receivedFirstTry: first };
  }
  out.push({ mark: "--", text: seal?.state === "refused" ? `not sealed: ${seal.error ?? `${who} refused it`}` : `not received by ${who} yet${seal?.error ? `: ${seal.error}` : ""}` });
  return { lines: out, included: false, stampedAt: null, receivedFirstTry: null };
}

const sign = (s: number) => `${s >= 0 ? "+" : "-"}${Math.abs(s) < 120 ? `${Math.abs(s)} s` : Math.abs(s) < 7200 ? `${Math.round(Math.abs(s) / 60)} min` : `${(Math.abs(s) / 3600).toFixed(1)} h`}`;

/** Verify every checkpoint kept on this machine. [LOCK] [VERIFY-TRUSTS-ONLY-PINNED-ROOTS] */
export function verifyAnchors(o: { waitMs?: number } = {}): VerifyReport {
  const all = listCheckpoints();
  if (all.length === 0) return { lines: [], unlocked: false, restored: [], clock: "no stamp to measure the clock against", holds: true, unstamped: 0, summary: "no checkpoint on this machine yet" };
  const rootsDir = mkdtempSync(join(tmpdir(), "opscontext-roots-"));
  try {
    const windows = checkWindows(all.map((c) => ({ id: c.name, created_at: c.checkpoint.created_at, ...c.checkpoint.records })), { waitMs: o.waitMs });
    const lines: CheckpointLine[] = [];
    let prev: { digest: string; head: string; seq: number } | null = null;
    let svc: Service | null = null;
    const service = (): Service => (svc ??= activeService());
    /** When each sealed checkpoint's hour was stamped, for the ones a later seal dates. */
    const dates = new Map<number, string>();
    const prevDigests = new Map<string, string>();
    let lastOffset: number | null = null;
    for (const c of all) {
      const digest = digestOf(c.checkpoint);
      const problems = checkpointProblems(c.checkpoint, canonBytes(c.checkpoint).length);
      const shape: CheckpointLine["shape"] = problems.length > 0
        ? { mark: "NO", detail: problems.join("; ") }
        : c.name.endsWith(digest.slice(0, 12)) ? { mark: "OK", detail: "shape of protocol version 1, digest matches its folder" } : { mark: "NO", detail: "checkpoint.json was changed after it was made (its digest no longer matches its folder)" };
      let chain: CheckpointLine["chain"];
      const cp = c.checkpoint;
      const twin = prevDigests.get(cp.prev_checkpoint_digest);
      if (twin) chain = { mark: "NO", detail: `a fork: ${twin} chains to the same previous checkpoint` };
      else if (!prev) chain = cp.prev_checkpoint_digest === ZERO ? { mark: "OK", detail: "first of the chain" } : { mark: "??", detail: "the checkpoint before it is not kept here" };
      else if (cp.prev_checkpoint_digest !== prev.digest) chain = { mark: "NO", detail: `does not chain to #${prev.seq}` };
      else if (cp.records.from_hash !== prev.head) chain = { mark: "NO", detail: `its window does not start where #${prev.seq}'s ended` };
      else chain = { mark: "OK", detail: `chains to #${prev.seq}` };
      prevDigests.set(cp.prev_checkpoint_digest, c.name);

      const w: WindowCheck = windows.results.get(c.name)!;
      const window: CheckpointLine["window"] = w.ok
        ? { mark: "OK", detail: `records_root recomputed from this machine's log, read ${w.reading}` }
        : { mark: "NO", detail: w.got?.found === false ? "its first record's predecessor is not in the log (history cut or replaced)" : `the log gives ${w.got?.count ?? 0} record(s)${w.got?.records_root ? `, another root` : ""} where the checkpoint says ${cp.records.count} (records deleted, rewritten or added inside the window)` };

      let code: CheckpointLine["code"] = null;
      if (cp.code) {
        let leaves: CodeLeaf[] | null = null;
        try { leaves = JSON.parse(readFileSync(join(c.dir, "code-leaves.json"), "utf8")) as CodeLeaf[]; } catch { leaves = null; }
        if (!leaves) code = { mark: "??", detail: "the code leaves are not kept here: the code root cannot be recomputed" };
        else if (leaves.length === cp.code.repos && codeRoot(leaves) === cp.code.code_root) code = { mark: "OK", detail: `${leaves.length} repositor${leaves.length === 1 ? "y" : "ies"}, root of the kept leaves` };
        else code = { mark: "NO", detail: "the kept code leaves do not give the checkpoint's code root" };
      }

      const stamps = checkStampsOf(c, digest, rootsDir);
      const flags: string[] = [];
      const sealed = backendOf(c) === "sealhour" ? sealLinesOf(c, digest, service()) : null;
      const first = stamps.filter((s) => s.mark === "OK" && !s.late && s.time).map((s) => Math.round((Date.parse(s.time!) - Date.parse(cp.created_at)) / 1000));
      if (sealed?.receivedFirstTry) first.push(Math.round((Date.parse(sealed.receivedFirstTry) - Date.parse(cp.created_at)) / 1000));
      const offsetS = first.length > 0 ? Math.min(...first) : null;
      if (offsetS !== null && lastOffset !== null && Math.abs(offsetS - lastOffset) > CLOCK_JUMP_S) {
        flags.push(`the clock jumped by ${sign(offsetS - lastOffset)} since the previous stamped checkpoint`);
      }
      if (offsetS !== null) lastOffset = offsetS;
      if (c.meta.last_ts && Date.parse(c.meta.last_ts) > Date.parse(cp.created_at) + 2000) flags.push("a record of its window is dated after the checkpoint was made (the clock went back?)");
      const late = stamps.filter((s) => s.mark === "OK" && s.late && s.time);
      for (const s of late) flags.push(`${s.name} stamped it ${sign(Math.round((Date.parse(s.time!) - Date.parse(cp.created_at)) / 1000)).slice(1)} after it was made (the services were away)`);

      const marks = [shape.mark, chain.mark, window.mark, code?.mark, ...stamps.map((s) => s.mark), ...(sealed?.lines.map((l) => l.mark) ?? [])];
      const stampedOk = stamps.some((s) => s.mark === "OK") || !!sealed?.stampedAt;
      if (sealed?.stampedAt) dates.set(c.seq, sealed.stampedAt);
      lines.push({
        seq: c.seq, name: c.name, created_at: cp.created_at, count: cp.records.count, repos: cp.code?.repos ?? null, digest,
        shape, chain, window, code, stamps, seal: sealed?.lines ?? [], offsetS, flags,
        holds: !marks.includes("NO"),
        stamped: stampedOk || stamps.some((s) => s.mark === "??" && s.time !== null) || !!sealed?.included,
        stampChecked: stampedOk,
        coveredBy: null,
      });
      prev = { digest, head: cp.records.head_hash, seq: c.seq };
    }
    // A checkpoint without a checked stamp of its own is dated through the chain by the earliest later
    // one that has one, when every link between them holds (each names the digest of the one before).
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].stampChecked) continue;
      for (let j = i + 1; j < lines.length; j++) {
        if (lines[j].chain.mark !== "OK") break;
        if (lines[j].stampChecked) {
          const t = dates.get(lines[j].seq) ?? lines[j].stamps.filter((x) => x.mark === "OK" && x.time).map((x) => x.time!).sort()[0] ?? null;
          lines[i].coveredBy = { seq: lines[j].seq, time: t };
          lines[i].flags.push(`no checked stamp of its own: dated through the chain by #${lines[j].seq}'s ${dates.has(lines[j].seq) ? "seal" : "stamp"}${t ? ` of ${t.slice(0, 19).replace("T", " ")}Z` : ""}, a later date`);
          break;
        }
      }
    }
    const offsets = lines.map((l) => l.offsetS).filter((x): x is number => x !== null);
    const jumps = lines.filter((l) => l.flags.some((f) => f.startsWith("the clock jumped")));
    const clock = offsets.length === 0
      ? "no stamp to measure the clock against"
      : jumps.length > 0
        ? `offset ${sign(offsets[offsets.length - 1])} now; ${jumps.length} jump(s) (#${jumps.map((l) => l.seq).join(", #")})`
        : `offset ${sign(Math.min(...offsets))} to ${sign(Math.max(...offsets))}, steady (a constant offset is this machine's clock, not a fault)`;
    const holds = lines.every((l) => l.holds);
    const unstamped = lines.filter((l) => !l.stamped && !l.coveredBy).length;
    const through = lines.filter((l) => !l.stampChecked && l.coveredBy).length;
    const uncheckable = lines.filter((l) => l.stamped && !l.stampChecked && !l.coveredBy).length;
    const sealedN = lines.filter((l) => dates.has(l.seq)).length;
    const summary = lines.length === 0
      ? "no checkpoint on this machine yet"
      : `${lines.filter((l) => l.holds).length} of ${lines.length} checkpoint(s) hold; ${sealedN ? `${sealedN} sealed, their hour's stamp checked; ` : ""}${lines.filter((l) => l.stampChecked).length - sealedN} stamped and checked` +
        `${through ? `, ${through} dated through a later stamp` : ""}${uncheckable ? `, ${uncheckable} stamped but not checkable here` : ""}${unstamped ? `, ${unstamped} not stamped` : ""}`;
    return { lines, unlocked: windows.unlocked, restored: windows.restored, clock, holds, unstamped, summary };
  } finally {
    rmSync(rootsDir, { recursive: true, force: true });
  }
}

export function formatVerify(r: VerifyReport, o: { offline?: boolean } = {}): string {
  const out: string[] = [];
  const anySeal = r.lines.some((l) => l.seal.length > 0);
  out.push(anySeal
    ? `SealHour: verifying ${r.lines.length} checkpoint(s) kept on this machine${o.offline ? " (offline)" : ""}; everything below is checked here, against this machine's audit log, SealHour's pinned receipt key and the pinned certificates of the time stamp services`
    : `SealHour interim: verifying ${r.lines.length} checkpoint(s) kept on this machine${o.offline ? " (offline)" : ""}; everything below is checked here, against this machine's audit log and the services' pinned roots`);
  const ssl = findOpenssl();
  out.push(`  stamps checked with: ${ssl ? `${ssl.version}${ssl.libressl ? " (LibreSSL: some stamps cannot be checked with it)" : ""}` : "OpenSSL not found: the stamps cannot be checked on this machine"}`);
  if (r.unlocked) out.push("  (read while a rotation of the audit log held its lock: if a window does not match, run verify again)");
  for (const l of r.lines) {
    out.push(`  #${l.seq}  ${l.created_at.replace("T", " ")}  ${l.count} record(s)${l.repos ? ` + ${l.repos} repositor${l.repos === 1 ? "y" : "ies"}` : ""}  digest ${l.digest.slice(0, 16)}`);
    out.push(`      [${l.shape.mark}] ${l.shape.detail}`);
    out.push(`      [${l.chain.mark}] chain: ${l.chain.detail}`);
    out.push(`      [${l.window.mark}] window: ${l.window.detail}`);
    if (l.code) out.push(`      [${l.code.mark}] code: ${l.code.detail}`);
    for (const s of l.stamps) {
      const when = s.time ? ` ${s.time.slice(0, 19).replace("T", " ")}Z` : "";
      const off = s.mark === "OK" && !s.late && s.time ? ` (${sign(Math.round((Date.parse(s.time) - Date.parse(l.created_at)) / 1000))})` : "";
      out.push(`      [${s.mark}] stamp ${s.name}:${when}${off}${s.mark === "OK" ? "" : ` ${s.detail}`}`);
    }
    for (const x of l.seal) out.push(`      [${x.mark}] ${x.text}`);
    if (!l.stamped && !l.coveredBy && l.seal.length === 0) out.push("      not stamped: no service has stamped this checkpoint yet");
    for (const f of l.flags) out.push(`      note: ${f}`);
  }
  out.push(`  Clock: ${r.clock}`);
  out.push(`Result: ${r.summary}.`);
  return out.join("\n");
}

// ---------- export-evidence ----------

function parseBound(s: string, end: boolean): number {
  if (/^\d{4}-\d\d-\d\d$/.test(s)) return Date.parse(`${s}T${end ? "23:59:59" : "00:00:00"}Z`);
  const t = Date.parse(s);
  if (Number.isNaN(t)) throw new Error(`not a date: ${s} (use YYYY-MM-DD or an ISO time)`);
  return t;
}

/** The checkpoints made between `from` and `to` (dates or ISO times, UTC). */
export function checkpointsBetween(from: string, to: string): StoredCheckpoint[] {
  const a = parseBound(from, false);
  const b = parseBound(to, true);
  return listCheckpoints().filter((c) => {
    const t = Date.parse(c.checkpoint.created_at);
    return t >= a && t <= b;
  });
}

/**
 * Write the checkpoints made between `from` and `to` (dates or ISO times, UTC), their stamps, the pinned
 * roots, a README in English and in French, and verify.mjs, a checker that needs only Node and OpenSSL.
 * A sealed checkpoint's folder is its proof exactly as SealHour served it (the contract's names only):
 * SealHour's free checker reads that folder as it is. The code leaves stay on this machine. Never
 * writes into a folder that exists.
 */
export function exportEvidence(o: { from: string; to: string; out: string }): { dir: string; count: number; sealed: number; pendingBitcoin: number } {
  const picked = checkpointsBetween(o.from, o.to);
  if (picked.length === 0) throw new Error(`no checkpoint made between ${o.from} and ${o.to}`);
  if (existsSync(o.out)) throw new Error(`${o.out} exists: choose a new folder (nothing is ever written over)`);
  mkdirSync(join(o.out, "checkpoints"), { recursive: true });
  mkdirSync(join(o.out, "certs"));
  const used = new Set<string>();
  let sealed = 0;
  let pendingBitcoin = 0;
  for (const c of picked) {
    const to2 = join(o.out, "checkpoints", c.name);
    mkdirSync(to2);
    if (backendOf(c) === "sealhour" && existsSync(proofDir(c))) {
      // [LOCK] [A-BUNDLE-WRITES-ONLY-THE-CONTRACT-S-NAMES]: readBundleDir() hands back those names only.
      for (const [name, data] of readBundleDir(proofDir(c))) {
        if (!BUNDLE_NAME.test(name)) continue;
        mkdirSync(dirname(join(to2, name)), { recursive: true });
        writeFileSync(join(to2, name), data);
      }
      sealed++;
      if (c.meta.seal?.bitcoin === "pending") pendingBitcoin++;
      continue;
    }
    copyFileSync(join(c.dir, "checkpoint.json"), join(to2, "checkpoint.json"));
    if (existsSync(join(c.dir, "receipt.json"))) copyFileSync(join(c.dir, "receipt.json"), join(to2, "receipt.json"));
    const stamps: Record<string, { name: string; ca_file: string; time: string | null; first_try: boolean }> = {};
    for (const f of readdirSync(c.dir).filter((x) => /^checkpoint\.[a-z0-9-]+\.tsr$/.test(x))) {
      const id = f.split(".")[1];
      const p = pinnedRoot(id);
      if (!p) continue;
      copyFileSync(join(c.dir, f), join(to2, f));
      let time: string | null = null;
      try { time = parseTsr(readFileSync(join(c.dir, f))).time; } catch { time = null; }
      stamps[id] = { name: p.name, ca_file: `certs/${id}-ca.pem`, time, first_try: c.stamps[id]?.first_try ?? true };
      used.add(id);
    }
    writeFileSync(join(to2, "stamps.json"), JSON.stringify(stamps, null, 2) + "\n");
  }
  for (const id of used) writeFileSync(join(o.out, "certs", `${id}-ca.pem`), pinnedRoot(id)!.caPem);
  writeFileSync(join(o.out, "README.txt"), sealed > 0 ? README_SEALED_EN : README_EN);
  writeFileSync(join(o.out, "LISEZMOI.txt"), sealed > 0 ? README_SEALED_FR : README_FR);
  // The checker knows the pinned key and certificates, never a test stand-in's: a proof made against a
  // stand-in shows [??] outside --trust-folder. [LOCK] [A-RECEIPT-COUNTS-ONLY-UNDER-A-PINNED-KEY]
  writeFileSync(join(o.out, "verify.mjs"), verifyMjs({ keys: Object.fromEntries(RECEIPT_KEYS.map((k) => [k.id, publicKeyHex(k.pem)])), anchors: STAMP_ANCHORS }));
  return { dir: o.out, count: picked.length, sealed, pendingBitcoin };
}

const README_EN = `OpsContext checkpoints and their time stamps (SealHour, interim mode)

What this folder is
  Each folder under checkpoints/ holds one checkpoint of an OpsContext audit log: a few SHA-256
  fingerprints of the log's records (records_root covers every record of its window, one leaf per
  record), their number, the time on the owner's machine, and, when the owner said yes, one fingerprint
  for all the workspace repositories. Each checkpoint names the one before it, so they form a chain.
  The SHA-256 of a checkpoint (its canonical JSON: keys sorted, no spaces, UTF-8) was sent to free public
  time stamp services, which signed it with their time (RFC 3161): checkpoint.<service>.tsr.

What it proves
  That this checkpoint existed no later than the stamp's time. A date, not ownership. With the owner's
  audit log, anyone can recompute records_root and see that the records it covers are the ones that
  existed then: the log is tamper-evident, with an outside time stamp. These are free services, stamped
  directly (interim mode): not the official European stamp, no Bitcoin, no SealHour receipt.

How to check it, offline, without OpsContext (Node 18 or later, OpenSSL 3)
  node verify.mjs .                 the checkpoints, their chain, every stamp
  node verify.mjs . audit.jsonl     the same, and each records_root recomputed from the owner's log
                                    (one JSON record per line, in the log's order, from
                                    "contextengine audit-export --format jsonl")

By hand, for one stamp:
  1. the checkpoint's digest:
     python3 -c 'import json,hashlib,sys; print(hashlib.sha256(json.dumps(json.load(open(sys.argv[1])),
       sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()).hexdigest())' checkpoint.json
  2. openssl ts -verify -digest <that digest> -in checkpoint.<service>.tsr -CAfile ../../certs/<service>-ca.pem
     (add -attime <the stamp's time, in seconds since 1970> once the service's certificate has expired)
  3. openssl ts -reply -in checkpoint.<service>.tsr -text     shows the stamp's time.

Limits
  A checkpoint made while part of the log was missing matches the log without the part put back later;
  the owner's "contextengine anchor verify" checks both readings. A stamp proves the time of the
  fingerprint, not who wrote the records. A check that cannot run is printed [??], never [OK].
`;

const README_FR = `Relevés OpsContext et leurs tampons horodatés (SealHour, mode intérimaire)

Ce dossier
  Chaque dossier sous checkpoints/ contient un relevé du journal d'audit OpsContext : quelques empreintes
  SHA-256 des enregistrements (records_root couvre chaque enregistrement de sa fenêtre, une feuille par
  enregistrement), leur nombre, l'heure de la machine et, si le propriétaire l'a accepté, une empreinte
  pour tous les dépôts de ses espaces de travail. Chaque relevé nomme le précédent : ils forment une chaîne.
  L'empreinte SHA-256 de chaque relevé (son JSON canonique : clés triées, sans espaces, UTF-8) a été
  envoyée à des services publics et gratuits d'horodatage, qui l'ont signée avec leur heure (RFC 3161) :
  checkpoint.<service>.tsr.

Ce que cela prouve
  Que le relevé existait au plus tard à l'heure du tampon. Une date, pas une propriété. Avec le journal du
  propriétaire, chacun peut recalculer records_root et constater que les enregistrements couverts sont
  bien ceux qui existaient alors. Ce sont des services gratuits, utilisés directement (mode intérimaire) :
  pas le tampon officiel européen, pas de Bitcoin, pas de reçu SealHour.

Vérifier, hors ligne, sans OpsContext (Node 18 ou plus, OpenSSL 3)
  node verify.mjs .                 les relevés, leur chaîne, chaque tampon
  node verify.mjs . audit.jsonl     idem, plus records_root recalculé depuis le journal du propriétaire

Limites
  Un relevé fait pendant qu'une partie du journal manquait correspond au journal sans la partie remise
  ensuite ; "contextengine anchor verify" chez le propriétaire essaie les deux lectures. Une vérification
  qui ne peut pas tourner s'affiche [??], jamais [OK].
`;

const README_SEALED_EN = `OpsContext checkpoints sealed by SealHour

What this folder is
  Each folder under checkpoints/ holds one checkpoint of an OpsContext audit log: a few SHA-256
  fingerprints of the log's records (records_root covers every record of its window, one leaf per
  record), their number, the time on the owner's machine, and, when the owner said yes, one fingerprint
  for all the workspace repositories. Each checkpoint names the one before it, so they form a chain.
  A folder that holds leaf.json is a proof as SealHour served it: the checkpoint, SealHour's signed
  receipt for it, its place in the hour SealHour sealed (leaf.json, path.json, root.bin), the time stamp
  of that hour by an official European provider (root.<name>.tsr; stamps.json names the provider) and
  its Bitcoin attestation (root.bin.ots). Its own README.txt says how to check it by hand.
  A folder without leaf.json is a checkpoint with no seal of its own (stamped directly by a free public
  service in interim mode, or not sealed yet): the next sealed checkpoint names it through the chain
  and dates it, at that later date.

What it proves
  That each sealed checkpoint existed no later than its hour's stamp. A date, not ownership. The
  official stamp is of the hour; the checkpoint is included in the stamped hour, verifiable by anyone.
  With the owner's audit log, anyone can recompute records_root and see that the records it covers are
  the ones that existed then: the log is tamper-evident, with an outside time stamp.

How to check it, offline, without OpsContext and without SealHour
  SealHour's free checker, one file (Python 3.9 or later, OpenSSL 3), one proof folder at a time:
      python3 sealhour_verify.py checkpoints/<a folder that holds leaf.json>
    The file is at https://sealhour.com/sealhour_verify.py and the keys it knows are listed at
    https://sealhour.com/keys/ . Exit code 0: the proof holds; 1: it does not; 2: nothing is wrong,
    but no date was checked. It also checks the Bitcoin attestation (it asks public block explorers
    for one block, unless --offline).
  This folder's own checker (Node 18 or later, OpenSSL 3), for the whole folder and the chain:
      node verify.mjs .                 the checkpoints, their chain, every receipt, path and stamp
      node verify.mjs . audit.jsonl     the same, and each records_root recomputed from the owner's log
                                        (one JSON record per line, in the log's order, from
                                        "contextengine audit-export --format jsonl")

Limits
  The Bitcoin attestation comes hours after the seal: a proof exported before says it is pending;
  "contextengine anchor export-evidence --refresh" fetches the complete one. A checkpoint made while
  part of the log was missing matches the log without the part put back later; the owner's
  "contextengine anchor verify" checks both readings. A stamp proves the time of the fingerprint, not
  who wrote the records. A check that cannot run is printed [??], never [OK].
`;

const README_SEALED_FR = `Relevés OpsContext scellés par SealHour

Ce dossier
  Chaque dossier sous checkpoints/ contient un relevé du journal d'audit OpsContext : quelques empreintes
  SHA-256 des enregistrements (records_root couvre chaque enregistrement de sa fenêtre, une feuille par
  enregistrement), leur nombre, l'heure de la machine et, si le propriétaire l'a accepté, une empreinte
  pour tous les dépôts de ses espaces de travail. Chaque relevé nomme le précédent : ils forment une chaîne.
  Un dossier qui contient leaf.json est une preuve telle que SealHour l'a servie : le relevé, le reçu
  signé de SealHour, sa place dans l'heure que SealHour a scellée (leaf.json, path.json, root.bin), le
  tampon de cette heure par un prestataire officiel européen (root.<nom>.tsr ; stamps.json nomme le
  prestataire) et son inscription dans Bitcoin (root.bin.ots). Son propre LISEZMOI.txt dit comment la
  vérifier à la main.
  Un dossier sans leaf.json est un relevé sans sceau à lui (tamponné directement par un service public
  gratuit en mode intérimaire, ou pas encore scellé) : le relevé scellé suivant le nomme par la chaîne
  et le date, à cette date plus tardive.

Ce que cela prouve
  Que chaque relevé scellé existait au plus tard à l'heure du tampon de son heure. Une date, pas une
  propriété. Le tampon officiel porte sur l'heure ; le relevé est inclus dans l'heure tamponnée, ce que
  chacun peut vérifier. Avec le journal du propriétaire, chacun peut recalculer records_root et constater
  que les enregistrements couverts sont bien ceux qui existaient alors.

Vérifier, hors ligne, sans OpsContext et sans SealHour
  Le vérificateur gratuit de SealHour, un seul fichier (Python 3.9 ou plus, OpenSSL 3), un dossier de
  preuve à la fois :
      python3 sealhour_verify.py checkpoints/<un dossier qui contient leaf.json>
    Le fichier est à https://sealhour.com/sealhour_verify.py et les clés qu'il connaît sont listées à
    https://sealhour.com/keys/ . Code de sortie 0 : la preuve tient ; 1 : elle ne tient pas ; 2 : rien
    de faux, mais aucune date n'a été vérifiée. Il vérifie aussi l'inscription dans Bitcoin (il demande
    un bloc à des explorateurs publics, sauf avec --offline).
  Le vérificateur de ce dossier (Node 18 ou plus, OpenSSL 3), pour tout le dossier et la chaîne :
      node verify.mjs .                 les relevés, leur chaîne, chaque reçu, chemin et tampon
      node verify.mjs . audit.jsonl     idem, plus records_root recalculé depuis le journal du propriétaire

Limites
  L'inscription dans Bitcoin arrive des heures après le sceau : une preuve exportée avant le dit ;
  "contextengine anchor export-evidence --refresh" va chercher la preuve complète. Un relevé fait pendant
  qu'une partie du journal manquait correspond au journal sans la partie remise ensuite ;
  "contextengine anchor verify" chez le propriétaire essaie les deux lectures. Une vérification qui ne
  peut pas tourner s'affiche [??], jamais [OK].
`;
