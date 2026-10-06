// `contextengine anchor ...`: the owner's side of the SealHour client (plan docs/SEALHOUR_INTEGRATION_PLAN.md
// section 7, the enable screen; COMPR-TSA docs/SEALHOUR_PROTOCOL.md section 10, the words).
//
// [LOCKED] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] - 2026-09-30
// [NEVER] store anything, or chain a consent record, before the answer to the start question; never make
//         yes the default of that question; never show a screen that promises less, or more, than what
//         the backend in use really sends.
// WHY: the plan's first screen said "a 32-byte fingerprint of your audit chain" while the contract's
//      checkpoint carries a few fingerprints, two numbers and a time; Yan approved the corrected words on
//      2026-09-30 (contract section 10, correction 7). In interim mode even less leaves: only the
//      checkpoint's digest goes out, to the free services this screen names, and no licence key. Consent
//      given to one backend is not consent to another.
// FIX: two questions, code (default yes) then start (default no); nothing written before the second
//      answer; the screen names the services and says what reaches them; the recorded consent names the
//      backend and the services, and the hourly job uses no other. `--yes` never answers the start question.
//      2026-10-05, the SealHour service: its screen is the contract's (section 10), it says the
//      checkpoint itself leaves, with the licence key, or with a pilot code when this machine has no
//      licence, and the consent records which of the two; a machine in interim mode is asked again and
//      stays as it was on anything but a yes; the pilot code is made after the yes, never before.
import { createInterface } from "readline";
import { existsSync, statSync } from "fs";
import { isAbsolute, join, resolve } from "path";
import { safeAppend } from "./audit.js";
import { activeProviders, findOpenssl, type Provider } from "./anchor-tsa.js";
import { workspaceRepos } from "./anchor-code.js";
import {
  ANCHOR_SCREEN_VERSION,
  acquireAnchorLock,
  anchorHealth,
  anchoringPolicy,
  anchorTick,
  anchorsDir,
  copyOffMachine,
  backendOf,
  isSealed,
  isStamped,
  listCheckpoints,
  newConfig,
  readConfig,
  readState,
  writeConfig,
  writeState,
} from "./anchor.js";
import { checkpointsBetween, exportEvidence, formatVerify, verifyAnchors } from "./anchor-verify.js";
import { activeService, ensurePilotToken, serviceName, LICENCE_KEY, type Service } from "./anchor-service.js";
import { fetchProof, type SealCheckpoint } from "./anchor-seal.js";
import { quietLicence } from "./activation.js";

const USAGE = `Usage: contextengine anchor <command>
  enable [--code yes|no] [--start yes|no]   Show what leaves this machine and ask; nothing starts without a yes
         [--interim]                        ...with free public time stamp services asked directly, not the SealHour service
  status                                    One line, then the details (exit 1 when the chain is not sealed or stamped as it should be)
  code on|off                               Include the workspaces' code in the checkpoints, or not
  copy <folder>|off                         Keep a copy of the checkpoints, receipts and proofs off this machine (a synced or shared folder)
  verify [--offline]                        Recompute every checkpoint from this machine's log and check every receipt, proof and stamp
  export-evidence <from> <to> [--out dir]   Write the checkpoints and proofs of a period, with a checker anyone can run
         [--refresh]                        ...after fetching each proof again (its Bitcoin attestation comes hours after the seal)
  tick [--now]                              Run the hourly job by hand (--now: a checkpoint now if the log grew)
  disable                                   Stop; nothing leaves this machine any more, what was made is kept`;

/**
 * The SealHour service's enable screen: the contract's words (section 10, correction 7), and what this
 * machine will really send as its credential. [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES]
 */
export function sealScreen(o: { credential: "licence" | "pilot"; why?: string; fromInterim: boolean; service: Service }): string {
  const to = o.service.test ? serviceName(o.service) : "SealHour (api.sealhour.com)";
  return [
    "SealHour seals your work every hour, so you can prove later that it existed by then:",
    "an outside time stamp from an official European provider, written into Bitcoin.",
    "A date, not ownership.",
    "",
    ...(o.fromInterim ? [
      "This machine is in interim mode today (free public time stamp services, asked directly).",
      "A yes below moves it to the SealHour service: the free services are no longer asked, and",
      "what they stamped is kept.",
      "",
    ] : []),
    "Once an hour, while OpsContext runs and only if your audit chain grew, OpsContext makes a",
    `checkpoint on this machine and sends it to ${to}.`,
    "SealHour answers with a signed receipt and keeps the checkpoint, so a lost or rewritten disk",
    "does not lose the proof. At minute 2 of the next hour it seals the checkpoints of the hour",
    "together, has that seal stamped by the official provider and writes it into Bitcoin. The",
    "proof comes back to this machine; anyone can check it without OpsContext and without SealHour.",
    "",
    "What leaves this machine, once an hour, while OpsContext runs:",
    "  - a checkpoint of your OpsContext audit chain: a few 32-byte fingerprints, the number of",
    "    records and the time; never a record;",
    "  - if you say yes below, one fingerprint for all your workspace repositories, and their",
    "    number; never a file, never code, never a name;",
    ...(o.credential === "licence" ? [
      "  - your licence key, and, as with any web request, this machine's address and the time.",
    ] : [
      "  - a pilot code made on this machine when you say yes (random: it names no one), and, as",
      "    with any web request, this machine's address and the time.",
    ]),
    "SealHour learns the hours you were active, to the hour. Nothing else leaves: no record, no file,",
    "no code, no name. Off any time: contextengine anchor disable.",
    "",
    ...(o.credential === "licence"
      ? ["SealHour is included in OpsContext Team and Enterprise, and open to every licence while its pilot lasts."]
      : [
        `No OpsContext licence is used: ${o.why ?? "this machine has none"}. The pilot code works while`,
        "the SealHour pilot lasts; after it, SealHour is included in OpsContext Team and Enterprise.",
      ]),
    "",
  ].join("\n");
}

export const SEAL_CODE_QUESTION = "Seal the code of your workspaces too?  [Y/n] ";
export const SEAL_START_QUESTION = "Start sealing?                         [y/N] ";

/** The interim enable screen. [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] */
export function enableScreen(providers: Provider[]): string {
  const names = providers.map((p) => p.name).join(" and ");
  const n = providers.length === 2 ? "two" : String(providers.length);
  return [
    "SealHour seals your work every hour, so you can prove later that it existed by then:",
    "an outside time stamp from an official European provider, written into Bitcoin.",
    "",
    "Interim mode, in place of the SealHour service: OpsContext has each checkpoint stamped",
    `directly by ${n} free public time stamp services, ${names}.`,
    "An outside date; not the official European stamp, not Bitcoin, no SealHour receipt.",
    "The SealHour service itself: contextengine anchor enable (it asks again).",
    "",
    "Once an hour, while OpsContext runs and only if your audit chain grew, OpsContext makes a",
    "checkpoint on this machine: a few 32-byte fingerprints of your audit chain, the number of",
    "records and the time, and, if you say yes below, one fingerprint for all your workspace",
    "repositories and their number. The checkpoint stays on this machine.",
    "",
    "What leaves this machine, once an hour:",
    "  - one 32-byte fingerprint of that checkpoint, to each of the time stamp services above;",
    "  - as with any web request, this machine's address and the time.",
    "They learn the hours you were active, to the hour. Nothing else leaves: no record, no file,",
    "no code, no name, no licence key. Off any time: contextengine anchor disable.",
    "",
  ].join("\n");
}

export const CODE_QUESTION = "Stamp the code of your workspaces too?  [Y/n] ";
export const START_QUESTION = "Start stamping?                         [y/N] ";

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

/** Answers from stdin, one line each; null when the input ends first. Created only when a question
 *  has to be asked, so a scripted call with both answers never waits on stdin. */
function lineReader(): { ask(q: string): Promise<string | null>; close(): void } {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const it = rl[Symbol.asyncIterator]();
  return {
    async ask(q: string) {
      process.stdout.write(q);
      const r = await it.next();
      if (r.done) {
        process.stdout.write("\n");
        return null;
      }
      if (!process.stdin.isTTY) process.stdout.write(`${r.value}\n`);
      return r.value;
    },
    close: () => rl.close(),
  };
}

/** Wait a little for the anchor lock (the hourly job holds it for seconds at most). */
async function withLock<T>(fn: () => T): Promise<T> {
  for (let i = 0; i < 40; i++) {
    const release = acquireAnchorLock();
    if (release) {
      try { return fn(); } finally { release(); }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("the hourly job holds the anchor lock; try again in a minute");
}


async function cmdEnable(args: string[]): Promise<number> {
  const interim = args.includes("--interim");
  const providers = interim ? activeProviders() : [];
  const before = readConfig();
  // What this machine would send as its credential: its licence key when it holds a usable one, else
  // a pilot code. Decided before the screen, shown on it, recorded with the yes.
  const lic = interim ? null : quietLicence();
  const licOk = !!lic && !("problem" in lic) && LICENCE_KEY.test(lic.key);
  const credential: "licence" | "pilot" = licOk ? "licence" : "pilot";
  const service = interim ? null : activeService();
  process.stdout.write((service
    ? sealScreen({ credential, why: lic && "problem" in lic ? lic.problem : lic ? "its key is not of the shape SealHour takes" : undefined, fromInterim: !!before?.enabled && before.backend === "rfc3161", service })
    : enableScreen(providers)) + "\n");
  const codeQ = service ? SEAL_CODE_QUESTION : CODE_QUESTION;
  const startQ = service ? SEAL_START_QUESTION : START_QUESTION;
  const yesAll = args.includes("--yes") || args.includes("-y");
  let codeAns = flag(args, "--code") ?? (yesAll ? "" : undefined);
  let startAns = flag(args, "--start") ?? (yesAll ? "" : undefined);
  let reader: ReturnType<typeof lineReader> | null = null;
  try {
    if (codeAns === undefined) {
      reader = lineReader();
      codeAns = (await reader.ask(codeQ)) ?? undefined;
      if (codeAns === undefined) {
        console.log("No answer: nothing was stored, nothing will leave this machine.");
        return 1;
      }
    } else {
      console.log(`${codeQ}${codeAns}`);
    }
    if (startAns === undefined) {
      reader = reader ?? lineReader();
      startAns = (await reader.ask(startQ)) ?? undefined;
    } else {
      console.log(`${startQ}${startAns}`);
    }
  } finally {
    reader?.close();
  }
  const code = !/^\s*n/i.test(codeAns);
  // [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES]: only an explicit yes starts; the default is no.
  if (startAns === undefined || !/^\s*y(es)?\s*$/i.test(startAns)) {
    const had = readConfig();
    console.log(had?.enabled
      ? `\nNothing changed: SealHour stays on as you set it before${had.backend === "rfc3161" ? " (interim mode)" : ""}. To stop it: contextengine anchor disable.`
      : "\nNot started: nothing was stored, nothing will leave this machine.");
    return 0;
  }
  const now = new Date();
  const cfg = await withLock(() => {
    const had = readConfig();
    const fresh = newConfig({ code, providers: service ? ["sealhour"] : providers.map((p) => p.id), now, backend: service ? "sealhour" : "rfc3161", credential });
    const c = had ? { ...had, enabled: true, code, backend: fresh.backend, consent: fresh.consent, enabled_at: fresh.enabled_at, disabled_at: null } : fresh;
    // Made only now, after the yes. [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES]
    if (service && credential === "pilot") ensurePilotToken();
    writeConfig(c);
    if (had && had.backend !== c.backend) {
      // The queue's hold belongs to the backend that set it.
      const st = readState();
      st.hold = null;
      st.next_due = null;
      writeState(st);
    }
    return c;
  });
  safeAppend("anchor.enable", { code, backend: cfg.backend, providers: cfg.consent!.providers, screen: ANCHOR_SCREEN_VERSION, ...(service ? { credential } : {}) });
  const repos = code ? workspaceRepos().length : 0;
  const minute = String(Math.floor(cfg.slot_seconds / 60)).padStart(2, "0");
  const what = !code ? "chain only" : repos === 0 ? "chain + code (no git repository in the workspaces yet)" : `chain + ${repos} repositor${repos === 1 ? "y" : "ies"}`;
  if (service) {
    console.log(`\n${serviceName(service)}: on, ${what}, every hour at about minute ${minute} when the chain grew. Each checkpoint is sealed at minute 2 of the hour after it.`);
    console.log(cfg.copy_dir ? `Copy off this machine: ${cfg.copy_dir}` : "A second copy of the receipts and proofs, off this machine: contextengine anchor copy <a synced or shared folder>");
    console.log("Later: contextengine anchor status | code off | verify | export-evidence <from> <to> [--refresh] | disable");
    return 0;
  }
  console.log(`\nSealHour interim: on, ${what}, every hour at about minute ${minute} when the chain grew. First stamp within the hour.`);
  console.log(cfg.copy_dir ? `Copy off this machine: ${cfg.copy_dir}` : "Keep a copy off this machine: contextengine anchor copy <a synced or shared folder>");
  console.log("Later: contextengine anchor status | code off | verify | export-evidence <from> <to> | disable");
  return 0;
}

async function cmdDisable(): Promise<number> {
  const cfg = readConfig();
  if (!cfg || !cfg.enabled) {
    console.log("SealHour: already off. Nothing leaves this machine.");
    return 0;
  }
  await withLock(() => writeConfig({ ...cfg, enabled: false, disabled_at: new Date().toISOString() }));
  safeAppend("anchor.disable", {});
  const n = listCheckpoints().length;
  console.log(`SealHour: off. Nothing leaves this machine from now on; the ${n} checkpoint(s) and their stamps stay in ${anchorsDir()}.`);
  return 0;
}

async function cmdCode(args: string[]): Promise<number> {
  const v = args[0];
  if (v !== "on" && v !== "off") {
    console.error("Usage: contextengine anchor code on|off");
    return 1;
  }
  const cfg = readConfig();
  if (!cfg) {
    console.error("SealHour is not set up on this machine: contextengine anchor enable");
    return 1;
  }
  await withLock(() => writeConfig({ ...cfg, code: v === "on" }));
  safeAppend("anchor.code", { code: v === "on" });
  console.log(v === "on" ? `Code: on. The next checkpoints cover ${workspaceRepos().length} workspace repositories with one fingerprint.` : "Code: off. The next checkpoints cover the audit chain only.");
  return 0;
}

async function cmdCopy(args: string[]): Promise<number> {
  const v = args[0];
  const cfg = readConfig();
  if (!v) {
    console.error("Usage: contextengine anchor copy <folder>|off");
    return 1;
  }
  if (!cfg) {
    console.error("SealHour is not set up on this machine: contextengine anchor enable");
    return 1;
  }
  if (v === "off") {
    await withLock(() => writeConfig({ ...cfg, copy_dir: null }));
    safeAppend("anchor.copy", { on: false });
    console.log("Copy off this machine: none. The stamps now live only on this disk.");
    return 0;
  }
  const dir = isAbsolute(v) ? v : resolve(v);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    console.error(`${dir} is not a folder on this machine.`);
    return 1;
  }
  const next = { ...cfg, copy_dir: dir };
  const copied = await withLock(() => {
    writeConfig(next);
    const r = copyOffMachine(next, new Date());
    const st = readState();
    st.copy = r;
    writeState(st);
    return r;
  });
  safeAppend("anchor.copy", { on: true });
  console.log(copied.error ? `Copy off this machine: ${dir}, but the first copy FAILED: ${copied.error}` : `Copy off this machine: ${dir} (checkpoints, stamps, receipts and proofs, never the code leaves), copied now and after every checkpoint.`);
  return copied.error ? 1 : 0;
}

function cmdStatus(): number {
  const h = anchorHealth();
  const pol = anchoringPolicy();
  console.log(h.line);
  const cfg = readConfig();
  if (cfg) {
    const all = listCheckpoints();
    if (cfg.backend === "sealhour") {
      let who = "SealHour";
      try { who = serviceName(activeService()); } catch { /* the line above says it */ }
      const mine = all.filter((c) => backendOf(c) === "sealhour");
      const count = (st: string) => mine.filter((c) => c.meta.seal?.state === st).length;
      const sealed = mine.filter(isSealed);
      const pendingBtc = sealed.filter((c) => c.meta.seal?.bitcoin === "pending").length;
      console.log(`  ${who} service: each checkpoint is sent with ${cfg.consent?.credential === "pilot" ? "this machine's pilot code" : "your licence key"}, sealed at minute 2 of the next hour with an official European time stamp, then written into Bitcoin; the receipt and the proof are kept here`);
      console.log(`  code: ${cfg.code ? `on${h.repos ? ` (${h.repos} repositor${h.repos === 1 ? "y" : "ies"} in the last checkpoint)` : ""}` : "off"}`);
      console.log(`  checkpoints: ${all.length} kept in ${anchorsDir()} (${sealed.length} sealed, ${count("received")} received and waiting for their hour, ${count("queued")} queued, ${count("missed") + count("refused")} without a seal of their own${all.length - mine.length ? `, ${all.length - mine.length} from interim mode` : ""})`);
      if (sealed.length > 0) console.log(`  Bitcoin: ${sealed.length - pendingBtc} of ${sealed.length} kept proofs carry their attestation${pendingBtc ? `, ${pendingBtc} still pending (it comes hours after the seal; the hourly job fetches it, or: contextengine anchor export-evidence <from> <to> --refresh)` : ""}`);
    } else {
      const providers = activeProviders().filter((p) => cfg.consent?.providers.includes(p.id));
      console.log(`  interim mode: each checkpoint is stamped directly by ${providers.map((p) => p.name).join(" and ") || "no service"} (free public time stamp services): an outside date, not the official European stamp, Bitcoin or a SealHour receipt. The SealHour service is open: contextengine anchor enable moves this machine to it (it asks first)`);
      console.log(`  code: ${cfg.code ? `on${h.repos ? ` (${h.repos} repositor${h.repos === 1 ? "y" : "ies"} in the last checkpoint)` : ""}` : "off"}`);
      console.log(`  checkpoints: ${all.length} kept in ${anchorsDir()} (${all.filter(isStamped).length} stamped, ${all.length - all.filter(isStamped).length} queued)`);
    }
    if (cfg.enabled) console.log(`  hourly slot: about minute ${String(Math.floor(cfg.slot_seconds / 60)).padStart(2, "0")}; last run ${h.lastTickAt ? `${h.lastTickAt.slice(0, 16).replace("T", " ")}Z` : "not yet"}`);
    const ssl = findOpenssl();
    console.log(`  stamps checked with: ${ssl ? ssl.version : "no openssl on this machine (stamps are kept, not checked)"}`);
  }
  console.log(`  policy: ${pol.where ? `${pol.where}: ${pol.error ?? (pol.required ? "anchoring required" : "anchoring not required")}` : "no policy.json here"}`);
  if (pol.required && (!h.enabled || h.problem)) {
    console.log(`  ERROR: ${pol.where} requires the audit chain to be ${h.backend === "sealhour" ? "sealed" : "stamped"}: ${h.enabled ? h.problem : "SealHour is off on this machine (contextengine anchor enable)"}`);
    return 1;
  }
  return h.problem ? 1 : 0;
}

function cmdVerify(args: string[]): number {
  const r = verifyAnchors();
  console.log(formatVerify(r, { offline: args.includes("--offline") }));
  const pol = anchoringPolicy();
  if (pol.required && (r.unstamped > 0 || r.lines.length === 0)) {
    const sealing = readConfig()?.backend === "sealhour";
    console.log(`ERROR: ${pol.where} requires the audit chain to be ${sealing ? "sealed" : "stamped"}: ${r.lines.length === 0 ? "no checkpoint on this machine" : `${r.unstamped} checkpoint(s) not ${sealing ? "sealed" : "stamped"}`}.`);
    return 1;
  }
  return r.holds ? 0 : 1;
}

/**
 * `export-evidence --refresh` (contract section 5.3): ask SealHour again for each proof of the period,
 * so one fetched before its Bitcoin attestation existed is replaced by the complete one. Only the
 * digests are sent, without a credential, and only while the owner's yes to the service stands.
 * [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] (src/anchor.ts)
 */
async function refreshProofs(from: string, to: string): Promise<string> {
  const cfg = readConfig();
  if (!cfg || !cfg.enabled || cfg.backend !== "sealhour" || cfg.consent?.backend !== "sealhour") {
    return "Not refreshed: the SealHour service is off on this machine, so nothing is asked of it (contextengine anchor enable).";
  }
  const service = activeService();
  let release: (() => void) | null = null;
  for (let i = 0; i < 40 && !release; i++) {
    release = acquireAnchorLock();
    if (!release) await new Promise((r) => setTimeout(r, 250));
  }
  if (!release) return "Not refreshed: the hourly job holds the anchor lock; try again in a minute.";
  try {
    const mine = checkpointsBetween(from, to).filter((c) => backendOf(c) === "sealhour" && (c.meta.seal?.state === "sealed" || c.meta.seal?.state === "received"));
    let complete = 0;
    let pending = 0;
    let waiting = 0;
    for (const c of mine) {
      await fetchProof(c as SealCheckpoint, service, { now: () => new Date() });
      const s = (c as SealCheckpoint).meta.seal;
      if (s?.state !== "sealed") waiting++;
      else if (s.bitcoin === "complete") complete++;
      else pending++;
    }
    return `Refreshed from ${serviceName(service)}: ${mine.length} proof(s) asked again; ${complete} carry their Bitcoin attestation${pending ? `, ${pending} still pending (it comes hours after the seal)` : ""}${waiting ? `, ${waiting} not sealed yet` : ""}.`;
  } finally {
    release();
  }
}

async function cmdExport(args: string[]): Promise<number> {
  const pos = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--out");
  const [from, to] = pos;
  if (!from || !to) {
    console.error("Usage: contextengine anchor export-evidence <from> <to> [--out <folder>] [--refresh]   (dates YYYY-MM-DD or ISO times, UTC)");
    return 1;
  }
  const out = resolve(flag(args, "--out") ?? `sealhour-evidence-${from}_${to}`.replace(/[:]/g, "-"));
  if (existsSync(out)) {
    console.error(`${out} exists: choose a new folder (nothing is ever written over)`);
    return 1;
  }
  if (args.includes("--refresh")) console.log(await refreshProofs(from, to));
  const r = exportEvidence({ from, to, out });
  if (r.sealed > 0) {
    console.log(`${r.count} checkpoint(s) written to ${r.dir}: ${r.sealed} with the proof SealHour served for it${r.count - r.sealed ? `, ${r.count - r.sealed} without a seal of their own` : ""}.`);
    if (r.pendingBitcoin > 0) console.log(`${r.pendingBitcoin} proof(s) do not carry their Bitcoin attestation yet (it comes hours after the seal): export again later with --refresh.`);
    console.log(`Anyone can check them, offline, without OpsContext and without SealHour:`);
    console.log(`  the whole folder and its chain:  node ${join(r.dir, "verify.mjs")} ${r.dir}`);
    console.log(`  one proof, with SealHour's free checker (https://sealhour.com/sealhour_verify.py):  python3 sealhour_verify.py ${join(r.dir, "checkpoints", "<a folder>")}`);
  } else {
    console.log(`${r.count} checkpoint(s) and their stamps written to ${r.dir}.`);
    console.log(`Anyone can check them, offline, without OpsContext: node ${join(r.dir, "verify.mjs")} ${r.dir}`);
  }
  console.log("(the code leaves stay on this machine; README.txt says what the folder proves and what it does not)");
  return 0;
}

async function cmdTick(args: string[]): Promise<number> {
  const scheduled = args.includes("--scheduled");
  const r = await anchorTick({ force: args.includes("--now") });
  if (!scheduled) console.log(`SealHour: ${r.action}: ${r.detail}${r.retried ? ` (${r.retried} queued checkpoint(s) retried)` : ""}`);
  return r.action === "error" ? 1 : 0;
}

export async function cliAnchor(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  let code: number;
  switch (sub) {
    case "enable": code = await cmdEnable(rest); break;
    case "disable": code = await cmdDisable(); break;
    case "code": code = await cmdCode(rest); break;
    case "copy": code = await cmdCopy(rest); break;
    case "status": code = cmdStatus(); break;
    case "verify": code = cmdVerify(rest); break;
    case "export-evidence": code = await cmdExport(rest); break;
    case "tick": code = await cmdTick(rest); break;
    default:
      console.error(USAGE);
      code = sub ? 1 : 0;
  }
  process.exit(code);
}
