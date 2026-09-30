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
  isStamped,
  listCheckpoints,
  newConfig,
  readConfig,
  readState,
  writeConfig,
  writeState,
} from "./anchor.js";
import { exportEvidence, formatVerify, verifyAnchors } from "./anchor-verify.js";

const USAGE = `Usage: contextengine anchor <command>
  enable [--code yes|no] [--start yes|no]   Show what leaves this machine and ask; nothing starts without a yes
  status                                    One line, then the details (exit 1 when the chain is not stamped as it should be)
  code on|off                               Include the workspaces' code in the checkpoints, or not
  copy <folder>|off                         Keep a copy of the checkpoints and stamps off this machine (a synced or shared folder)
  verify [--offline]                        Recompute every checkpoint from this machine's log and check every stamp
  export-evidence <from> <to> [--out dir]   Write the checkpoints and stamps of a period, with a checker anyone can run
  tick [--now]                              Run the hourly job by hand (--now: a checkpoint now if the log grew)
  disable                                   Stop; nothing leaves this machine any more, what was made is kept`;

/** The interim enable screen. [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] */
export function enableScreen(providers: Provider[]): string {
  const names = providers.map((p) => p.name).join(" and ");
  const n = providers.length === 2 ? "two" : String(providers.length);
  return [
    "SealHour seals your work every hour, so you can prove later that it existed by then:",
    "an outside time stamp from an official European provider, written into Bitcoin.",
    "",
    "The SealHour service is not open yet. Until it is, OpsContext runs in interim mode: it has each",
    `checkpoint stamped directly by ${n} free public time stamp services, ${names}.`,
    "An outside date today; not yet the official European stamp, Bitcoin or a SealHour receipt.",
    "Moving to the SealHour service will ask you again.",
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
  const providers = activeProviders();
  process.stdout.write(enableScreen(providers) + "\n");
  const yesAll = args.includes("--yes") || args.includes("-y");
  let codeAns = flag(args, "--code") ?? (yesAll ? "" : undefined);
  let startAns = flag(args, "--start") ?? (yesAll ? "" : undefined);
  let reader: ReturnType<typeof lineReader> | null = null;
  try {
    if (codeAns === undefined) {
      reader = lineReader();
      codeAns = (await reader.ask(CODE_QUESTION)) ?? undefined;
      if (codeAns === undefined) {
        console.log("No answer: nothing was stored, nothing will leave this machine.");
        return 1;
      }
    } else {
      console.log(`${CODE_QUESTION}${codeAns}`);
    }
    if (startAns === undefined) {
      reader = reader ?? lineReader();
      startAns = (await reader.ask(START_QUESTION)) ?? undefined;
    } else {
      console.log(`${START_QUESTION}${startAns}`);
    }
  } finally {
    reader?.close();
  }
  const code = !/^\s*n/i.test(codeAns);
  // [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES]: only an explicit yes starts; the default is no.
  if (startAns === undefined || !/^\s*y(es)?\s*$/i.test(startAns)) {
    const had = readConfig();
    console.log(had?.enabled
      ? "\nNothing changed: SealHour stays on as you set it before. To stop it: contextengine anchor disable."
      : "\nNot started: nothing was stored, nothing will leave this machine.");
    return 0;
  }
  const now = new Date();
  const cfg = await withLock(() => {
    const had = readConfig();
    const fresh = newConfig({ code, providers: providers.map((p) => p.id), now });
    const c = had ? { ...had, enabled: true, code, consent: fresh.consent, enabled_at: fresh.enabled_at, disabled_at: null } : fresh;
    writeConfig(c);
    return c;
  });
  safeAppend("anchor.enable", { code, backend: cfg.backend, providers: cfg.consent!.providers, screen: ANCHOR_SCREEN_VERSION });
  const repos = code ? workspaceRepos().length : 0;
  const minute = String(Math.floor(cfg.slot_seconds / 60)).padStart(2, "0");
  const what = !code ? "chain only" : repos === 0 ? "chain + code (no git repository in the workspaces yet)" : `chain + ${repos} repositor${repos === 1 ? "y" : "ies"}`;
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
  console.log(copied.error ? `Copy off this machine: ${dir}, but the first copy FAILED: ${copied.error}` : `Copy off this machine: ${dir} (checkpoints and stamps, never the code leaves), copied now and after every checkpoint.`);
  return copied.error ? 1 : 0;
}

function cmdStatus(): number {
  const h = anchorHealth();
  const pol = anchoringPolicy();
  console.log(h.line);
  const cfg = readConfig();
  if (cfg) {
    const all = listCheckpoints();
    const providers = activeProviders().filter((p) => cfg.consent?.providers.includes(p.id));
    console.log(`  interim mode: each checkpoint is stamped directly by ${providers.map((p) => p.name).join(" and ") || "no service"} (free public time stamp services), until the SealHour service opens: an outside date, not yet the official European stamp, Bitcoin or a SealHour receipt`);
    console.log(`  code: ${cfg.code ? `on${h.repos ? ` (${h.repos} repositor${h.repos === 1 ? "y" : "ies"} in the last checkpoint)` : ""}` : "off"}`);
    console.log(`  checkpoints: ${all.length} kept in ${anchorsDir()} (${all.filter(isStamped).length} stamped, ${all.length - all.filter(isStamped).length} queued)`);
    if (cfg.enabled) console.log(`  hourly slot: about minute ${String(Math.floor(cfg.slot_seconds / 60)).padStart(2, "0")}; last run ${h.lastTickAt ? `${h.lastTickAt.slice(0, 16).replace("T", " ")}Z` : "not yet"}`);
    const ssl = findOpenssl();
    console.log(`  stamps checked with: ${ssl ? ssl.version : "no openssl on this machine (stamps are kept, not checked)"}`);
  }
  console.log(`  policy: ${pol.where ? `${pol.where}: ${pol.error ?? (pol.required ? "anchoring required" : "anchoring not required")}` : "no policy.json here"}`);
  if (pol.required && (!h.enabled || h.problem)) {
    console.log(`  ERROR: ${pol.where} requires the audit chain to be stamped: ${h.enabled ? h.problem : "SealHour is off on this machine (contextengine anchor enable)"}`);
    return 1;
  }
  return h.problem ? 1 : 0;
}

function cmdVerify(args: string[]): number {
  const r = verifyAnchors();
  console.log(formatVerify(r, { offline: args.includes("--offline") }));
  const pol = anchoringPolicy();
  if (pol.required && (r.unstamped > 0 || r.lines.length === 0)) {
    console.log(`ERROR: ${pol.where} requires the audit chain to be stamped: ${r.lines.length === 0 ? "no checkpoint on this machine" : `${r.unstamped} checkpoint(s) not stamped`}.`);
    return 1;
  }
  return r.holds ? 0 : 1;
}

function cmdExport(args: string[]): number {
  const pos = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--out");
  const [from, to] = pos;
  if (!from || !to) {
    console.error("Usage: contextengine anchor export-evidence <from> <to> [--out <folder>]   (dates YYYY-MM-DD or ISO times, UTC)");
    return 1;
  }
  const out = resolve(flag(args, "--out") ?? `sealhour-evidence-${from}_${to}`.replace(/[:]/g, "-"));
  const r = exportEvidence({ from, to, out });
  console.log(`${r.count} checkpoint(s) and their stamps written to ${r.dir}.`);
  console.log(`Anyone can check them, offline, without OpsContext: node ${join(r.dir, "verify.mjs")} ${r.dir}`);
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
    case "export-evidence": code = cmdExport(rest); break;
    case "tick": code = await cmdTick(rest); break;
    default:
      console.error(USAGE);
      code = sub ? 1 : 0;
  }
  process.exit(code);
}
