// `contextengine anchor ...`, run as the owner runs it (dist/cli.js; `npm run build` first).
// [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] (src/anchor-cli.ts) [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] (src/anchor.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { findOpenssl } from "../src/anchor-tsa.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";
import { sealScreen } from "../src/anchor-cli.js";
import { activeService, SEALHOUR_URL } from "../src/anchor-service.js";

const CLI = join(process.cwd(), "dist", "cli.js");
const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;

let tsa: FakeTsa;
let keys: string;
let home: string;
let cwd: string;

beforeAll(async () => {
  if (!haveOpenssl) return;
  keys = mkdtempSync(join(tmpdir(), "ce-anchor-ckeys-"));
  tsa = await startFakeTsa(keys, "test-a");
});
afterAll(async () => {
  if (!haveOpenssl) return;
  await tsa.close().catch(() => undefined);
  rmSync(keys, { recursive: true, force: true });
});
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "ce-anchor-chome-"));
  cwd = mkdtempSync(join(tmpdir(), "ce-anchor-cwd-"));
  if (haveOpenssl) tsa.requests.length = 0;
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(cwd, { recursive: true, force: true });
});

function run(args: string[], input = ""): { status: number | null; out: string } {
  const env: NodeJS.ProcessEnv = { ...process.env, CONTEXTENGINE_HOME: home, CONTEXTENGINE_WORKSPACES: cwd };
  if (haveOpenssl) env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS = JSON.stringify([tsa.entry()]);
  // No command of this file may reach the SealHour service: a stand-in address on this machine where
  // nothing listens. [LOCK] [SEALHOUR-GETS-THE-CHECKPOINT-AND-THE-CREDENTIAL-ONLY] (src/anchor-service.ts)
  env.CONTEXTENGINE_SEALHOUR_TEST = JSON.stringify({ url: "http://127.0.0.1:1", keys: [], anchors: [] });
  const p = spawnSync(process.execPath, [CLI, "anchor", ...args], { input, encoding: "utf8", env, cwd, timeout: 30_000 });
  return { status: p.status, out: `${p.stdout}${p.stderr}` };
}
const auditText = () => (existsSync(join(home, "audit.log")) ? readFileSync(join(home, "audit.log"), "utf8") : "");
const configured = () => existsSync(join(home, "anchors", "config.json"));

describe.skipIf(!existsSync(CLI))("the interim enable screen (anchor enable --interim)", () => {
  it("says what leaves, names the services, and asks code (default yes) then start (default no)", () => {
    const r = run(["enable", "--interim"], "\n\n");
    expect(r.out).toMatch(/Interim mode, in place of the SealHour service/);
    expect(r.out).toMatch(/The SealHour service itself: contextengine anchor enable \(it asks again\)/);
    expect(r.out).toMatch(/What leaves this machine, once an hour:/);
    expect(r.out).toMatch(/one 32-byte fingerprint of that checkpoint, to each of the time stamp services above/);
    expect(r.out).toMatch(/no code, no name, no licence key/);
    expect(r.out).toMatch(/Stamp the code of your workspaces too\? {2}\[Y\/n\]/);
    expect(r.out).toMatch(/Start stamping\? +\[y\/N\]/);
    expect(r.out).toMatch(/Not started: nothing was stored, nothing will leave this machine\./);
    expect(r.status).toBe(0);
    expect(configured()).toBe(false);
    expect(auditText()).not.toMatch(/anchor\.enable/);
  });

  it("nothing is stored before the second answer: input that ends after the first stores nothing", () => {
    const r = run(["enable", "--interim"], "y\n");
    expect(r.out).toMatch(/Not started/);
    expect(configured()).toBe(false);
    expect(existsSync(join(home, "anchors"))).toBe(false);
  });

  it("--yes answers with the defaults, so it never starts", () => {
    const r = run(["enable", "--interim", "--yes"]);
    expect(r.out).toMatch(/Not started/);
    expect(configured()).toBe(false);
    const s = run(["enable", "--yes"]);
    expect(s.out).toMatch(/Start sealing\? +\[y\/N\]/);
    expect(s.out).toMatch(/Not started/);
    expect(configured()).toBe(false);
  });

  it("an explicit yes starts: the owner's answers and the services are recorded, on disk and on the chain, and nothing is sent yet", () => {
    const r = run(["enable", "--interim"], "n\nyes\n");
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/SealHour interim: on, chain only, every hour at about minute \d\d when the chain grew\. First stamp within the hour\./);
    const cfg = JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"));
    expect(cfg).toMatchObject({ enabled: true, code: false, backend: "rfc3161", consent: { screen: 2, backend: "rfc3161" } });
    expect(cfg.consent.credential).toBeUndefined();
    expect(cfg.consent.providers).toEqual(haveOpenssl ? ["test-a"] : ["freetsa", "digicert"]);
    const rec = auditText().trimEnd().split("\n").map((l) => JSON.parse(l)).find((x) => x.event === "anchor.enable");
    expect(rec.payload).toMatchObject({ code: false, backend: "rfc3161", screen: 2 });
    if (haveOpenssl) expect(tsa.requests.length).toBe(0);
  });

  it("asked again while on, a no changes nothing and says so", () => {
    run(["enable", "--interim", "--code", "no", "--start", "yes"]);
    const r = run(["enable", "--interim"], "\n\n");
    expect(r.out).toMatch(/Nothing changed: SealHour stays on as you set it before \(interim mode\)\. To stop it: contextengine anchor disable\./);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8")).enabled).toBe(true);
  });

  it("flags answer for a script, and the screen is still printed", () => {
    const r = run(["enable", "--interim", "--code", "yes", "--start", "yes"]);
    expect(r.out).toMatch(/What leaves this machine/);
    expect(r.out).toMatch(/SealHour interim: on, chain \+ code \(no git repository in the workspaces yet\)/);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8")).code).toBe(true);
  });
});

describe.skipIf(!existsSync(CLI))("the SealHour service's enable screen (anchor enable)", () => {
  const token = () => (existsSync(join(home, "anchors", "pilot-token")) ? readFileSync(join(home, "anchors", "pilot-token"), "utf8").trim() : null);

  it("says the checkpoint itself leaves, with what credential, to whom, and asks code (default yes) then start (default no)", () => {
    const r = run(["enable"], "\n\n");
    expect(r.out).toMatch(/sends it to SealHour TEST stand-in \(127\.0\.0\.1:1, not the SealHour service\)\./);
    expect(r.out).toMatch(/What leaves this machine, once an hour, while OpsContext runs:/);
    expect(r.out).toMatch(/a checkpoint of your OpsContext audit chain: a few 32-byte fingerprints, the number of\n +records and the time; never a record;/);
    expect(r.out).toMatch(/one fingerprint for all your workspace repositories, and their\n +number; never a file, never code, never a name;/);
    // This test home has no licence: the screen says a pilot code is sent, and never "your licence key".
    expect(r.out).toMatch(/a pilot code made on this machine when you say yes \(random: it names no one\)/);
    expect(r.out).toMatch(/No OpsContext licence is used: no OpsContext licence on this machine\./);
    expect(r.out).not.toMatch(/your licence key/);
    expect(r.out).toMatch(/SealHour learns the hours you were active, to the hour\. Nothing else leaves: no record, no file,\nno code, no name\./);
    expect(r.out).toMatch(/A date, not ownership\./);
    expect(r.out).toMatch(/Seal the code of your workspaces too\? {2}\[Y\/n\]/);
    expect(r.out).toMatch(/Start sealing\? +\[y\/N\]/);
    expect(r.out).toMatch(/Not started: nothing was stored, nothing will leave this machine\./);
    expect(configured()).toBe(false);
    expect(token()).toBeNull(); // the pilot code is not made before the yes
    expect(auditText()).not.toMatch(/anchor\.enable/);
  });

  it("with a licence the screen says the licence key leaves, and names the real service", () => {
    const real = { url: SEALHOUR_URL, keys: [], anchors: [], test: false };
    const s = sealScreen({ credential: "licence", fromInterim: false, service: real });
    expect(s).toMatch(/sends it to SealHour \(api\.sealhour\.com\)\./);
    expect(s).toMatch(/ {2}- your licence key, and, as with any web request, this machine's address and the time\./);
    expect(s).not.toMatch(/pilot code/);
    expect(s).toMatch(/included in OpsContext Team and Enterprise, and open to every licence while its pilot lasts/);
    // No provider of the official stamp and no price is named, on either screen.
    for (const text of [s, sealScreen({ credential: "pilot", fromInterim: true, service: real })]) expect(text).not.toMatch(/€|\bEUR\b|\bCHF\b|\$|\d+ ?(euros?|francs?)|per (month|year)/i);
  });

  it("the service in use is the pinned one unless a stand-in on this machine is named; any other address is refused", () => {
    const keep = process.env.CONTEXTENGINE_SEALHOUR_TEST;
    try {
      delete process.env.CONTEXTENGINE_SEALHOUR_TEST;
      expect(activeService()).toMatchObject({ url: "https://api.sealhour.com", test: false });
      expect(activeService().keys.map((k) => k.id)).toEqual(["sealhour-2026-10"]);
      for (const url of ["https://api.sealhour.com", "http://example.com", "https://127.0.0.1:8047", "http://127.0.0.1.example.com", "http://10.0.0.5:8047"]) {
        process.env.CONTEXTENGINE_SEALHOUR_TEST = JSON.stringify({ url, keys: [], anchors: [] });
        expect(() => activeService(), url).toThrow(/test service refused/);
      }
      process.env.CONTEXTENGINE_SEALHOUR_TEST = JSON.stringify({ url: "http://127.0.0.1:8047/x?y", keys: [], anchors: [] });
      expect(activeService()).toMatchObject({ url: "http://127.0.0.1:8047", test: true, keys: [], anchors: [] }); // never the real key in test mode
    } finally {
      if (keep === undefined) delete process.env.CONTEXTENGINE_SEALHOUR_TEST;
      else process.env.CONTEXTENGINE_SEALHOUR_TEST = keep;
    }
  });

  it("nothing is stored before the second answer", () => {
    const r = run(["enable"], "y\n");
    expect(r.out).toMatch(/Not started/);
    expect(existsSync(join(home, "anchors"))).toBe(false);
  });

  it("an explicit yes starts: the backend and the kind of credential are recorded, the pilot code is made, private, and never on the chain", () => {
    const r = run(["enable"], "n\nyes\n");
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/SealHour TEST stand-in \(127\.0\.0\.1:1, not the SealHour service\): on, chain only, every hour at about minute \d\d when the chain grew\. Each checkpoint is sealed at minute 2 of the hour after it\./);
    const cfg = JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"));
    expect(cfg).toMatchObject({ enabled: true, code: false, backend: "sealhour", consent: { screen: 2, backend: "sealhour", providers: ["sealhour"], credential: "pilot" } });
    expect(token()).toMatch(/^pilot-[0-9a-f]{64}$/);
    expect(statSync(join(home, "anchors", "pilot-token")).mode & 0o777).toBe(0o600);
    const rec = auditText().trimEnd().split("\n").map((l) => JSON.parse(l)).find((x) => x.event === "anchor.enable");
    expect(rec.payload).toMatchObject({ code: false, backend: "sealhour", screen: 2, credential: "pilot" });
    expect(auditText()).not.toContain(token()!);
    expect(readFileSync(join(home, "anchors", "config.json"), "utf8")).not.toContain(token()!);
    expect(r.out).not.toContain(token()!);
    // Status: the line names the stand-in, the details say what is sent.
    const st = run(["status"]);
    expect(st.out.split("\n")[0]).toMatch(/^SealHour TEST stand-in \(127\.0\.0\.1:1, not the SealHour service\): on \(chain only\), no seal yet/);
    expect(st.out).toMatch(/each checkpoint is sent with this machine's pilot code, sealed at minute 2 of the next hour/);
    expect(st.out).not.toContain(token()!);
    // A second yes keeps the same pilot code.
    const first = token();
    run(["enable", "--code", "no", "--start", "yes"]);
    expect(token()).toBe(first);
  });

  it("a machine in interim mode is asked again: anything but a yes leaves it as it was, a yes moves it", () => {
    run(["enable", "--interim", "--code", "no", "--start", "yes"]);
    const asked = run(["enable"], "\n\n");
    expect(asked.out).toMatch(/This machine is in interim mode today \(free public time stamp services, asked directly\)\./);
    expect(asked.out).toMatch(/Nothing changed: SealHour stays on as you set it before \(interim mode\)\./);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"))).toMatchObject({ backend: "rfc3161", consent: { backend: "rfc3161" } });
    expect(token()).toBeNull();
    expect(run(["status"]).out).toMatch(/The SealHour service is open: contextengine anchor enable moves this machine to it \(it asks first\)/);
    run(["enable"], "\nyes\n");
    const cfg = JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"));
    expect(cfg).toMatchObject({ backend: "sealhour", consent: { backend: "sealhour", credential: "pilot" } });
    // And back, on the owner's word.
    run(["enable", "--interim", "--code", "no", "--start", "yes"]);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"))).toMatchObject({ backend: "rfc3161", consent: { backend: "rfc3161" } });
  });

  it("export-evidence --refresh asks nothing of the service while it is off or in interim mode", () => {
    run(["enable", "--interim", "--code", "no", "--start", "yes"]);
    const r = run(["export-evidence", "2026-01-01", "2026-12-31", "--refresh", "--out", join(home, "out")]);
    expect(r.out).toMatch(/Not refreshed: the SealHour service is off on this machine, so nothing is asked of it/);
  });
});

describe.skipIf(!existsSync(CLI))("status, code, disable, and the policy", () => {
  it("off: one line, exit 0", () => {
    const r = run(["status"]);
    expect(r.out.split("\n")[0]).toBe("SealHour: off (contextengine anchor enable)");
    expect(r.status).toBe(0);
  });

  it("a repository whose policy requires stamps: off is an error", () => {
    mkdirSync(join(cwd, ".git"));
    mkdirSync(join(cwd, ".contextengine"));
    writeFileSync(join(cwd, ".contextengine", "policy.json"), JSON.stringify({ version: 1, anchoring: { required: true } }));
    const r = run(["status"]);
    expect(r.out).toMatch(/ERROR: .*policy\.json requires the audit chain to be stamped: SealHour is off on this machine/);
    expect(r.status).toBe(1);
    const v = run(["verify"]);
    expect(v.out).toMatch(/ERROR: .*requires the audit chain to be stamped: no checkpoint on this machine/);
    expect(v.status).toBe(1);
  });

  it("code off, then disable: recorded on the chain, and the job stays off", () => {
    run(["enable", "--code", "yes", "--start", "yes"]);
    expect(run(["code", "off"]).out).toMatch(/Code: off/);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8")).code).toBe(false);
    expect(run(["disable"]).out).toMatch(/SealHour: off\. Nothing leaves this machine from now on/);
    expect(run(["tick", "--now"]).out).toMatch(/SealHour: off: SealHour is off on this machine/);
    const events = auditText().trimEnd().split("\n").map((l) => JSON.parse(l).event);
    expect(events).toEqual(["anchor.enable", "anchor.code", "anchor.disable"]);
    if (haveOpenssl) expect(tsa.requests.length).toBe(0);
  });

  it("audit-verify ends on the SealHour line, off or on, in the same words as status", () => {
    const verify = () => spawnSync(process.execPath, [CLI, "audit-verify"], { encoding: "utf8", cwd, env: { ...process.env, CONTEXTENGINE_HOME: home, CONTEXTENGINE_SEALHOUR_TEST: JSON.stringify({ url: "http://127.0.0.1:1", keys: [], anchors: [] }) } });
    run(["enable", "--code", "no", "--start", "no"]);
    const off = verify();
    expect(off.stdout).toMatch(/\nSealHour: off \(contextengine anchor enable\)\n?$/);
    run(["enable", "--code", "no", "--start", "yes"]);
    const on = verify();
    const first = run(["status"]).out.split("\n")[0];
    expect(first).toMatch(/^SealHour TEST stand-in .*: on \(chain only\), no seal yet/);
    expect(on.stdout).toContain(`\n${first}\n`);
    expect(on.stdout).toMatch(/The check above reads this machine only; that line is its outside date\./);
    expect(on.status).toBe(0);
  });

  it("an unknown sub-command is named with the usage, exit 1", () => {
    const r = run(["seal-everything"]);
    expect(r.out).toMatch(/Usage: contextengine anchor <command>/);
    expect(r.status).toBe(1);
  });
});
