// `contextengine anchor ...`, run as the owner runs it (dist/cli.js; `npm run build` first).
// [LOCK] [THE-ENABLE-SCREEN-SAYS-WHAT-LEAVES] (src/anchor-cli.ts) [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] (src/anchor.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { findOpenssl } from "../src/anchor-tsa.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";

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
  const p = spawnSync(process.execPath, [CLI, "anchor", ...args], { input, encoding: "utf8", env, cwd, timeout: 30_000 });
  return { status: p.status, out: `${p.stdout}${p.stderr}` };
}
const auditText = () => (existsSync(join(home, "audit.log")) ? readFileSync(join(home, "audit.log"), "utf8") : "");
const configured = () => existsSync(join(home, "anchors", "config.json"));

describe.skipIf(!existsSync(CLI))("the enable screen", () => {
  it("says what leaves, names the services, and asks code (default yes) then start (default no)", () => {
    const r = run(["enable"], "\n\n");
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
    const r = run(["enable"], "y\n");
    expect(r.out).toMatch(/Not started/);
    expect(configured()).toBe(false);
    expect(existsSync(join(home, "anchors"))).toBe(false);
  });

  it("--yes answers with the defaults, so it never starts", () => {
    const r = run(["enable", "--yes"]);
    expect(r.out).toMatch(/Not started/);
    expect(configured()).toBe(false);
  });

  it("an explicit yes starts: the owner's answers and the services are recorded, on disk and on the chain, and nothing is sent yet", () => {
    const r = run(["enable"], "n\nyes\n");
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/SealHour interim: on, chain only, every hour at about minute \d\d when the chain grew\. First stamp within the hour\./);
    const cfg = JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8"));
    expect(cfg).toMatchObject({ enabled: true, code: false, backend: "rfc3161", consent: { screen: 1, backend: "rfc3161" } });
    expect(cfg.consent.providers).toEqual(haveOpenssl ? ["test-a"] : ["freetsa", "digicert"]);
    const rec = auditText().trimEnd().split("\n").map((l) => JSON.parse(l)).find((x) => x.event === "anchor.enable");
    expect(rec.payload).toMatchObject({ code: false, backend: "rfc3161", screen: 1 });
    if (haveOpenssl) expect(tsa.requests.length).toBe(0);
  });

  it("asked again while on, a no changes nothing and says so", () => {
    run(["enable", "--code", "no", "--start", "yes"]);
    const r = run(["enable"], "\n\n");
    expect(r.out).toMatch(/Nothing changed: SealHour stays on as you set it before\. To stop it: contextengine anchor disable\./);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8")).enabled).toBe(true);
  });

  it("flags answer for a script, and the screen is still printed", () => {
    const r = run(["enable", "--code", "yes", "--start", "yes"]);
    expect(r.out).toMatch(/What leaves this machine/);
    expect(r.out).toMatch(/SealHour interim: on, chain \+ code \(no git repository in the workspaces yet\)/);
    expect(JSON.parse(readFileSync(join(home, "anchors", "config.json"), "utf8")).code).toBe(true);
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

  it("an unknown sub-command is named with the usage, exit 1", () => {
    const r = run(["seal-everything"]);
    expect(r.out).toMatch(/Usage: contextengine anchor <command>/);
    expect(r.status).toBe(1);
  });
});
