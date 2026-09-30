// The hourly job. [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] [LOCK] [ONE-EMITTER-PER-MACHINE]
// [LOCK] [NO-CHECKPOINT-WITHOUT-A-NEW-RECORD] [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED] (src/anchor.ts)
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";
import { appendAudit } from "../src/audit.js";
import { anchorTick, anchorHealth, anchorTickDue, newConfig, writeConfig, readConfig, readState, listCheckpoints, anchorsDir, slotOf, type AnchorConfig } from "../src/anchor.js";
import { codeLeaves } from "../src/anchor-code.js";
import { digestOf, codeRoot, ZERO } from "../src/anchor-protocol.js";
import { findOpenssl } from "../src/anchor-tsa.js";
import { computeFleetHealth, formatFleetHealth } from "../src/fleet-health.js";
import { startFakeTsa, type FakeTsa } from "./helpers/fake-tsa.js";

const ssl = findOpenssl();
const haveOpenssl = !!ssl && !ssl.libressl;

let tsaA: FakeTsa;
let tsaB: FakeTsa;
let keys: string;
let home: string;
let work: string;
const saved: Record<string, string | undefined> = {};

beforeAll(async () => {
  if (!haveOpenssl) return;
  keys = mkdtempSync(join(tmpdir(), "ce-anchor-keys-"));
  tsaA = await startFakeTsa(keys, "test-a");
  tsaB = await startFakeTsa(keys, "test-b");
});
afterAll(async () => {
  if (!haveOpenssl) return;
  await tsaA.close().catch(() => undefined);
  await tsaB.close().catch(() => undefined);
  rmSync(keys, { recursive: true, force: true });
});
beforeEach(() => {
  for (const k of ["CONTEXTENGINE_HOME", "CONTEXTENGINE_ANCHOR_TEST_PROVIDERS", "CONTEXTENGINE_WORKSPACES"]) saved[k] = process.env[k];
  home = mkdtempSync(join(tmpdir(), "ce-anchor-home-"));
  work = mkdtempSync(join(tmpdir(), "ce-anchor-ws-"));
  process.env.CONTEXTENGINE_HOME = home;
  process.env.CONTEXTENGINE_WORKSPACES = work;
  if (haveOpenssl) {
    process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS = JSON.stringify([tsaA.entry(), tsaB.entry()]);
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    tsaA.requests.length = 0;
    tsaB.requests.length = 0;
    tsaA.failNext = 0;
    tsaB.failNext = 0;
  }
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(home, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
});

/** A fixed clock: the hour, then minutes into it. */
const at = (hour: string, minute = 30, second = 0) => new Date(`${hour}:${String(minute).padStart(2, "0")}:${String(second).padStart(2, "0")}Z`);
const H1 = "2026-10-03T14";
const H2 = "2026-10-03T15";
const H3 = "2026-10-03T16";

function enable(o: Partial<AnchorConfig> = {}): AnchorConfig {
  const cfg = { ...newConfig({ code: false, providers: ["test-a", "test-b"], now: at(H1, 0), rand: () => 10 * 60 }), ...o };
  writeConfig(cfg);
  return cfg;
}
const tick = (now: Date, extra: { force?: boolean } = {}) => anchorTick({ now: () => now, timeoutMs: 2000, clientVersion: "test", ...extra });
const logText = () => readFileSync(join(home, "audit.log"), "utf8");
const requests = () => tsaA.requests.length + tsaB.requests.length;

describe("off by default: nothing is read, written or sent without the enable screen's yes", () => {
  it("a fresh installation: the job does nothing, creates nothing, sends nothing", async () => {
    appendAudit("learning.save", { n: 1 });
    const r = await tick(at(H1, 30));
    expect(r.action).toBe("off");
    expect(existsSync(anchorsDir())).toBe(false);
    if (haveOpenssl) expect(requests()).toBe(0);
    expect(anchorTickDue()).toBe(false);
    expect(anchorHealth().line).toBe("SealHour: off (contextengine anchor enable)");
  });

  it("a configuration without the recorded yes is off too", async () => {
    appendAudit("learning.save", { n: 1 });
    enable({ consent: null });
    expect((await tick(at(H1, 30))).action).toBe("off");
    enable({ enabled: false });
    expect((await tick(at(H1, 30))).action).toBe("off");
    if (haveOpenssl) expect(requests()).toBe(0);
  });
});

describe("the slot, drawn once per machine", () => {
  it("is between minute 5 and minute 55, and differs between machines", () => {
    const slots = new Set<number>();
    for (let i = 0; i < 40; i++) {
      const s = newConfig({ code: true, providers: [], now: new Date() }).slot_seconds;
      expect(s).toBeGreaterThanOrEqual(300);
      expect(s).toBeLessThan(3300);
      slots.add(s);
    }
    expect(slots.size).toBeGreaterThan(20);
    expect(slotOf(at(H1, 42), 600).toISOString()).toBe("2026-10-03T14:10:00.000Z");
  });
});

describe.skipIf(!haveOpenssl)("the hourly job", () => {
  it("waits for the slot, then makes one checkpoint in the hour, stamped by both services", async () => {
    appendAudit("learning.save", { n: 1 });
    appendAudit("learning.save", { n: 2 });
    enable();
    expect((await tick(at(H1, 5))).action).toBe("not-due"); // slot is :10
    expect(requests()).toBe(0);
    const r = await tick(at(H1, 12));
    expect(r.action).toBe("checkpoint");
    expect(r.stamped).toEqual(["Test TSA test-a", "Test TSA test-b"]);
    const [c] = listCheckpoints();
    expect(c.checkpoint.records).toMatchObject({ from_hash: ZERO, count: 2 });
    expect(c.checkpoint.prev_checkpoint_digest).toBe(ZERO);
    expect(c.checkpoint.created_at).toBe("2026-10-03T14:12:00Z");
    expect(c.checkpoint.client).toEqual({ name: "opscontext", version: "test" });
    expect(c.checkpoint.code).toBeUndefined();
    expect(existsSync(join(c.dir, "checkpoint.test-a.tsr"))).toBe(true);
    expect(existsSync(join(c.dir, "checkpoint.test-b.tsr"))).toBe(true);
    // Each service received one request, holding this checkpoint's digest.
    expect(tsaA.requests.length).toBe(1);
    expect(tsaA.requests[0].body.toString("hex")).toContain("0420" + digestOf(c.checkpoint));
    // One per clock hour, even with new records.
    appendAudit("learning.save", { n: 3 });
    expect((await tick(at(H1, 40))).action).toBe("not-due");
    const h = anchorHealth(at(H1, 41));
    expect(h.problem).toBeNull();
    expect(h.line).toMatch(/^SealHour interim: on \(chain only\), last stamp 29 min ago by 2 of 2 free services, next after 15:10Z; no copy off this machine/);
  });

  it("nothing without activity: no new record, no checkpoint, no request, and the job writes no record itself", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    expect((await tick(at(H1, 12))).action).toBe("checkpoint");
    const before = logText();
    const sent = requests();
    const r = await tick(at(H2, 12));
    expect(r.action).toBe("quiet");
    expect(requests()).toBe(sent);
    expect(listCheckpoints().length).toBe(1);
    expect(logText()).toBe(before);
    expect(anchorHealth(at(H2, 13)).line).toMatch(/nothing new since/);
  });

  it("the next checkpoint chains to the previous one and starts after its last record", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    await tick(at(H1, 12));
    appendAudit("learning.save", { n: 2 });
    appendAudit("learning.save", { n: 3 });
    expect((await tick(at(H2, 12))).action).toBe("checkpoint");
    const [c1, c2] = listCheckpoints();
    expect(c2.checkpoint.prev_checkpoint_digest).toBe(digestOf(c1.checkpoint));
    expect(c2.checkpoint.records.from_hash).toBe(c1.checkpoint.records.head_hash);
    expect(c2.checkpoint.records.count).toBe(2);
  });

  it("one service down: stamped by the other, and the status names the one that did not answer", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    tsaB.mode = "http503";
    const r = await tick(at(H1, 12));
    expect(r.stamped).toEqual(["Test TSA test-a"]);
    const [c] = listCheckpoints();
    expect(c.stamps["test-b"]).toMatchObject({ ok: false, error: "the service answered HTTP 503" });
    expect(existsSync(join(c.dir, "checkpoint.test-b.tsr"))).toBe(false);
    const h = anchorHealth(at(H1, 13));
    expect(h.problem).toBeNull();
    expect(h.line).toMatch(/by 1 of 2 free services \(Test TSA test-b did not answer\)/);
  });

  it("both services down: the checkpoint is queued, said, retried on its backoff, and stamped late when they come back", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    tsaA.mode = "http503";
    tsaB.mode = "cut";
    const r = await tick(at(H1, 12));
    expect(r.action).toBe("checkpoint");
    expect(r.stamped).toEqual([]);
    expect(r.detail).toMatch(/not stamped yet.*\(queued\)/);
    let h = anchorHealth(at(H1, 13));
    expect(h.queued).toBe(1);
    // Fleet health carries it as a measured problem, in the same words.
    const fleet = computeFleetHealth({ now: at(H1, 13), version: "test", report: { servers: [], warnings: [] } as unknown as Parameters<typeof computeFleetHealth>[0]["report"] });
    expect(fleet.warnings.some((w) => /^SealHour: not stamped yet: .*\(1 checkpoint queued\)$/.test(w))).toBe(true);
    expect(formatFleetHealth(fleet)).toContain(h.line);
    expect(h.line).toMatch(/^SealHour interim: on, not stamped yet: .*HTTP 503.* \(1 checkpoint queued\)/);
    expect(h.line).not.toMatch(/last stamp/);
    // Before its retry time (one minute), a tick leaves it alone.
    const sent = requests();
    await tick(at(H1, 12, 30));
    expect(requests()).toBe(sent);
    // The services are back; the retry stamps it, marked as not the first try.
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    const r2 = await tick(at(H1, 14));
    expect(r2.retried).toBe(1);
    const [c] = listCheckpoints();
    expect(c.stamps["test-a"]).toMatchObject({ ok: true, first_try: false });
    h = anchorHealth(at(H1, 15));
    expect(h.queued).toBe(0);
    expect(h.problem).toBeNull();
    // The queue keeps the order: the next checkpoint chains to the one that waited.
    appendAudit("learning.save", { n: 2 });
    await tick(at(H2, 12));
    const [c1, c2] = listCheckpoints();
    expect(c2.checkpoint.prev_checkpoint_digest).toBe(digestOf(c1.checkpoint));
  });

  it("a queued checkpoint is dated through the chain once a later one is stamped, and no longer retried", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    tsaA.mode = "http503";
    tsaB.mode = "http503";
    await tick(at(H1, 12));
    tsaA.mode = "ok";
    tsaB.mode = "ok";
    tsaA.failNext = 1; // the retry of checkpoint 1 fails once more, the new checkpoint's first try does not
    tsaB.failNext = 1;
    appendAudit("learning.save", { n: 2 });
    const r = await tick(at(H2, 12));
    expect(r.stamped).toEqual(["Test TSA test-a", "Test TSA test-b"]);
    const [c1, c2] = listCheckpoints();
    expect(c1.stamps["test-a"].ok).toBe(false);
    expect(c1.meta.covered_by).toMatchObject({ seq: 2, name: c2.name });
    expect(c1.meta.next_try_at).toBeNull();
    const h = anchorHealth(at(H2, 13));
    expect(h.queued).toBe(0);
    expect(h.problem).toBeNull();
    expect(h.line).toMatch(/^SealHour interim: on \(chain only\), last stamp 1 min ago by 2 of 2 free services/);
    // Its own stamp would now be later than the one that dates it: never asked for again.
    const sent = requests();
    await tick(at(H2, 50), { force: false });
    expect(requests()).toBe(sent);
  });

  it("one emitter: two jobs at once make one checkpoint", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    const [a, b] = await Promise.all([tick(at(H1, 12)), tick(at(H1, 12))]);
    expect([a.action, b.action].sort()).toEqual(["busy", "checkpoint"]);
    expect(listCheckpoints().length).toBe(1);
    expect(existsSync(join(anchorsDir(), "anchor.lock"))).toBe(false);
  });

  it("a live job's lock is respected; a dead one's is broken at once", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    writeFileSync(join(anchorsDir(), "anchor.lock"), `${process.ppid}\n`);
    expect((await tick(at(H1, 12))).action).toBe("busy");
    writeFileSync(join(anchorsDir(), "anchor.lock"), "999999\n");
    expect((await tick(at(H1, 12))).action).toBe("checkpoint");
  });

  it("a checkpoint written just before a crash that lost the state is still the chain's head", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    await tick(at(H1, 12));
    unlinkSync(join(anchorsDir(), "state.json"));
    appendAudit("learning.save", { n: 2 });
    await tick(at(H2, 12));
    const [c1, c2] = listCheckpoints();
    expect(c2.checkpoint.prev_checkpoint_digest).toBe(digestOf(c1.checkpoint));
    expect(c2.checkpoint.records.from_hash).toBe(c1.checkpoint.records.head_hash);
    expect(c2.seq).toBe(2);
  });

  it("the previous checkpoint's last record gone from the log is said, and nothing is chained on a guess", async () => {
    appendAudit("learning.save", { n: 1 });
    enable();
    await tick(at(H1, 12));
    writeFileSync(join(home, "audit.log"), ""); // history replaced
    appendAudit("learning.save", { n: "after the cut" });
    const r = await tick(at(H2, 12));
    expect(r.action).toBe("lost");
    expect(listCheckpoints().length).toBe(1);
    expect(anchorHealth(at(H2, 13)).line).toMatch(/gone from the audit log/);
  });

  it("a copy off the machine: checkpoints and stamps, never the code leaves or meta", async () => {
    const copy = mkdtempSync(join(tmpdir(), "ce-anchor-copy-"));
    try {
      appendAudit("learning.save", { n: 1 });
      const cfg = enable({ copy_dir: copy, code: true });
      mkdirSync(join(work, "repo-one"));
      execFileSync("git", ["init", "-q", join(work, "repo-one")]);
      writeFileSync(join(work, "repo-one", "a.txt"), "a\n");
      execFileSync("git", ["-C", join(work, "repo-one"), "-c", "user.email=t@t", "-c", "user.name=t", "add", "."]);
      execFileSync("git", ["-C", join(work, "repo-one"), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "one"]);
      await tick(at(H1, 12));
      const [c] = listCheckpoints();
      const dest = join(copy, `opscontext-anchors-${cfg.machine}`, "checkpoints", c.name);
      expect(readdirSync(dest).sort()).toEqual(["checkpoint.json", "checkpoint.test-a.tsq", "checkpoint.test-a.tsr", "checkpoint.test-b.tsq", "checkpoint.test-b.tsr", "stamps.json"]);
      expect(existsSync(join(c.dir, "code-leaves.json"))).toBe(true);
      expect(anchorHealth(at(H1, 13)).line).toMatch(/copied off this machine 1 min ago$/);
      // The folder gone (an unmounted drive): said, never silent.
      rmSync(copy, { recursive: true, force: true });
      appendAudit("learning.save", { n: 2 });
      await tick(at(H2, 12));
      expect(anchorHealth(at(H2, 13)).line).toMatch(/copy off this machine FAILED \(the folder .* is not there/);
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  });
});

// ---------- the code ----------

function gitIn(repo: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", ...args], { encoding: "utf8" });
}

/** The manifest computed with plain git commands, one blob at a time: the independent reading. */
function plainManifest(repo: string): Buffer {
  const lines = execFileSync("git", ["-C", repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD"]).toString("latin1").split("\0").filter(Boolean);
  const out: Buffer[] = [];
  for (const l of lines) {
    const [meta, path] = l.split("\t");
    const [mode, type, oid] = meta.split(" ");
    const h = type === "blob" ? createHash("sha256").update(execFileSync("git", ["-C", repo, "cat-file", "blob", oid])).digest("hex") : `commit:${oid}`;
    out.push(Buffer.concat([Buffer.from(`${mode} ${h} `), Buffer.from(path, "latin1"), Buffer.from("\n")]));
  }
  return Buffer.concat(out);
}

describe("the code leaves (contract section 2.3)", () => {
  it("one leaf per repository, the manifest as plain git gives it, sorted by name, cached per commit", async () => {
    const names = ["zeta", "café-app", "alpha"];
    for (const n of names) {
      const r = join(work, n);
      mkdirSync(join(r, "src", "deep"), { recursive: true });
      execFileSync("git", ["init", "-q", r]);
      writeFileSync(join(r, "README.md"), `# ${n}\n`);
      writeFileSync(join(r, "empty.txt"), "");
      writeFileSync(join(r, "src", "deep", "é file.bin"), Buffer.from([0, 1, 2, 255, 10, 13]));
      symlinkSync("README.md", join(r, "link"));
      gitIn(r, "add", ".");
      gitIn(r, "commit", "-qm", "first");
    }
    mkdirSync(join(work, "not-a-repo"));
    mkdirSync(join(work, "empty-repo"));
    execFileSync("git", ["init", "-q", join(work, "empty-repo")]);
    const cache = join(home, "manifests");
    const { leaves, skipped } = await codeLeaves({ cacheDir: cache });
    expect(leaves.map((l) => l.repo)).toEqual(["alpha", "café-app", "zeta"]);
    expect(skipped).toEqual([{ repo: "empty-repo", why: "no commit yet" }]);
    for (const l of leaves) {
      const repo = join(work, l.repo);
      const m = plainManifest(repo);
      expect(l.commit).toBe(gitIn(repo, "rev-parse", "HEAD").trim());
      expect(l.files).toBe(4); // README.md, empty.txt, the binary file with a non-ASCII name, the symlink
      expect(l.files_sha256).toBe(createHash("sha256").update(m).digest("hex"));
      expect(existsSync(join(cache, `${l.commit}.txt.gz`))).toBe(true);
    }
    // Cached: the same leaves again without git reading a single blob.
    expect((await codeLeaves({ cacheDir: cache })).leaves).toEqual(leaves);
    expect(codeRoot(leaves)).toMatch(/^[0-9a-f]{64}$/);
  });

  it.skipIf(!haveOpenssl)("code on: the checkpoint carries the number of repositories and their root, the leaves stay here", async () => {
    for (const n of ["one", "two"]) {
      const r = join(work, n);
      mkdirSync(r);
      execFileSync("git", ["init", "-q", r]);
      writeFileSync(join(r, "f.txt"), n);
      gitIn(r, "add", ".");
      gitIn(r, "commit", "-qm", n);
    }
    appendAudit("learning.save", { n: 1 });
    enable({ code: true });
    await tick(at(H1, 12));
    const [c] = listCheckpoints();
    const leaves = JSON.parse(readFileSync(join(c.dir, "code-leaves.json"), "utf8"));
    expect(c.checkpoint.code).toEqual({ repos: 2, code_root: codeRoot(leaves) });
    expect(JSON.stringify(c.checkpoint)).not.toMatch(/one|two/);
    expect(anchorHealth(at(H1, 13)).line).toMatch(/\(chain \+ 2 repos\)/);
    expect(readConfig()!.code).toBe(true);
    expect(readState().code).toEqual({ repos: 2, skipped: 0 });
  });
});
