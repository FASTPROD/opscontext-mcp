// [LOCK] [SERVERS-ARE-INVENTORIED]: the registry must name every live server, its build against
// the file on disk, and drop dead records. Throwaway HOME via src/test-setup.ts.
import { describe, it, expect, beforeAll } from "vitest";
import { mkdirSync, writeFileSync, readdirSync, existsSync, readFileSync, statSync, unlinkSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

let R: typeof import("./server-registry.js");
const home = () => process.env.CONTEXTENGINE_HOME as string;
const dir = () => join(home(), "servers");

beforeAll(async () => { R = await import("./server-registry.js"); });

describe("registerServer", () => {
  it("writes a record for this process with a build hash of the script it loaded, and removes it on stop", () => {
    const script = join(home(), "fake-server.js");
    mkdirSync(home(), { recursive: true });
    writeFileSync(script, "console.log('v1')");
    const { record, stop } = R.registerServer({ version: "9.9.9", script });
    expect(record.pid).toBe(process.pid);
    expect(record.build).toBe(R.buildHashOf(script));
    expect(existsSync(join(dir(), `${process.pid}.json`))).toBe(true);
    const rep = R.listServers();
    expect(rep.servers.map((s) => s.pid)).toContain(process.pid);
    expect(rep.servers.find((s) => s.pid === process.pid)?.staleBuild).toBe(false);
    stop();
    expect(existsSync(join(dir(), `${process.pid}.json`))).toBe(false);
  });
  it("flags a server whose script changed on disk after it started, the 2026-09-05 shape", () => {
    const script = join(home(), "fake-server2.js");
    writeFileSync(script, "console.log('old build')");
    const { stop } = R.registerServer({ version: "9.9.9", script });
    writeFileSync(script, "console.log('new build')"); // a rebuild while the server keeps the old code
    const me = R.listServers().servers.find((s) => s.pid === process.pid);
    expect(me?.staleBuild).toBe(true);
    expect(R.listServers().warnings.some((w) => /older than the file on disk/.test(w))).toBe(true);
    stop();
  });
});

describe("listServers", () => {
  it("removes records of dead processes and warns above the server-count ceiling", () => {
    mkdirSync(dir(), { recursive: true });
    // A process that has certainly exited: spawn `true` and use its pid.
    const dead = spawnSync("true").pid as number;
    const script = join(home(), "fake-server3.js");
    writeFileSync(script, "x");
    // `started` is now: a live process's record must not claim a start before the process began, or
    // it reads as a reused pid and is removed. [LOCK] [A-RECORD-BELONGS-TO-ITS-OWN-PROCESS]
    const now = new Date().toISOString();
    const rec = (pid: number) => ({ pid, ppid: 1, parent: "test", started: now, heartbeat: now, version: "1", script, build: R.buildHashOf(script), cwd: "/", node: "v20" });
    writeFileSync(join(dir(), `${dead}.json`), JSON.stringify(rec(dead)));
    // Alive impostors: this process under several fake pids is not possible, so use live pids that exist: our own and our parent.
    writeFileSync(join(dir(), `${process.pid}.json`), JSON.stringify(rec(process.pid)));
    writeFileSync(join(dir(), `${process.ppid}.json`), JSON.stringify(rec(process.ppid)));
    writeFileSync(join(dir(), `1.json`), JSON.stringify(rec(1)));
    writeFileSync(join(dir(), `broken.json`), "{not json");
    const rep = R.listServers();
    expect(rep.removed).toBeGreaterThanOrEqual(2); // the dead pid and the broken file
    expect(rep.servers.some((s) => s.pid === dead)).toBe(false);
    expect(readdirSync(dir())).not.toContain(`${dead}.json`);
    expect(rep.servers.length).toBeGreaterThanOrEqual(3);
    if (rep.servers.length > R.SERVER_COUNT_WARN) expect(rep.warnings.some((w) => /index on their own/.test(w))).toBe(true);
    const text = R.formatServers(rep, "/");
    expect(text).toMatch(/server\(s\) running/);
  });
});

describe("roles (one indexer, many readers)", () => {
  it("records corpus and role, updates the role in place, prints both, and warns only about servers that index", () => {
    const script = join(home(), "fake-server3.js");
    writeFileSync(script, "console.log('v3')");
    const { record, stop, setRole } = R.registerServer({ version: "9.9.9", script, corpus: "abc123abc123", role: "reader" });
    expect(record.corpus).toBe("abc123abc123");
    expect(JSON.parse(readFileSync(join(dir(), `${process.pid}.json`), "utf8")).role).toBe("reader");
    setRole("indexer");
    expect(JSON.parse(readFileSync(join(dir(), `${process.pid}.json`), "utf8")).role).toBe("indexer");
    const rep = R.listServers();
    expect(R.formatServers(rep)).toMatch(/indexer corpus abc123abc123/);
    // Four readers and one indexer: no "too many indexers" warning; five self-indexing servers: warning.
    for (let i = 1; i <= 4; i++) writeFileSync(join(dir(), `${process.pid}-r${i}.json`), JSON.stringify({ ...record, pid: process.pid, role: "reader", started: record.started }));
    expect(R.listServers().warnings.some((w) => /index on their own/.test(w))).toBe(false);
    for (let i = 1; i <= 4; i++) writeFileSync(join(dir(), `${process.pid}-r${i}.json`), JSON.stringify({ ...record, pid: process.pid, role: undefined }));
    // Earlier tests leave live-pid records behind (our parent, pid 1), so count only the shape.
    const w = R.listServers().warnings.find((x) => /(\d+) of \1 servers index on their own/.test(x));
    expect(w).toBeDefined();
    expect(Number(w!.match(/^(\d+) of/)![1])).toBeGreaterThanOrEqual(5);
    stop();
  });
});

// [LOCK] [A-HALF-READ-RECORD-IS-NOT-DEAD]: E2E_REVIEW_2026-09 C0. A listing that read a record while
// its owner rewrote it deleted it, and the owner then indexed on its own for 15 s (11 times in the
// live log, 28 to 30 September). The first three tests fail on the code before.
const psWorks = spawnSync("ps", ["-o", "pid=", "-p", String(process.pid)]).status === 0;

describe("a record caught mid-rewrite", () => {
  it("is left in place and not listed while its process is alive, empty or half written", () => {
    mkdirSync(dir(), { recursive: true });
    // The roles test above leaves extra records carrying this pid under other names.
    for (const f of readdirSync(dir())) if (f.startsWith(`${process.pid}-`)) unlinkSync(join(dir(), f));
    const file = join(dir(), `${process.pid}.json`);
    for (const torn of ["", `{"pid": ${process.pid}, "started": "20`]) {
      writeFileSync(file, torn);
      const rep = R.listServers();
      expect(existsSync(file)).toBe(true);
      expect(rep.servers.some((s) => s.pid === process.pid)).toBe(false);
      expect(rep.warnings.some((w) => w.startsWith(`${process.pid}.json: the record could not be read`))).toBe(true);
    }
    unlinkSync(file);
  });
  it("is replaced whole: the new record is renamed into place, never truncated and refilled", () => {
    const script = join(home(), "fake-server-whole.js");
    writeFileSync(script, "console.log('whole')");
    const { stop, setRole } = R.registerServer({ version: "9.9.9", script, corpus: "whole12whole", role: "reader" });
    const file = join(dir(), `${process.pid}.json`);
    const before = statSync(file).ino;
    setRole("indexer");
    expect(statSync(file).ino).not.toBe(before);
    expect(JSON.parse(readFileSync(file, "utf8")).role).toBe("indexer");
    expect(readdirSync(dir()).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    stop();
  });
  it("of a dead process is still removed, and so is a dead writer's temp file; a live writer's temp file stays", () => {
    mkdirSync(dir(), { recursive: true });
    const dead = spawnSync("true").pid as number;
    writeFileSync(join(dir(), `${dead}.json`), "");
    writeFileSync(join(dir(), `.${dead}.json.tmp`), "{");
    writeFileSync(join(dir(), `.${process.ppid}.json.tmp`), "{");
    const rep = R.listServers();
    expect(readdirSync(dir())).not.toContain(`${dead}.json`);
    expect(readdirSync(dir())).not.toContain(`.${dead}.json.tmp`);
    expect(readdirSync(dir())).toContain(`.${process.ppid}.json.tmp`);
    expect(rep.removed).toBeGreaterThanOrEqual(1);
    unlinkSync(join(dir(), `.${process.ppid}.json.tmp`));
  });
  it.skipIf(!psWorks)("of a pid reused since the file was written is removed (the pid's process started later)", () => {
    mkdirSync(dir(), { recursive: true });
    const file = join(dir(), `${process.pid}.json`);
    writeFileSync(file, "");
    const past = new Date("2020-01-01T00:00:00Z");
    utimesSync(file, past, past);
    R.listServers();
    expect(existsSync(file)).toBe(false);
  });
});

describe("a corpus nobody indexes", () => {
  it("is named when all its servers run an old build and none indexes; not once one does", () => {
    mkdirSync(dir(), { recursive: true });
    const script = join(home(), "fake-server-noidx.js");
    writeFileSync(script, "console.log('disk build')");
    const now = new Date().toISOString();
    const rec = (pid: number, role: "reader" | "indexer") => ({ pid, ppid: 1, parent: "test", started: now, heartbeat: now, version: "1", script, build: "an-old-build", cwd: "/", node: "v20", corpus: "noidx1noidx1", role });
    writeFileSync(join(dir(), `${process.pid}.json`), JSON.stringify(rec(process.pid, "reader")));
    writeFileSync(join(dir(), `${process.ppid}.json`), JSON.stringify(rec(process.ppid, "reader")));
    expect(R.listServers().warnings.some((w) => /^corpus noidx1noidx1 has no indexer: its 2 server\(s\) run an old build/.test(w))).toBe(true);
    writeFileSync(join(dir(), `${process.ppid}.json`), JSON.stringify(rec(process.ppid, "indexer")));
    expect(R.listServers().warnings.some((w) => /^corpus noidx1noidx1 has no indexer/.test(w))).toBe(false);
    unlinkSync(join(dir(), `${process.pid}.json`));
    unlinkSync(join(dir(), `${process.ppid}.json`));
  });
});
