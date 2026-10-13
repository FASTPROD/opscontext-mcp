// [LOCK] [THE-TOOL-CALLS-A-GIT-THAT-STARTS] (src/git-path.ts): `git`, called by name from the server
// and its children, is a git that starts, whatever PATH the server was given.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, execSync } from "child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { delimiter, dirname, join } from "path";
import { fileURLToPath } from "url";
import { ensureGitStarts, gitProblem, gitStarts } from "../src/git-path.js";

let T: string;
const dir = (name: string): string => join(T, name);

/** A stand-in git: answers --version and --exec-path, as a real one does. */
function working(folder: string, version: string, ownFolder?: string): string {
  mkdirSync(dir(folder), { recursive: true });
  const file = join(dir(folder), "git");
  writeFileSync(file, `#!/bin/sh\ncase "$1" in\n  --version) echo "git version ${version}"; exit 0 ;;\n  --exec-path) echo "${ownFolder ?? dir(folder)}"; exit 0 ;;\nesac\nexit 1\n`);
  chmodSync(file, 0o755);
  return file;
}

beforeAll(() => {
  T = mkdtempSync(join(tmpdir(), "ce git path "));
  // A program this machine cannot start: the header of a 32-bit Intel program and nothing else.
  // macOS answers "Bad CPU type in executable" (error -86), the words of 2026-10-07. Started by
  // its full name it does not start on Linux either; what Linux does when it is called by name is
  // not relied on (see the Mac-only test below).
  mkdirSync(dir("badcpu"));
  writeFileSync(join(dir("badcpu"), "git"), Buffer.from([0xce, 0xfa, 0xed, 0xfe, 7, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  chmodSync(join(dir("badcpu"), "git"), 0o755);
  // Apple's git before its licence is accepted: it starts, says so, and refuses.
  mkdirSync(dir("licence"));
  writeFileSync(join(dir("licence"), "git"), '#!/bin/sh\necho "You have not agreed to the Xcode license agreements." >&2\nexit 69\n');
  chmodSync(join(dir("licence"), "git"), 0o755);
  // Not programs: a file without the right to run, and a folder named git.
  mkdirSync(dir("noexec"));
  writeFileSync(join(dir("noexec"), "git"), "not a program\n");
  mkdirSync(join(dir("folder"), "git"), { recursive: true });
  working("good", "1.0-first");
  working("other", "2.0-other");
  working("with space", "3.0-space");
});
afterAll(() => rmSync(T, { recursive: true, force: true }));

// Only the stand-ins' folders: the machine's own git must never decide a test. The stand-ins need
// nothing from PATH (their shell is named in full, and they use its built-in words only).
const env = (...folders: string[]): NodeJS.ProcessEnv => ({ PATH: folders.map(dir).join(delimiter) });
const gitOf = (e: NodeJS.ProcessEnv, how: "node" | "shell"): string =>
  how === "node"
    ? execFileSync("git", ["--version"], { env: e, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim()
    : execSync("git --version", { env: e, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();

describe("a git that starts", () => {
  it("the stand-ins are what they claim: one starts, two do not", () => {
    expect(gitStarts(join(dir("good"), "git"))).toBe(true);
    expect(gitStarts(join(dir("badcpu"), "git"))).toBe(false);
    expect(gitStarts(join(dir("licence"), "git"))).toBe(false);
    expect(gitStarts(join(dir("nowhere"), "git"))).toBe(false);
  });

  it("the failure this guards against is real: Node stops at a first git that refuses, with or without a shell", () => {
    const e = env("licence", "good");
    expect(() => gitOf(e, "node")).toThrow();
    expect(() => gitOf(e, "shell")).toThrow();
  });

  // On a Mac only. The first version of this test claimed it for every system, and failed on
  // GitHub's Linux machines under Node 20, 22 and 24 (2026-10-13, the release run of 2.19.2): there,
  // called by name, the stand-in did not stop the call. Called by its full name it does not start
  // on Linux either (the test above passed there), which is all the code relies on.
  it.runIf(process.platform === "darwin")("on a Mac, Node also stops at a first git built for another processor", () => {
    const e = env("badcpu", "good");
    expect(() => gitOf(e, "node")).toThrow();
    expect(() => gitOf(e, "shell")).toThrow();
  });

  it("the first git on PATH starts: nothing changes", () => {
    const e = env("good", "badcpu");
    const before = e.PATH;
    const r = ensureGitStarts(e, { usual: [] });
    expect(r).toEqual({ changed: false, git: join(dir("good"), "git"), note: null });
    expect(e.PATH).toBe(before);
  });

  it("the first git cannot start: the next one on PATH is put first, for Node and for a shell alike", () => {
    const e = env("badcpu", "good", "other");
    const r = ensureGitStarts(e, { usual: [] });
    expect(r.changed).toBe(true);
    expect(r.git).toBe(join(dir("good"), "git"));
    expect(e.PATH!.split(delimiter)[0]).toBe(dir("good"));
    expect(r.note).toContain(`${join(dir("badcpu"), "git")} cannot start on this machine`);
    expect(r.note).toContain(`using ${join(dir("good"), "git")}`);
    expect(gitOf(e, "node")).toBe("git version 1.0-first");
    expect(gitOf(e, "shell")).toBe("git version 1.0-first");
  });

  it("on a Mac the note carries the system's own words for a program built for another processor", () => {
    const r = ensureGitStarts(env("badcpu", "good"), { usual: [] });
    if (process.platform === "darwin") expect(r.note).toContain("Bad CPU type in executable");
    else expect(r.note).toMatch(/cannot start on this machine \(.+\)/);
  });

  it("the first git starts and refuses: it is passed over too, and its words are kept", () => {
    const e = env("licence", "other");
    const r = ensureGitStarts(e, { usual: [] });
    expect(r.changed).toBe(true);
    expect(r.note).toContain("You have not agreed to the Xcode license agreements.");
    expect(gitOf(e, "node")).toBe("git version 2.0-other");
  });

  it("nothing on PATH starts: the usual places are tried, in their order", () => {
    const e = env("badcpu", "licence");
    const r = ensureGitStarts(e, { usual: [join(dir("nowhere"), "git"), join(dir("other"), "git"), join(dir("good"), "git")] });
    expect(r.git).toBe(join(dir("other"), "git"));
    expect(gitOf(e, "shell")).toBe("git version 2.0-other");
  });

  it("no git on PATH at all: one from the usual places is put on it", () => {
    const e: NodeJS.ProcessEnv = { PATH: [dir("empty"), dir("noexec"), dir("folder")].join(delimiter) };
    const r = ensureGitStarts(e, { usual: [join(dir("good"), "git")] });
    expect(r.changed).toBe(true);
    expect(r.note).toBe(`git: no git on PATH; using ${join(dir("good"), "git")}`);
    expect(e.PATH!.split(delimiter)[0]).toBe(dir("good"));
  });

  it("a file without the right to run and a folder named git are not gits", () => {
    const e: NodeJS.ProcessEnv = { PATH: [dir("noexec"), dir("folder"), dir("good")].join(delimiter) };
    const r = ensureGitStarts(e, { usual: [] });
    expect(r).toEqual({ changed: false, git: join(dir("good"), "git"), note: null });
  });

  it("a folder with a space in its name is taken whole", () => {
    const e = env("badcpu", "with space");
    const r = ensureGitStarts(e, { usual: [] });
    expect(r.git).toBe(join(dir("with space"), "git"));
    expect(gitOf(e, "node")).toBe("git version 3.0-space");
    expect(gitOf(e, "shell")).toBe("git version 3.0-space");
  });

  it("the folder put first is the git's own program folder when it holds a git that starts", () => {
    working("own-programs", "4.0-own");
    working("front", "4.0-front", dir("own-programs"));
    const e = env("badcpu", "front");
    ensureGitStarts(e, { usual: [] });
    expect(e.PATH!.split(delimiter)[0]).toBe(dir("own-programs"));
    expect(gitOf(e, "node")).toBe("git version 4.0-own");
  });

  it("a git whose own program folder holds no git that starts is used from where it is", () => {
    working("lonely", "5.0-lonely", dir("badcpu"));
    const e = env("badcpu", "lonely");
    ensureGitStarts(e, { usual: [] });
    expect(e.PATH!.split(delimiter)[0]).toBe(dir("lonely"));
    expect(gitOf(e, "node")).toBe("git version 5.0-lonely");
  });

  it("no git starts anywhere: PATH is left alone and the note says every git call will fail", () => {
    const e = env("badcpu", "licence");
    const before = e.PATH;
    const r = ensureGitStarts(e, { usual: [join(dir("nowhere"), "git"), join(dir("licence"), "git")] });
    expect(r.changed).toBe(false);
    expect(r.git).toBeNull();
    expect(r.note).toContain("and no other git was found: every git call will fail until one is installed");
    expect(e.PATH).toBe(before);
  });

  it("git is simply not installed: nothing to say", () => {
    const e: NodeJS.ProcessEnv = { PATH: dir("empty") };
    expect(ensureGitStarts(e, { usual: [join(dir("nowhere"), "git")] })).toEqual({ changed: false, git: null, note: null });
  });

  it("fleet health hears of it only for this process's own PATH, and only when no git starts", () => {
    const kept = process.env.PATH;
    try {
      ensureGitStarts(env("badcpu", "licence"), { usual: [] });
      expect(gitProblem()).toBeNull(); // another PATH than this process's: not its problem
      process.env.PATH = [dir("badcpu"), dir("licence")].join(delimiter);
      ensureGitStarts(process.env, { usual: [] });
      expect(gitProblem()).toContain("every git call will fail");
      process.env.PATH = [dir("badcpu"), dir("good")].join(delimiter);
      ensureGitStarts(process.env, { usual: [] });
      expect(gitProblem()).toBeNull();
    } finally {
      process.env.PATH = kept;
    }
  });
});

describe("the fix is wired, not only written", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = (f: string): string => readFileSync(join(here, "..", "src", f), "utf-8");

  it("the server asks before it registers, indexes or starts a child", () => {
    const index = src("index.ts");
    const main = index.slice(index.indexOf("async function main()"));
    const asked = main.indexOf("ensureGitStarts()");
    expect(asked).toBeGreaterThan(0);
    expect(asked).toBeLessThan(main.indexOf("registerServer("));
    expect(main.slice(0, asked)).not.toMatch(/spawn\(|execSync\(|execFileSync\(/);
  });

  it("what it says goes to the log, never to the protocol's stream", () => {
    const index = src("index.ts");
    const at = index.indexOf("ensureGitStarts()");
    expect(index.slice(at, at + 200)).toContain("console.error(");
    expect(src("git-path.ts")).not.toMatch(/console\.log|process\.stdout/);
  });

  it("fleet health carries the problem", () => {
    expect(src("fleet-health.ts")).toMatch(/const noGit = gitProblem\(\);\s*if \(noGit\) warnings\.push\(noGit\);/);
  });

  it("no setting names the git to use", () => {
    expect(src("git-path.ts").replace(/^\s*\/\/.*$/gm, "")).not.toMatch(/process\.env\.[A-Z_]*GIT|env\.[A-Z_]*GIT/);
  });
});
