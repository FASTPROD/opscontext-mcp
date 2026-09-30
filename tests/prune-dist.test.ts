import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { spawnSync } from "child_process";

// [LOCK] [DIST-HAS-NO-ORPHANS] in prune-dist.mjs: the build step after tsc, and the check
// npm publish runs on the files it is about to pack.
const SCRIPT = join(process.cwd(), "prune-dist.mjs");

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ce-prune-dist-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function project(compilerOptions: object = { outDir: "./dist", rootDir: "./src" }) {
  writeFileSync(
    join(dir, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: { target: "ES2022", module: "Node16", moduleResolution: "Node16", declaration: true, declarationMap: true, sourceMap: true, ...compilerOptions },
      include: ["src/**/*"],
      exclude: ["src/**/*.test.ts"],
    }),
  );
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "prune-fixture", version: "1.0.0", files: ["dist/", "!dist/**/*.map"] }));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "kept.ts"), "export const kept = 1;\n");
  writeFileSync(join(dir, "src", "kept.test.ts"), "export {};\n");
  mkdirSync(join(dir, "dist"), { recursive: true });
  for (const f of ["kept.js", "kept.d.ts", "kept.js.map", "kept.d.ts.map", "stray.js", "stray.d.ts", "stray.js.map", "kept.test.js", "notes.txt"]) {
    writeFileSync(join(dir, "dist", f), "// fixture\n");
  }
}

function run(...args: string[]) {
  const r = spawnSync(process.execPath, [SCRIPT, "--project", dir, ...args], { encoding: "utf8" });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

describe("prune-dist: no compiled file without a source", () => {
  it("a stray compiled file fails the check, the build step removes it, the check then passes", () => {
    project();

    const before = run("--check");
    expect(before.status).toBe(1);
    expect(before.out).toContain("dist/stray.js");
    expect(before.out).toContain("dist/stray.d.ts");
    // tsc never compiles an excluded test file, so its output is an orphan too
    expect(before.out).toContain("dist/kept.test.js");
    expect(before.out).not.toMatch(/dist\/kept\.js\b/);

    const prune = run();
    expect(prune.status).toBe(0);
    expect(prune.out).toContain("removed 4 compiled file(s) with no source");
    expect(readdirSync(join(dir, "dist")).sort()).toEqual(["kept.d.ts", "kept.d.ts.map", "kept.js", "kept.js.map", "notes.txt"]);

    const after = run("--check");
    expect(after.status).toBe(0);
    expect(after.out).toContain("every compiled file npm would pack has a source (2 files)");
  }, 30000);

  it("a clean build folder: nothing removed, nothing said", () => {
    project();
    run();
    const again = run();
    expect(again.status).toBe(0);
    expect(again.out).toBe("");
  });

  it("refuses with nothing deleted when the config leaves any doubt", () => {
    project({ outDir: undefined, rootDir: "./src" });
    const noOutDir = run();
    expect(noOutDir.status).toBe(1);
    expect(noOutDir.out).toContain("has no outDir");

    project({ outDir: "../elsewhere", rootDir: "./src" });
    const outside = run();
    expect(outside.status).toBe(1);
    expect(outside.out).toContain("is not a folder inside");

    project({ outDir: ".", rootDir: "./src" });
    expect(run().status).toBe(1);

    project();
    rmSync(join(dir, "src"), { recursive: true, force: true });
    const noInput = run();
    expect(noInput.status).toBe(1);
    expect(existsSync(join(dir, "dist", "stray.js"))).toBe(true);
  });
});
