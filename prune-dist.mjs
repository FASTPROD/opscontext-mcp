#!/usr/bin/env node
/**
 * prune-dist.mjs: the build step after tsc. tsc writes an output for every source and never
 * removes one, so the compiled file of a deleted source stays in dist/ and ships.
 *
 *   node prune-dist.mjs           remove every compiled file in the output folder whose source
 *                                 is gone (`npm run build` runs this after tsc)
 *   node prune-dist.mjs --check   list what npm would pack and refuse (exit 1) if a compiled
 *                                 file in it has no source (`npm publish` runs this last, from
 *                                 prepublishOnly, on the exact files it is about to pack)
 *   --project <dir>               another project folder (default: the folder of this file)
 *
 * It lives at the root, not in scripts/, because the public copy carries no scripts/ folder
 * and its CI runs `npm run build` (scripts/release-public.sh, KEEP).
 *
 * [LOCKED] [DIST-HAS-NO-ORPHANS], 2026-09-29
 * [NEVER] replace this with `rm -rf dist`: every MCP server on the owner's Mac runs from dist/,
 *         and the CLI imports some modules lazily (audit, detector, the installers), so a
 *         process that imports one while the folder is being rebuilt finds it gone.
 * WHY: src/cache.ts was deleted on 2026-09-05 and tsc never removed dist/cache.js: 2.6.0 to
 *      2.12.0 shipped it (the 2.12.0 tarball in the npm cache still carries it) until it was
 *      deleted by hand while 2.13.0 was prepared. Nothing would have stopped the next one.
 * FIX: the expected outputs are asked of TypeScript itself (the config's input files and the
 *      output names tsc gives each), so the exclude list and the folders are never guessed
 *      here. Only files with a compiled extension are touched, anything else is left alone,
 *      and any doubt about the config (no outDir, an outDir outside the project, no input)
 *      refuses with nothing deleted.
 */
import { readdirSync, unlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const args = process.argv.slice(2);
const checkMode = args.includes("--check");
const projectAt = args.indexOf("--project");
const root = resolve(projectAt >= 0 ? args[projectAt + 1] ?? "" : dirname(fileURLToPath(import.meta.url)));
const COMPILED = /\.(?:[mc]?js|d\.[mc]?ts)(?:\.map)?$/;

function refuse(message) {
  console.error(`prune-dist: ${message}`);
  process.exit(1);
}

const configPath = join(root, "tsconfig.json");
const read = ts.readConfigFile(configPath, ts.sys.readFile);
if (read.error) refuse(`cannot read ${configPath}: ${ts.flattenDiagnosticMessageText(read.error.messageText, " ")}`);
const config = ts.parseJsonConfigFileContent(read.config, ts.sys, root, undefined, configPath);
if (config.errors.length) {
  refuse(`${configPath}: ${config.errors.map((d) => ts.flattenDiagnosticMessageText(d.messageText, " ")).join("; ")}`);
}
const outDir = config.options.outDir;
if (!outDir) refuse(`${configPath} has no outDir: refusing to guess which folder holds the build`);
const outRel = relative(root, outDir);
if (!outRel || outRel.startsWith("..") || isAbsolute(outRel)) refuse(`outDir ${outDir} is not a folder inside ${root}: refusing`);
if (config.fileNames.length === 0) refuse(`${configPath} lists no input file: refusing, every output would look orphaned`);

const expected = new Set();
for (const input of config.fileNames) {
  for (const output of ts.getOutputFileNames(config, input, !ts.sys.useCaseSensitiveFileNames)) expected.add(resolve(output));
}
const orphan = (file) => COMPILED.test(file) && !expected.has(resolve(file));

if (checkMode) {
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
    }),
  )[0].files.map((f) => f.path);
  const built = packed.filter((p) => p.startsWith(`${outRel}/`) && COMPILED.test(p));
  const stray = built.filter((p) => orphan(join(root, p)));
  if (stray.length) {
    refuse(
      `${stray.length} compiled file(s) npm would pack have no source: ${stray.join(", ")}. ` +
        "`npm run build` removes them; publish again after it.",
    );
  }
  console.log(`prune-dist --check: every compiled file npm would pack has a source (${built.length} files)`);
  process.exit(0);
}

function listFiles(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  return entries.flatMap((e) =>
    e.isDirectory() ? listFiles(join(dir, e.name)) : e.isFile() ? [join(dir, e.name)] : [],
  );
}

const removed = [];
const failed = [];
for (const file of listFiles(outDir).filter(orphan)) {
  try {
    unlinkSync(file);
    removed.push(relative(root, file));
  } catch (e) {
    failed.push(`${relative(root, file)} (${e.code ?? e.message})`);
  }
}
if (removed.length) console.log(`prune-dist: removed ${removed.length} compiled file(s) with no source: ${removed.join(", ")}`);
if (failed.length) refuse(`could not remove ${failed.length} compiled file(s) with no source: ${failed.join(", ")}`);
