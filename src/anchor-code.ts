// The code of a checkpoint (COMPR-TSA docs/SEALHOUR_PROTOCOL.md section 2.3): one leaf per repository of
// the workspaces, the trial's git leaf unchanged. The leaves name repositories and commits: they stay on
// this machine, with the checkpoint; only their number and their root are part of the checkpoint.
//
// git runs through execFile with an argument list, never a shell string (CLAUDE.md rule 4).
import { execFileSync, spawn } from "child_process";
import { createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from "fs";
import { basename, join } from "path";
import { gunzipSync, gzipSync } from "zlib";
import { loadProjectDirs } from "./config.js";
import { sortCodeLeaves, type CodeLeaf } from "./anchor-protocol.js";

/** The git repositories of the workspaces: every project folder that holds a .git (folder or file). */
export function workspaceRepos(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const d of loadProjectDirs()) {
    if (!existsSync(join(d.path, ".git"))) continue;
    let real: string;
    try { real = realpathSync(d.path); } catch { continue; }
    if (seen.has(real)) continue;
    seen.add(real);
    out.push(d.path);
  }
  return out;
}

function git(repo: string, args: string[]): Buffer {
  return execFileSync("git", ["-C", repo, ...args], { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 512 << 20, timeout: 120_000 });
}

/** SHA-256 of each blob's content, streamed through one `git cat-file --batch`. */
function blobSha256(repo: string, oids: string[]): Promise<Map<string, string>> {
  return new Promise((resolve, reject) => {
    const out = new Map<string, string>();
    if (oids.length === 0) { resolve(out); return; }
    const p = spawn("git", ["-C", repo, "cat-file", "--batch"], { stdio: ["pipe", "pipe", "pipe"] });
    let phase: "header" | "body" | "lf" = "header";
    let oid = "";
    let left = 0;
    let h = createHash("sha256");
    let pending: Buffer = Buffer.alloc(0);
    let failed = false;
    const fail = (e: Error) => { if (!failed) { failed = true; p.kill(); reject(e); } };
    p.stdout.on("data", (chunk: Buffer) => {
      pending = pending.length > 0 ? Buffer.concat([pending, chunk]) : chunk;
      let pos = 0;
      while (pos < pending.length && !failed) {
        if (phase === "header") {
          const nl = pending.indexOf(10, pos);
          if (nl === -1) break;
          const parts = pending.toString("latin1", pos, nl).split(" ");
          pos = nl + 1;
          if (parts.length !== 3) { fail(new Error(`git cat-file: ${parts.join(" ")}`)); return; }
          oid = parts[0];
          left = Number(parts[2]);
          h = createHash("sha256");
          phase = left > 0 ? "body" : "lf";
        } else if (phase === "body") {
          const take = Math.min(left, pending.length - pos);
          h.update(pending.subarray(pos, pos + take));
          left -= take;
          pos += take;
          if (left === 0) phase = "lf";
        } else {
          pos++; // the newline after the content
          out.set(oid, h.digest("hex"));
          phase = "header";
        }
      }
      pending = Buffer.from(pending.subarray(pos));
    });
    p.on("error", fail);
    p.on("close", (code) => {
      if (failed) return;
      if (code !== 0 || out.size !== new Set(oids).size) fail(new Error(`git cat-file ended early (exit ${code})`));
      else resolve(out);
    });
    p.stdin.on("error", () => { /* the reader failed first; its error is reported */ });
    p.stdin.end([...new Set(oids)].join("\n") + "\n");
  });
}

/**
 * The manifest of one commit: one line per tracked file, `<mode> <sha256 of its content> <path>`, in
 * `git ls-tree -r -z --full-tree` order (a submodule: `<mode> commit:<40 hex> <path>`). Cached per
 * commit: a commit never changes.
 */
export async function filesManifest(repo: string, commit: string, cacheDir: string): Promise<Buffer> {
  const cache = join(cacheDir, `${commit}.txt.gz`);
  if (existsSync(cache)) return gunzipSync(readFileSync(cache));
  const entries: Array<{ mode: Buffer; type: string; oid: string; path: Buffer }> = [];
  const list = git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit]);
  let start = 0;
  for (let i = 0; i < list.length; i++) {
    if (list[i] !== 0) continue;
    const item = list.subarray(start, i);
    start = i + 1;
    const tab = item.indexOf(9);
    const [mode, type, oid] = item.subarray(0, tab).toString("latin1").split(" ");
    entries.push({ mode: Buffer.from(mode, "latin1"), type, oid, path: Buffer.from(item.subarray(tab + 1)) });
  }
  const digests = await blobSha256(repo, entries.filter((e) => e.type === "blob").map((e) => e.oid));
  const manifest = Buffer.concat(entries.flatMap((e) => [
    e.mode, Buffer.from(" "), Buffer.from(e.type === "blob" ? digests.get(e.oid)! : `commit:${e.oid}`, "latin1"), Buffer.from(" "), e.path, Buffer.from("\n"),
  ]));
  mkdirSync(cacheDir, { recursive: true });
  const tmp = `${cache}.tmp-${process.pid}`;
  writeFileSync(tmp, gzipSync(manifest));
  renameSync(tmp, cache);
  return manifest;
}

export interface CodeResult {
  leaves: CodeLeaf[];
  skipped: Array<{ repo: string; why: string }>;
}

/** The code leaves of the workspaces now, in checkpoint order. One broken repository never stops the
 *  others: it is left out and named in `skipped`. */
export async function codeLeaves(o: { cacheDir: string; repos?: string[] }): Promise<CodeResult> {
  const leaves: CodeLeaf[] = [];
  const skipped: CodeResult["skipped"] = [];
  for (const repo of o.repos ?? workspaceRepos()) {
    const name = basename(repo);
    try {
      let head: string;
      try {
        head = git(repo, ["rev-parse", "--verify", "-q", "HEAD"]).toString("latin1").trim();
      } catch {
        skipped.push({ repo: name, why: "no commit yet" });
        continue;
      }
      if (!/^[0-9a-f]{40}$/.test(head)) {
        skipped.push({ repo: name, why: "not a SHA-1 repository" });
        continue;
      }
      const manifest = await filesManifest(repo, head, o.cacheDir);
      let files = 0;
      for (const b of manifest) if (b === 10) files++;
      leaves.push({ kind: "git", repo: name, commit: head, files, files_sha256: createHash("sha256").update(manifest).digest("hex") });
    } catch (e) {
      skipped.push({ repo: name, why: (e as Error).message.split("\n")[0].slice(0, 120) });
    }
  }
  return { leaves: sortCodeLeaves(leaves), skipped };
}
